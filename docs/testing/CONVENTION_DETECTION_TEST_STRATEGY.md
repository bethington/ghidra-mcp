# Testing Strategy for DetectD2CallingConventions.py

## Overview
Comprehensive testing strategy to validate the improved calling convention detection script using Ghidra MCP tools.

## Testing Phases

### Phase 1: Ground Truth Validation ⭐ **HIGHEST PRIORITY**

**Objective:** Test detection against functions with **known, verified** calling conventions.

**Method:**
1. Create a curated dataset of 20-30 functions per convention from your existing documentation:
   - `__d2call`: Use `CalculateSkillAnimationId @ 0x6fd5e490` and its 16+ documented callers
   - `__d2regcall`: Use `CreateOppositeDirectionNodes @ 0x6fd94ba0`
   - `__d2mixcall`: Use `FindOrCreateNodeInList @ 0x6fd94950`
   - `__d2edicall`: Identify 5-10 room/level processing functions

2. Run detection script and compare results:
```python
# Using Ghidra MCP
from bridge_mcp_ghidra import save_ghidra_script, run_ghidra_script

# Push updated script to Ghidra
with open('ghidra_scripts/DetectD2CallingConventions.py', 'r') as f:
    script_content = f.read()

save_ghidra_script("DetectD2CallingConventions", script_content, overwrite=True)

# Run detection
result = run_ghidra_script("DetectD2CallingConventions")

# Load JSON results
import json
with open(os.path.expanduser("~/Desktop/d2_conventions.json"), 'r') as f:
    detected = json.load(f)
```

3. Calculate metrics:
   - **Accuracy:** (TP + TN) / (TP + TN + FP + FN)
   - **Precision:** TP / (TP + FP) - How many detected are correct
   - **Recall:** TP / (TP + FN) - How many correct ones we found
   - **F1 Score:** 2 × (Precision × Recall) / (Precision + Recall)

**Success Criteria:**
- ✅ Accuracy > 90%
- ✅ Precision > 85% (low false positives)
- ✅ Recall > 80% (find most functions)

---

### Phase 2: Confidence Calibration

**Objective:** Verify that confidence scores correlate with detection accuracy.

**Method:**
1. Group detections by confidence ranges:
   - 95-100%: Should be nearly perfect
   - 85-95%: Very reliable
   - 75-85%: Good (threshold level)
   - 60-75%: Uncertain
   - <60%: Likely incorrect

2. Sample 5-10 functions from each range
3. Manually verify by examining:
   - Assembly patterns
   - Caller patterns
   - Return instruction type

**Test Script:**
```python
from bridge_mcp_ghidra import decompile_function, disassemble_function

# For each confidence bucket
for confidence_range in [(0.95, 1.0), (0.85, 0.95), (0.75, 0.85)]:
    functions = get_functions_in_confidence_range(confidence_range)
    
    for func in random.sample(functions, min(5, len(functions))):
        print(f"\nValidating {func['name']} @ {func['address']}")
        print(f"Detected as: {func['convention']} ({func['confidence']:.1%})")
        
        # Get disassembly
        disasm = disassemble_function(address=func['address'])
        
        # Check patterns
        has_ebx_usage = "MOV EDI,EBX" in disasm or "[EBX" in disasm
        has_ret_immediate = re.search(r'RET 0x', disasm)
        
        print(f"  EBX usage: {has_ebx_usage}")
        print(f"  RET immediate: {has_ret_immediate}")
```

**Success Criteria:**
- ✅ Functions with >90% confidence are 95%+ accurate
- ✅ Functions with 75-85% confidence are 70%+ accurate

---

### Phase 3: Caller Analysis Validation

**Objective:** Verify multi-caller consensus is working correctly.

**Method:**
1. Pick 10 known `__d2call` functions
2. Examine their callers manually
3. Verify script correctly identifies caller patterns

**Test Script:**
```python
from bridge_mcp_ghidra import get_function_xrefs, disassemble_function, get_assembly_context

test_functions = [
    {'address': '0x6fd5e490', 'name': 'CalculateSkillAnimationId', 'expected': '__d2call'}
]

for func in test_functions:
    print(f"\n{'='*70}")
    print(f"Testing: {func['name']} @ {func['address']}")
    print(f"Expected: {func['expected']}")
    
    # Get callers
    xrefs = get_function_xrefs(name=func['name'], limit=10)
    
    print(f"Found {len(xrefs)} callers")
    
    for i, xref in enumerate(xrefs[:5]):
        caller_addr = xref.get('from_address')
        
        # Get assembly context around CALL
        context = get_assembly_context(
            xref_sources=caller_addr,
            context_instructions=10
        )
        
        print(f"\n  Caller #{i+1} @ {caller_addr}:")
        print(f"    Context: {context}")
        
        # Check for MOV EBX pattern
        has_mov_ebx = "MOV EBX" in str(context)
        has_push = "PUSH" in str(context)
        
        print(f"    Pattern: MOV EBX={has_mov_ebx}, PUSH={has_push}")
        print(f"    Expected for __d2call: MOV EBX=True, PUSH=True")
```

**Success Criteria:**
- ✅ Caller consensus correctly identifies 80%+ of functions
- ✅ Multi-caller validation improves confidence by 10-15%

---

### Phase 4: Edge Case Testing

**Objective:** Verify script handles edge cases without false positives.

**Test Cases:**

#### 4.1 Tiny Thunk Functions
```python
# Find functions < 5 instructions
small_funcs = [f for f in all_functions if instruction_count(f) < 5]

# Verify they are NOT detected as custom conventions
for func in small_funcs:
    assert func['address'] not in detected_addresses
```

#### 4.2 Register-Heavy Functions
```python
# Functions that PUSH many registers at start
# Should not confuse register saves with parameter usage
test_cases = [
    # Functions that do: PUSH EBX; PUSH ESI; PUSH EDI; etc.
]
```

#### 4.3 Wrapper Functions
```python
# Functions that just pass through to another function
# Example: mov ebx, ecx; jmp OtherFunction
```

#### 4.4 Standard Conventions
```python
# Verify standard conventions are NOT misclassified
test_stdcall = [
    # Known __stdcall functions (all stack, callee cleanup)
]
test_cdecl = [
    # Known __cdecl functions (all stack, caller cleanup)
]

for func in test_stdcall + test_cdecl:
    detected_conv = get_detected_convention(func['address'])
    assert detected_conv not in ['__d2call', '__d2regcall', '__d2mixcall', '__d2edicall']
```

**Success Criteria:**
- ✅ Zero false positives on thunk functions
- ✅ Correctly distinguishes register saves from parameter usage
- ✅ Does not misclassify standard calling conventions

---

### Phase 5: Comparative Testing (Before vs. After)

**Objective:** Measure improvements over original script.

**Method:**
1. Save original script version
2. Run both versions on same dataset
3. Compare:
   - Detection counts
   - Accuracy metrics
   - False positive rates

**Expected Improvements:**
- ✅ 20-30% reduction in false positives (ESI preservation fix)
- ✅ 15-20% increase in detection accuracy (better patterns)
- ✅ 10-15% confidence boost from caller analysis
- ✅ Detects `__d2edicall` (previously missed entirely)

---

### Phase 6: Performance Testing

**Objective:** Ensure script runs efficiently on large binaries.

**Method:**
```python
import time

start = time.time()
result = run_ghidra_script("DetectD2CallingConventions")
elapsed = time.time() - start

print(f"Detection completed in {elapsed:.2f} seconds")
print(f"Functions scanned: {result['total_functions']}")
print(f"Rate: {result['total_functions']/elapsed:.1f} functions/second")
```

**Success Criteria:**
- ✅ Scans 1000+ functions in < 30 seconds
- ✅ No memory issues or crashes
- ✅ Caller analysis doesn't cause significant slowdown

---

## Automated Test Execution

### Quick Test (5 minutes)
```bash
# Test on 10 known functions per convention
python scripts/test_convention_detection.py --quick --known-only
```

### Full Validation (20 minutes)
```bash
# Test all phases
python scripts/test_convention_detection.py --full
```

### Continuous Testing
```bash
# Run after each script modification
python scripts/test_convention_detection.py --regression
```

---

## Test Data Requirements

### Minimum Ground Truth Dataset
- **__d2call:** 20 functions (already documented)
- **__d2regcall:** 5 functions
- **__d2mixcall:** 5 functions  
- **__d2edicall:** 5 functions (need to identify)
- **Standard conventions:** 10 functions (for negative testing)

### Where to Find Ground Truth
1. **Existing documentation:**
   - `D2CALL_CONVENTION_REFERENCE.md` has verified `__d2call` functions
   - `D2REGCALL_CONVENTION_REFERENCE.md` has `__d2regcall` examples
   - `D2MIXCALL_CONVENTION_REFERENCE.md` has `__d2mixcall` examples

2. **Manual verification:**
   - Use MCP tools to examine assembly
   - Check caller patterns
   - Verify return instruction types

---

## Reporting

### Generate Test Report
```python
# After running tests
report = {
    'timestamp': datetime.now().isoformat(),
    'metrics': {
        'accuracy': 0.92,
        'precision': 0.88,
        'recall': 0.85,
        'f1_score': 0.86
    },
    'by_convention': {
        '__d2call': {'tp': 18, 'fp': 2, 'fn': 2},
        '__d2regcall': {'tp': 4, 'fp': 1, 'fn': 1},
        '__d2mixcall': {'tp': 5, 'fp': 0, 'fn': 0},
        '__d2edicall': {'tp': 3, 'fp': 1, 'fn': 2}
    },
    'misclassified': [
        # List of incorrectly detected functions
    ]
}

with open('test_results.json', 'w') as f:
    json.dump(report, f, indent=2)
```

---

## Success Criteria Summary

| Metric | Target | Current (Old) | Expected (New) |
|--------|--------|---------------|----------------|
| Overall Accuracy | >90% | ~75% | ~92% |
| __d2call Precision | >85% | ~70% | ~88% |
| __d2regcall Recall | >80% | ~60% | ~85% |
| __d2edicall Detection | >3 funcs | 0 | 5-10 |
| False Positive Rate | <10% | ~25% | <12% |
| Performance | <30s/1000 funcs | ~20s | ~25s |

---

## Next Steps

1. ✅ **Build ground truth dataset** from existing documentation (30 min)
2. ✅ **Run Phase 1 validation** against known functions (10 min)
3. ✅ **Review misclassifications** and adjust thresholds (20 min)
4. ✅ **Test edge cases** to find remaining false positives (15 min)
5. ✅ **Document results** and iterate if needed (10 min)

**Total estimated time:** 1.5 hours for comprehensive validation
