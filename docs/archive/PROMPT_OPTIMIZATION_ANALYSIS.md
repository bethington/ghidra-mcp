# Prompt Optimization Analysis

## Summary of Changes

### What Was Added ✅

1. **Field-Level Analysis Workflow** (NEW - Critical Enhancement)
   - Step 4: Structure field analysis with usage pattern recognition
   - Pattern recognition table for automated field naming
   - Field name extraction from decompiled code
   - Structure refinement process

2. **Pattern Recognition Table** (NEW)
   - Maps code patterns to field purposes
   - Provides naming conventions for each pattern
   - Enables systematic field analysis

3. **Quick Reference Guide** (NEW)
   - Tool usage cheatsheet
   - Common patterns with code examples
   - Reduces need to explain same concepts multiple times

### What Was Removed ❌

1. **Redundant Explanations**
   - Original: Multiple paragraphs explaining what xrefs are
   - New: Assumes user knows basics, focuses on process

2. **Verbose Step-by-Step Instructions**
   - Original: "First do X, then do Y, make sure to do Z..."
   - New: Direct tool call sequences in code blocks

3. **Repeated Warnings**
   - Original: Multiple sections warning about tool order
   - New: Single "Implementation Rules" section

4. **Duplicate Examples**
   - Original: 3-4 examples of same primitive type application
   - New: One example per unique pattern

5. **Philosophical Discussions**
   - Original: Why naming matters, importance of documentation
   - New: Just the actionable steps

## Metrics

| Metric | Original | Enhanced | Change |
|--------|----------|----------|--------|
| Total Lines | ~430 | ~280 | -35% |
| Word Count | ~3,200 | ~1,400 | -56% |
| Sections | 15 | 9 | -40% |
| Code Examples | 8 | 12 | +50% |
| Tables | 0 | 3 | +3 |
| Unique Capabilities | 3 | 5 | +67% |

## Recommendations for Further Optimization

### 1. Create Tiered Prompt System

**Tier 1: Ultra-Concise (for experienced users)**
```markdown
# Quick Analysis Protocol
1. `analyze_data_region()` → classify
2. Decompile xrefs → extract field names
3. `create_struct()` with descriptive names
4. Apply → Rename → Comment → Verify
```

**Tier 2: Standard (current enhanced prompt)**
- Balanced detail with field analysis
- Pattern recognition tables
- Quick reference

**Tier 3: Detailed (for learning/training)**
- Full explanations of concepts
- Multiple examples per pattern
- Troubleshooting guide

### 2. Extract to Reference Documents

Move these to separate files:

**REFERENCE_DATA_TYPES.md**
```markdown
# Data Type Quick Reference
| Assembly | C Type | Ghidra |
|----------|--------|--------|
| byte     | char   | "byte" |
...
```

**REFERENCE_NAMING_CONVENTIONS.md**
```markdown
# Hungarian Notation Guide
p/lp = pointer
dw = DWORD
...
```

**REFERENCE_PATTERNS.md**
```markdown
# Common Pattern Recognition
if (x->field == 0) → Boolean flag
...
```

Then prompt becomes:
```markdown
See REFERENCE_DATA_TYPES.md for type mappings.
See REFERENCE_NAMING_CONVENTIONS.md for naming rules.
```

### 3. Use Directive-Based Syntax

**Current:**
```markdown
Step 1: Identify Complete Data Region
- Boundary detection: From the xref'd address...
- Calculate exact byte span...
```

**Optimized:**
```markdown
@STEP1_REGION_DETECTION
- Run: analyze_data_region()
- Extract: start, end, span, xrefs, classification
```

### 4. Template-Based Approach

```markdown
# Template: PRIMITIVE_ANALYSIS
apply_data_type({{addr}}, "{{type}}")
rename_data({{addr}}, "{{PascalCaseName}}")
set_decompiler_comment({{addr}}, "{{usage_description}}")

# Template: STRUCT_ANALYSIS
analyze_fields() → extract_names() → create_struct() → apply() → verify()
```

### 5. Conditional Sections

Use markers for optional details:

```markdown
## Field Analysis [ADVANCED]
<details>
Only expand if dealing with complex structures...
</details>

## Basic Workflow [REQUIRED]
Always follow these steps...
```

### 6. Automated Field Name Suggestions

Instead of describing HOW to analyze fields, provide a decision tree:

```markdown
## Field Name Decision Tree

Field Value Pattern → Action
├─ Always 0 or 1 → Check if used in `if()` → `fEnabled`/`bActive`
├─ Always -1 (0xFFFFFFFF) → `dwSentinel` or `INVALID_VALUE`
├─ Increments → `nCount`, `dwIndex`
├─ Dereferenced → `p*` or `lp*`
└─ Unknown → Decompile xrefs and check variable names
```

### 7. Checklist Format

```markdown
# Pre-Analysis Checklist
- [ ] Get current address
- [ ] Run analyze_data_region()
- [ ] Check classification_hint

# Structure Analysis Checklist
- [ ] Decompile all xref functions
- [ ] Extract field names from code
- [ ] Map offsets to purposes
- [ ] Create struct with descriptive names

# Verification Checklist
- [ ] current_type != "undefined"
- [ ] current_name is descriptive
- [ ] byte_span matches expected
```

## Recommended Final Version

Combine the enhanced prompt with these optimizations:

```markdown
# Ghidra Data Analysis - Quick Protocol

## 1. Analyze
analyze_data_region() → classification_hint → (primitive|struct|array)

## 2. Decompile & Extract Names
For structures:
  - Decompile xref functions
  - Find pattern in [PATTERN_TABLE]
  - Extract variable names from code

## 3. Apply Types
Primitive: apply_data_type() → rename → comment
Structure: create_struct(with_extracted_names) → apply → rename → comment
Array: create_array_type() → apply → rename → comment

## 4. Verify
analyze_data_region() confirms type != undefined

[PATTERN_TABLE] - See separate file
[NAMING_GUIDE] - See separate file
[TOOL_REFERENCE] - See separate file
```

## Implementation Priority

1. **High Priority** - Use enhanced prompt as-is (already 56% shorter)
2. **Medium Priority** - Extract pattern/naming tables to reference files
3. **Low Priority** - Create tiered prompt system for different skill levels
4. **Future** - Build MCP tool to suggest field names automatically

## Token Efficiency

**Current enhanced prompt**: ~1,400 words = ~1,800 tokens
**With reference extraction**: ~600 words = ~800 tokens
**Ultra-concise version**: ~200 words = ~250 tokens

**Recommendation**: Use enhanced version (1,800 tokens) for complex analysis, switch to ultra-concise (250 tokens) once pattern is established.
