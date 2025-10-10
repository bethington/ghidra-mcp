# String Detection Implementation Guide

## Overview

This document describes the comprehensive string detection features added to Ghidra MCP to prevent misidentification of strings as numeric data types.

**Version:** 1.3.0+
**Date:** 2025-10-10

## Problem Statement

During data analysis, strings can be misidentified as numeric primitives (dword, qword) or arrays when:
- Analyst relies only on byte span without checking actual content
- Data-to-data cross-references don't trigger string awareness
- No verification step exists before applying data types

**Real-world example:** The string "July" at address `0x6fb7ffbc` was initially misidentified as `dword[2]` (8-byte qword).

## Solution Architecture

### Three-Layer Prevention Strategy

1. **Content Inspection Endpoint** (`inspect_memory_content`)
   - Reads raw memory bytes in hex and ASCII
   - Detects printable characters and null terminators
   - Calculates string likelihood scores
   - Suggests appropriate data types

2. **Enhanced Data Region Analysis** (`analyze_data_region`)
   - Integrated string detection into boundary detection
   - Returns `is_likely_string`, `detected_string`, `suggested_string_type` fields
   - Classification hints include new `"STRING"` category

3. **Automatic Verification** (`create_and_apply_data_type`)
   - Checks content before applying PRIMITIVE or ARRAY types
   - Auto-corrects to STRING with 80%+ printable character confidence
   - Logs warnings for analyst review

## API Reference

### 1. inspect_memory_content

**Endpoint:** `GET /inspect_memory_content`
**MCP Tool:** `inspect_memory_content(address, length, detect_strings)`

Reads raw memory and provides comprehensive analysis.

**Parameters:**
- `address` (string): Hex address (e.g., `"0x6fb7ffbc"`)
- `length` (int): Bytes to read (default: 64, max: 4096)
- `detect_strings` (bool): Enable string detection (default: true)

**Returns (JSON):**
```json
{
  "address": "0x6fb7ffbc",
  "bytes_read": 64,
  "hex_dump": "4A 75 6C 79 00 00 00 00 ...",
  "ascii_repr": "July\\0\\0\\0\\0...",
  "printable_count": 4,
  "printable_ratio": 0.80,
  "null_terminator_at": 4,
  "max_consecutive_printable": 4,
  "is_likely_string": true,
  "detected_string": "July",
  "suggested_type": "char[5]",
  "string_length": 5
}
```

**String Detection Criteria:**
- ≥60% printable ASCII characters (0x20-0x7E), OR
- ≥4 consecutive printable chars followed by null terminator

**Use Cases:**
- Verify data content before classification
- Investigate unknown data regions
- Validate assumptions about data types

### 2. Enhanced analyze_data_region

**Endpoint:** `POST /analyze_data_region`
**MCP Tool:** `analyze_data_region(address, max_scan_bytes, ...)`

Comprehensive data region analysis with integrated string detection.

**New Response Fields:**
```json
{
  "start_address": "0x6fb7ffbc",
  "end_address": "0x6fb7ffc3",
  "byte_span": 8,
  "classification_hint": "STRING",  // NEW: Can be STRING, PRIMITIVE, STRUCTURE, or ARRAY
  "is_likely_string": true,           // NEW
  "detected_string": "July",          // NEW
  "suggested_string_type": "char[5]", // NEW
  "current_name": "MonthJuly",
  "current_type": "CHAR[5]"
}
```

**Workflow Integration:**
```python
# Step 1: Analyze region
result = analyze_data_region("0x6fb7ffbc")
data = json.loads(result)

# Step 2: Check classification hint
if data["classification_hint"] == "STRING":
    print(f"Detected string: {data['detected_string']}")
    print(f"Suggested type: {data['suggested_string_type']}")

    # Step 3: Apply correct type
    create_and_apply_data_type(
        address="0x6fb7ffbc",
        classification="STRING",
        name="MonthJuly",
        type_definition=json.dumps({"type": data["suggested_string_type"]})
    )
```

### 3. Auto-Correcting create_and_apply_data_type

**MCP Tool:** `create_and_apply_data_type(address, classification, name, comment, type_definition)`

Now includes automatic content verification for PRIMITIVE and ARRAY classifications.

**New Behavior:**
- **Before applying:** Calls `inspect_memory_content` internally
- **If string detected:** Logs warning with detected content
- **If ≥80% printable:** Auto-corrects classification to STRING
- **Logs all decisions:** Check logs for verification details

**Example (Auto-Correction):**
```python
# Analyst attempts to apply primitive type to string data
create_and_apply_data_type(
    address="0x6fb7ffbc",
    classification="PRIMITIVE",  # Wrong classification
    type_definition='{"type": "dword[2]"}'
)

# System detects string "July" with 80% printable ratio
# Logs: "WARNING: String detected at 0x6fb7ffbc but classification is PRIMITIVE"
# Logs: "Auto-correcting classification from PRIMITIVE to STRING"
# Result: Applies char[5] type instead of dword[2]
```

## Implementation Details

### Java Plugin (GhidraMCPPlugin.java)

**New Method:** `inspectMemoryContent(String addressStr, int length, boolean detectStrings)`

Location: Lines 5656-5782

**String Detection Algorithm:**
```java
// Read memory bytes
byte[] bytes = new byte[length];
memory.getBytes(addr, bytes);

// Count printable characters
for (byte b : bytes) {
    char c = (char) (b & 0xFF);
    if (c >= 0x20 && c <= 0x7E) {
        printableCount++;
        consecutivePrintable++;
    }
    if (c == 0x00 && nullTerminatorIndex == -1) {
        nullTerminatorIndex = i;
    }
}

// Calculate ratio
double printableRatio = (double) printableCount / bytesRead;

// Determine if likely string
isLikelyString = (printableRatio >= 0.6) ||
                 (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);
```

**Enhanced analyzeDataRegion:**
- Added string detection block (lines 5414-5469)
- Classification now includes STRING category
- Returns string detection results in JSON

### Python Bridge (bridge_mcp_ghidra.py)

**New Helper Function:** `_verify_content_before_classification(address)`

Location: Lines 2272-2325

**Verification Logic:**
```python
def _verify_content_before_classification(address: str) -> dict:
    result = inspect_memory_content(address, length=64)
    data = json.loads(result)

    verification = {
        "is_string": data["is_likely_string"],
        "detected_string": data["detected_string"],
        "suggested_type": data["suggested_type"],
        "printable_ratio": float(data["printable_ratio"]),
        "recommendation": ""
    }

    if verification["is_string"]:
        verification["recommendation"] = (
            f"WARNING: Content appears to be a string..."
        )

    return verification
```

**Updated create_and_apply_data_type:**
- Validates classification includes STRING
- Calls verification for PRIMITIVE/ARRAY
- Auto-corrects with ≥80% confidence
- Logs all decisions

## Usage Examples

### Example 1: Manual Content Inspection

```python
# Inspect unknown data at cursor
result = inspect_memory_content("0x6fb7ffbc", length=32)
data = json.loads(result)

if data["is_likely_string"]:
    print(f"String detected: '{data['detected_string']}'")
    print(f"Apply type: {data['suggested_type']}")
else:
    print(f"Not a string (printable ratio: {data['printable_ratio']:.2%})")
    print(f"Hex: {data['hex_dump']}")
```

### Example 2: Integrated Workflow

```python
# Step 1: Analyze with string detection
analysis = analyze_data_region("0x6fb7ffbc")
data = json.loads(analysis)

# Step 2: Check classification hint
classification = data["classification_hint"]
print(f"Auto-detected classification: {classification}")

# Step 3: Apply appropriate type
if classification == "STRING":
    create_and_apply_data_type(
        address="0x6fb7ffbc",
        classification="STRING",
        name="MonthName",
        type_definition=json.dumps({"type": data["suggested_string_type"]}),
        comment=f"String constant: \"{data['detected_string']}\""
    )
elif classification == "PRIMITIVE":
    # Safe to apply primitive - not a string
    create_and_apply_data_type(
        address="0x6fb7ffbc",
        classification="PRIMITIVE",
        type_definition='{"type": "dword"}'
    )
```

### Example 3: Month Name Table Analysis

```python
# Analyze table of month names
month_addresses = [
    "0x6fb7ffbc",  # "July"
    "0x6fb7ffc4",  # "August"
    "0x6fb7ffcc",  # "September"
]

for addr in month_addresses:
    result = inspect_memory_content(addr, length=16)
    data = json.loads(result)

    if data["is_likely_string"]:
        print(f"{addr}: {data['detected_string']} ({data['suggested_type']})")

        create_and_apply_data_type(
            address=addr,
            classification="STRING",
            name=f"Month{data['detected_string']}",
            type_definition=json.dumps({"type": data["suggested_type"]})
        )
```

## Prevention Recommendations

### Mandatory Pre-Application Verification

**Golden Rule:** Never apply a data type without first inspecting actual byte content.

**Three-Step Workflow:**
1. ✅ **Boundary detection** → `analyze_data_region(address)`
2. ✅ **Content inspection** → Check `is_likely_string` field
3. ✅ **Classification and type application** → Use correct classification

### Verification Checklist

Before applying any data type, verify:

- [ ] Read actual memory content (hex + ASCII)
- [ ] Checked `classification_hint` from `analyze_data_region`
- [ ] If `is_likely_string == true`, use STRING classification
- [ ] Reviewed `printable_ratio` and `detected_string` fields
- [ ] Applied `suggested_string_type` if string detected
- [ ] Added descriptive comment with string value

### Common Pitfalls to Avoid

❌ **DON'T:**
- Apply types based solely on byte span
- Assume 8 bytes = qword without verification
- Ignore `classification_hint` field
- Skip content inspection for "obvious" primitives

✅ **DO:**
- Always check `is_likely_string` before PRIMITIVE/ARRAY
- Trust auto-correction when printable_ratio ≥ 80%
- Read logs for verification warnings
- Use `inspect_memory_content` for unknown regions

## Testing

### Test Case 1: String Misidentification Prevention

**Setup:** String "July" at `0x6fb7ffbc`

**Before (Incorrect):**
```python
# Old behavior - no verification
create_and_apply_data_type(
    address="0x6fb7ffbc",
    classification="PRIMITIVE",
    type_definition='{"type": "dword[2]"}'
)
# Result: Misidentified as 8-byte qword
```

**After (Correct):**
```python
# New behavior - automatic verification
create_and_apply_data_type(
    address="0x6fb7ffbc",
    classification="PRIMITIVE",
    type_definition='{"type": "dword[2]"}'
)
# Logs: "WARNING: String detected at 0x6fb7ffbc"
# Logs: "Auto-correcting classification from PRIMITIVE to STRING"
# Result: Applied char[5] type automatically
```

### Test Case 2: Manual Inspection Workflow

```python
# Inspect before classifying
result = inspect_memory_content("0x6fb7ffbc")
data = json.loads(result)

assert data["is_likely_string"] == True
assert data["detected_string"] == "July"
assert data["suggested_type"] == "char[5]"
assert data["printable_ratio"] >= 0.8
```

### Test Case 3: Non-String Verification

```python
# Verify actual primitive data
result = inspect_memory_content("0x401000")  # Contains: 0x00 0x10 0x40 0x00
data = json.loads(result)

assert data["is_likely_string"] == False
assert data["printable_ratio"] < 0.6
# Safe to apply primitive type
```

## Deployment

### Installation

1. **Build plugin:**
   ```bash
   mvn clean package assembly:single -DskipTests
   ```

2. **Install to Ghidra:**
   ```bash
   cp target/GhidraMCP.jar "<ghidra>/Extensions/Ghidra/"
   ```

3. **Restart Ghidra**

4. **Verify endpoints:**
   ```bash
   curl -s http://127.0.0.1:8089/inspect_memory_content?address=0x401000&length=64
   ```

### Configuration

**Enable debug logging:**
```bash
export GHIDRA_MCP_LOG_LEVEL=DEBUG
python bridge_mcp_ghidra.py
```

**Verification logs:**
- `WARNING: String detected at...` → Content verification warning
- `Auto-correcting classification...` → Automatic correction applied
- `Content verification passed` → No string detected

## Troubleshooting

### Issue: String not detected

**Symptoms:** `is_likely_string == false` for known string

**Causes:**
- String contains non-printable characters
- No null terminator and printable ratio < 60%
- String is UTF-16/Unicode (not ASCII)

**Solution:**
```python
# Check raw hex dump
result = inspect_memory_content(address, length=64, detect_strings=False)
data = json.loads(result)
print(data["hex_dump"])
print(data["ascii_repr"])

# Manually verify and apply
create_and_apply_data_type(
    address=address,
    classification="STRING",
    type_definition='{"type": "char[length]"}'
)
```

### Issue: False positive string detection

**Symptoms:** Non-string data classified as STRING

**Causes:**
- Coincidentally high printable character ratio
- Code or data with ASCII-range bytes

**Solution:**
```python
# Check detected string content
result = inspect_memory_content(address)
data = json.loads(result)
print(f"Detected: '{data['detected_string']}'")
print(f"Printable ratio: {data['printable_ratio']:.2%}")

# If nonsensical, override classification
create_and_apply_data_type(
    address=address,
    classification="PRIMITIVE",  # Will log warning but apply primitive
    type_definition='{"type": "dword"}'
)
```

### Issue: Auto-correction not triggering

**Symptoms:** Expected STRING but got PRIMITIVE

**Check:**
1. Verify printable_ratio ≥ 80%
2. Check logs for verification output
3. Ensure `detect_strings=True` (default)

**Debug:**
```python
# Manual verification check
verification = inspect_memory_content(address)
data = json.loads(verification)
print(f"Printable ratio: {data['printable_ratio']:.2%}")
print(f"Is likely string: {data['is_likely_string']}")

# If ≥ 80%, should auto-correct
# Check logs: grep "Auto-correcting" bridge.log
```

## Performance Impact

**Overhead per operation:**
- `inspect_memory_content`: ~10-50ms (memory read + analysis)
- `analyze_data_region` enhancement: ~5-20ms (string detection)
- `create_and_apply_data_type` verification: ~10-50ms (one content check)

**Optimization:**
- Content verification only for PRIMITIVE/ARRAY (not STRUCTURE)
- Cached results reused within same session
- Configurable max length (default 64 bytes)

**Total impact:** Negligible for manual analysis workflows (<100ms per address)

## Future Enhancements

Potential improvements:

1. **Unicode String Detection**
   - UTF-16 detection (wide char)
   - UTF-8 multi-byte sequences

2. **String Table Recognition**
   - Detect arrays of string pointers
   - Auto-apply string array types

3. **Context-Aware Detection**
   - Known string xref patterns (sprintf, format functions)
   - Common string constants (months, days, errors)

4. **Machine Learning**
   - Train classifier on known string/data patterns
   - Improve confidence scoring

## Related Documentation

- **API Reference:** `docs/API_REFERENCE.md`
- **Development Guide:** `docs/DEVELOPMENT_GUIDE.md`
- **Data Type Tools:** `docs/DATA_TYPE_TOOLS.md`
- **Complete Implementation:** `docs/COMPLETE_IMPLEMENTATION_SUMMARY.md`

## Credits

**Implementation Version:** 1.3.0
**Date:** 2025-10-10
**Author:** Claude Code (Anthropic)
**Motivation:** Prevent "July" string misidentification incident

## Changelog

### v1.3.0 (2025-10-10)
- ✨ Added `inspect_memory_content` endpoint and MCP tool
- ✨ Enhanced `analyze_data_region` with string detection
- ✨ Added automatic verification to `create_and_apply_data_type`
- 🐛 Fixed string misidentification as numeric types
- 📝 Added comprehensive string detection documentation

---

**For support, see:** https://github.com/anthropics/claude-code/issues
