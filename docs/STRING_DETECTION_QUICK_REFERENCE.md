# String Detection Quick Reference

## Quick Start

### Check if data is a string
```python
result = inspect_memory_content("0x6fb7ffbc")
data = json.loads(result)
if data["is_likely_string"]:
    print(f"String: '{data['detected_string']}'")
    print(f"Apply type: {data['suggested_type']}")
```

### Enhanced data analysis (with string detection)
```python
result = analyze_data_region("0x6fb7ffbc")
data = json.loads(result)
if data["classification_hint"] == "STRING":
    # Apply string type automatically
    pass
```

### Apply type with auto-verification
```python
# System automatically checks for strings before applying PRIMITIVE/ARRAY
create_and_apply_data_type(
    address="0x6fb7ffbc",
    classification="PRIMITIVE",  # Will auto-correct to STRING if detected
    type_definition='{"type": "dword"}'
)
```

## String Detection Criteria

| Condition | Action |
|-----------|--------|
| ≥60% printable chars | Likely string |
| ≥4 printable + null terminator | Likely string |
| ≥80% printable in PRIMITIVE/ARRAY | Auto-correct to STRING |
| <60% printable | Not a string |

## API Quick Reference

### inspect_memory_content
```python
inspect_memory_content(
    address: str,      # e.g., "0x6fb7ffbc"
    length: int = 64,  # Bytes to read
    detect_strings: bool = True
)
```

**Returns:**
- `is_likely_string`: bool
- `detected_string`: str or None
- `suggested_type`: e.g., "char[5]"
- `printable_ratio`: float (0.0-1.0)
- `hex_dump`: Hex representation
- `ascii_repr`: ASCII with \\0 and . for non-printable

### Enhanced analyze_data_region
```python
analyze_data_region(
    address: str,
    max_scan_bytes: int = 1024,
    include_xref_map: bool = True,
    include_assembly_patterns: bool = True,
    include_boundary_detection: bool = True
)
```

**New Fields:**
- `classification_hint`: "STRING" | "PRIMITIVE" | "STRUCTURE" | "ARRAY"
- `is_likely_string`: bool
- `detected_string`: str or None
- `suggested_string_type`: e.g., "char[5]"

### Auto-verifying create_and_apply_data_type
```python
create_and_apply_data_type(
    address: str,
    classification: str,  # "PRIMITIVE" | "STRUCTURE" | "ARRAY" | "STRING"
    name: str = None,
    comment: str = None,
    type_definition: str | dict = None
)
```

**Automatic Behavior:**
- Verifies PRIMITIVE/ARRAY classifications
- Auto-corrects to STRING if ≥80% printable
- Logs all verification decisions

## Common Workflows

### Workflow 1: Unknown Data Analysis
```python
# 1. Get cursor position
addr = get_current_address()

# 2. Analyze with string detection
result = analyze_data_region(addr)
data = json.loads(result)

# 3. Check classification
if data["classification_hint"] == "STRING":
    create_and_apply_data_type(
        address=addr,
        classification="STRING",
        name=f"Str_{data['detected_string'][:10]}",
        type_definition=json.dumps({"type": data["suggested_string_type"]})
    )
```

### Workflow 2: Manual Verification
```python
# Inspect content first
result = inspect_memory_content(addr, length=32)
data = json.loads(result)

print(f"Hex: {data['hex_dump']}")
print(f"ASCII: {data['ascii_repr']}")
print(f"String: {data['is_likely_string']}")

# Then apply appropriate type
```

### Workflow 3: Batch String Table Analysis
```python
addresses = ["0x6fb7ffbc", "0x6fb7ffc4", "0x6fb7ffcc"]

for addr in addresses:
    result = inspect_memory_content(addr, length=16)
    data = json.loads(result)

    if data["is_likely_string"]:
        create_and_apply_data_type(
            address=addr,
            classification="STRING",
            name=f"Str{data['detected_string']}",
            type_definition=json.dumps({"type": data["suggested_type"]})
        )
```

## Troubleshooting

### String not detected
**Check:** printable_ratio and detected_string
```python
result = inspect_memory_content(addr)
data = json.loads(result)
print(f"Printable: {data['printable_ratio']:.2%}")
print(f"Detected: {data['detected_string']}")
```

### False positive
**Verify:** Inspect actual content
```python
result = inspect_memory_content(addr, detect_strings=False)
data = json.loads(result)
print(f"Hex: {data['hex_dump'][:50]}")  # First 50 chars
```

### Auto-correction not working
**Debug:** Check logs for verification output
```bash
export GHIDRA_MCP_LOG_LEVEL=DEBUG
python bridge_mcp_ghidra.py
# Look for: "Auto-correcting classification"
```

## Prevention Checklist

Before applying ANY data type:

- [ ] Run `analyze_data_region` and check `classification_hint`
- [ ] If hint is STRING, use STRING classification
- [ ] For unknown data, run `inspect_memory_content` first
- [ ] Check `printable_ratio` ≥ 0.6 for string likelihood
- [ ] Review logs for auto-correction warnings
- [ ] Apply suggested type from `suggested_string_type` or `suggested_type`

## Log Messages

### Normal Operation
```
INFO: Content verification passed: not a string.
```

### String Detected
```
WARNING: String detected at 0x6fb7ffbc but classification is PRIMITIVE.
WARNING: Content appears to be a string ("July"). Consider using classification='STRING'...
```

### Auto-Correction
```
INFO: Auto-correcting classification from PRIMITIVE to STRING
```

## Example Outputs

### String Detection Success
```json
{
  "address": "0x6fb7ffbc",
  "is_likely_string": true,
  "detected_string": "July",
  "suggested_type": "char[5]",
  "printable_ratio": 0.80,
  "null_terminator_at": 4
}
```

### Non-String Data
```json
{
  "address": "0x401000",
  "is_likely_string": false,
  "detected_string": null,
  "suggested_type": null,
  "printable_ratio": 0.25,
  "null_terminator_at": -1
}
```

## Performance

| Operation | Typical Time |
|-----------|-------------|
| inspect_memory_content | 10-50ms |
| analyze_data_region (enhanced) | +5-20ms |
| create_and_apply_data_type (verification) | +10-50ms |
| **Total per address** | **<100ms** |

## References

- **Full Guide:** `docs/STRING_DETECTION_GUIDE.md`
- **Implementation:** `STRING_DETECTION_SUMMARY.md`
- **API Docs:** `docs/API_REFERENCE.md`

---

**Version:** Ghidra MCP 1.3.0
**Last Updated:** 2025-10-10
