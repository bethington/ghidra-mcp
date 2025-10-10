# ENHANCED REVERSE ENGINEERING PROMPT FOR GHIDRA DATA ANALYSIS

Find cursor position in Ghidra, analyze data state, and apply descriptive names based on usage patterns. Use PascalCase convention.

---

## Quick Decision Tree

1. **Data already has descriptive name + structure type?**
   - YES → Skip to **Step 4: Structure Field Analysis** (refine field names)
   - NO → Continue to Step 1

2. **Data already has type but generic name (DAT_*, FUN_*)?**
   - Apply meaningful name based on xref usage
   - If structure, proceed to **Step 4: Structure Field Analysis**

3. **Data is undefined?**
   - Follow full workflow (Steps 1-4)

---

## Analysis Workflow

### Step 1: Identify Data Region
- Get current address with `get_current_address()`
- Run `analyze_data_region()` to detect boundaries, xrefs, and classification hint
- Calculate byte span: `end_address - start_address`
- **Check if data already has type and name** - if descriptive, proceed to field analysis

### Step 2: Byte-Level XRef Analysis
- Use `get_bulk_xrefs()` for all bytes in span
- Identify which specific offsets have xrefs (indicates field boundaries in structures)
- Track multi-byte access patterns (word/dword/qword fields)

### Step 3: Classify Data Type

**A) Single Primitive** (one xref, no adjacent fields):
```python
apply_data_type(address, type_name="dword"|"word"|"byte"|"pointer"|"qword"|"string")
rename_data(address, new_name="DescriptiveName")
set_decompiler_comment(address, comment="purpose and usage")
```

**B) Structure** (multiple xrefs or logically grouped):
```python
# Initial creation with placeholder names
create_struct("StructName", fields=[...])
# Then refine with field analysis (see Step 4)
```

**C) Array/Table** (repeating stride pattern):
```python
create_struct("ElementStruct", fields=[...])  # if struct elements
create_array_type(base_type, length, name)
apply_data_type(address, type_name="ArrayType")
```

### Step 4: Structure Field Analysis (NEW - v1.4.0)

**CRITICAL**: When a structure already exists (even with a descriptive name), ALWAYS analyze and refine field names based on actual usage in code.

**4.1 Automated Field Analysis** (MANDATORY for existing structures)
```python
# Single-call comprehensive field analysis
result = analyze_struct_field_usage(address, struct_name="MyStruct", max_functions=10)
# Returns: field access counts, suggested names, usage patterns for all fields

# Get specific field context examples
context = get_field_access_context(struct_address, field_offset=4, num_examples=5)
# Returns: assembly context, function names, access types

# Get name suggestions based on types
suggestions = suggest_field_names(struct_address, struct_size=28)
# Returns: Hungarian notation suggestions, confidence scores
```

**4.2 Manual Field Analysis** (Alternative)
```python
# Get all xref sources
xrefs = get_xrefs_to(address, limit=10)

# Decompile each function
for xref in xrefs:
    code = decompile_function(xref.function_name)
    # Analyze how structure fields are accessed
```

**4.3 Analyze Field Usage Patterns**

For each field offset, look for:

| Pattern | Field Purpose | Naming Convention |
|---------|---------------|-------------------|
| `if (x->field == 0)` | Boolean/flag | `fEnabled`, `bActive`, `isValid` |
| `if (x->field == -1)` | Sentinel value | `dwSentinel`, `INVALID_VALUE` |
| `x->field++` or `x->field += n` | Counter/index | `nCount`, `dwIndex`, `iPosition` |
| `CMP field, N` then `JL/JG` | Threshold/limit | `dwMaxSize`, `nThreshold` |
| `func(x->field)` | Passed to function | Check function parameter name |
| `ptr = x->field` then `[ptr]` | Pointer | `pData`, `lpBuffer`, `pNext` |
| `x->field[i]` | Array/buffer | `szName[N]`, `pEntries[N]` |
| Loop counter to field | Array length | `nCount`, `dwArraySize` |
| Always same value | Constant/reserved | `Reserved`, `Padding`, `_N` |

**4.4 Extract Field Names from Decompilation**

Search decompiled code for patterns (or use analyze_struct_field_usage for automation):
- Variable assignments: `dwFlags = struct->field` → field is `dwFlags`
- Comparisons: `if (struct->someState == 5)` → field is `someState`
- Function calls: `LoadResource(struct->resourcePtr)` → field is `resourcePtr`
- Comments in decompiled code about field purpose

**4.5 Refine Structure Definition**

```python
# WORKFLOW FOR EXISTING STRUCTURES:
# 1. Analyze field usage
result = analyze_struct_field_usage(address, struct_name="MyStruct", max_functions=10)

# 2. Get existing structure layout
layout = get_struct_layout(struct_name="MyStruct")

# 3. Rename each field based on usage analysis
for field in layout:
    if field.name in ["field1", "dwValue1", "Unknown1"]:  # Generic name
        # Use suggested_names from analyze_struct_field_usage result
        new_name = result["field_usage"][str(field.offset)]["suggested_names"][0]
        modify_struct_field("MyStruct", field.name, new_name=new_name)

# ALTERNATIVE: Complete recreation for major changes
delete_data_type("MyStruct")
create_struct("MyStruct", [
    {"name": "dwResourceType", "type": "dword"},      # From usage analysis
    {"name": "pResourceData", "type": "pointer"},      # From suggested_names
    {"name": "nElementCount", "type": "word"},         # From access patterns
    {"name": "Reserved", "type": "word"}               # From usage count = 0
])
apply_data_type(address, type_name="MyStruct")
```

---

## Field Naming Guidelines

### Prefixes (Hungarian Notation - Optional but Common)
- `p` / `lp` = pointer (`pNext`, `lpBuffer`)
- `n` / `i` = integer counter (`nCount`, `iIndex`)
- `dw` = DWORD (`dwFlags`, `dwSize`)
- `w` = WORD (`wLevel`, `wValue`)
- `b` / `f` / `is` = boolean (`bEnabled`, `fActive`, `isValid`)
- `sz` = null-terminated string (`szName`, `szGameName`)
- `w` = wide char string (`wText`, `wTitle`)
- `a` / `arr` = array (`anValues`, `arrItems`)
- `fn` = function pointer (`fnCallback`)
- `h` = handle (`hFile`, `hDevice`)

### Suffixes
- Count/size: `Count`, `Size`, `Length`, `Num`
- Positions: `X`, `Y`, `Pos`, `Offset`
- States: `State`, `Mode`, `Status`, `Flags`
- IDs: `Id`, `Index`, `No`

### Unknown/Padding Fields
- `Unknown1`, `Unknown2` - unidentified purpose
- `_1`, `_2`, `_3` - reverse engineering convention
- `Padding1`, `Padding2` - alignment padding
- `Reserved1`, `Reserved2` - reserved for future use

---

## Data Type Mapping

| Assembly Size | C Type | Ghidra Type |
|--------------|--------|-------------|
| byte | char, BYTE, BOOL | `"byte"` |
| word | short, WORD | `"word"` |
| dword | int, DWORD, BOOL | `"dword"` |
| qword | long long, QWORD | `"qword"` |
| ptr (32-bit) | void*, struct* | `"pointer"` |
| char[N] | ASCII string | `"byte[N]"` or `"string"` |
| wchar_t[N] | Wide string | `"word[N]"` |
| struct[N] | Structure array | create array type |

---

## Implementation Rules

### Rule 1: Type Before Name
```python
# CORRECT ORDER:
create_struct() or apply_data_type()  # 1. Type
rename_data()                          # 2. Name
set_decompiler_comment()               # 3. Comment
analyze_data_region()                  # 4. Verify
```

### Rule 2: Field Analysis Before Finalization
```python
# DON'T: Create struct with generic names and stop
create_struct("Config", [
    {"name": "field1", "type": "dword"},  # ❌ Generic
    {"name": "field2", "type": "dword"}   # ❌ Generic
])

# DO: Analyze usage, then create with descriptive names
# 1. Decompile xref functions
# 2. Identify field usage patterns
# 3. Extract meaningful names from code
create_struct("Config", [
    {"name": "dwResourceFlags", "type": "dword"},  # ✅ Descriptive
    {"name": "pDataBuffer", "type": "pointer"}      # ✅ Descriptive
])
```

### Rule 3: Verify Everything
```python
result = analyze_data_region(address)
assert result.current_type != "undefined"
assert result.current_name != "DAT_*"
assert result.byte_span == expected_size
```

---

## Quick Reference: Tool Usage

```python
# Data region analysis
analyze_data_region(addr, max_scan=2048, include_xref_map=True)

# Bulk xref checking (for field detection)
get_bulk_xrefs("0x1000,0x1001,0x1002,...")

# Decompilation (for field name extraction)
decompile_function(name)
batch_decompile_xref_sources(target_addr)

# Structure operations
create_struct(name, fields=[{"name":"x","type":"dword"}])
apply_data_type(addr, type_name="StructName")
delete_data_type("OldStructName")  # for refinement
modify_struct_field(struct_name, field_name, new_type, new_name)

# Array operations
create_array_type(base_type, length, name)

# Metadata
rename_data(addr, new_name)
set_decompiler_comment(addr, comment)

# *** NEW FIELD-LEVEL ANALYSIS (v1.4.0) ***
analyze_struct_field_usage(addr, struct_name, max_functions=10)
get_field_access_context(struct_address, field_offset, num_examples=5)
suggest_field_names(struct_address, struct_size=0)

# Field analysis helpers (manual - use automated tools above instead)
get_xrefs_to(addr)
get_assembly_context(xref_sources)
disassemble_function(addr)
```

---

## Advanced Patterns

### Nested Structures
```python
create_struct("Inner", [{"name": "value", "type": "dword"}])
create_struct("Outer", [{"name": "data", "type": "Inner"}])
```

### Unions (via comments)
```python
# Ghidra has limited union support - document in comments
create_struct("Variant", [
    {"name": "asInt", "type": "dword"},     # Offset 0
    {"name": "asFloat", "type": "dword"}    # Offset 0 (overlaps)
])
# Add comment: "Union: asInt and asFloat occupy same memory"
```

### Pointer Arrays
```python
create_struct("Table", [
    {"name": "pEntries", "type": "pointer[16]"}
])
```

### String Buffers
```python
create_struct("PlayerData", [
    {"name": "szPlayerName", "type": "byte[16]"},   # char[16]
    {"name": "wDisplayName", "type": "word[32]"}    # wchar_t[32]
])
```

---

## Conciseness Improvements

**REMOVED** from original prompt:
- ❌ Redundant explanations of basic concepts
- ❌ Multiple examples of same pattern
- ❌ Verbose step-by-step instructions already implied by tools
- ❌ Repeated warnings about tool order

**KEPT** in enhanced prompt:
- ✅ Field analysis workflow (NEW)
- ✅ Pattern recognition table (NEW)
- ✅ Quick reference guide (NEW)
- ✅ Critical implementation rules
- ✅ Data type mapping

**Result**: ~60% reduction in prompt length while adding field analysis capabilities.

---

## Work Silently
All changes in Ghidra only. No file creation/editing.
