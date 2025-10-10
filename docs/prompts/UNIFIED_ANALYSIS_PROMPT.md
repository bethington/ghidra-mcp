# Unified Ghidra Reverse Engineering Analysis Prompt

Find the next undocumented or poorly documented function. Perform comprehensive analysis and documentation following the workflow below.

---

## Analysis Workflow

### 1. Function-Level Analysis

**1.1 Find Next Function**
```python
find_next_undefined_function(criteria="name_pattern", pattern="FUN_")
```

**1.2 Gather Function Context**
```python
# Parallel calls for efficiency
decompile_function(name)
disassemble_function(address)
get_function_callees(name)
get_function_xrefs(name)
get_function_variables(name)
```

**1.3 Analyze Data References**
- Get current cursor position with `get_current_address()`
- For each data reference in function:
  - Run `analyze_data_region(address)` to detect boundaries, xrefs, classification
  - Use `get_bulk_xrefs(addresses)` for multi-byte analysis
  - Use `inspect_memory_content(address)` to detect strings vs numeric data

---

### 2. Function Documentation

**2.1 Rename Function** (PascalCase)
- Based on purpose, algorithm, and caller context (xrefs)
- Examples: `ProcessPlayerSlotStates`, `ValidateResourceBuffer`, `InitializeGameState`

**2.2 Set Function Prototype and Calling Convention**
```python
set_function_prototype(
    function_address="0x...",
    prototype="void FunctionName(int param1, void* param2)",
    calling_convention="__cdecl"  # or __stdcall, __fastcall, __thiscall
)
```

**2.3 Define Return Type**
```python
# Included in set_function_prototype above
# Common patterns: void, int, BOOL, pointer, HRESULT
```

**2.4 Rename Variables and Parameters**
- Remove prefixes (local_, param_)
- Use descriptive names based on purpose
- Include register artifacts where meaningful (eax_result, ecx_counter)
- Examples: `playerIndex`, `bufferSize`, `validationFlag`

**2.5 Define Undefined Variables**
```python
# Single variable
set_local_variable_type(
    function_address="0x...",
    variable_name="var1",
    new_type="DWORD"
)

# Batch operations (v1.5.1)
batch_set_variable_types(
    function_address="0x...",
    variable_types={
        "var1": "DWORD",
        "var2": "pointer",
        "var3": "byte"
    }
)
```

**2.6 Rename Function Callees**
- Rename called functions based on their purpose
- Update parameter names in called functions

---

### 3. Label Creation (snake_case)

**3.1 Identify Jump Targets**
```python
jump_targets = get_function_jump_target_addresses(name)
```

**3.2 Create Labels Based on Purpose**
```python
# Batch creation (v1.5.1 - PREFERRED)
batch_create_labels([
    {"address": "0x...", "name": "loop_start"},
    {"address": "0x...", "name": "validation_failed"},
    {"address": "0x...", "name": "exit_function"},
    {"address": "0x...", "name": "state_switch_table"},
    {"address": "0x...", "name": "error_handler"}
])

# Individual creation (legacy)
create_label(address, name)
```

**Label Naming Patterns**:
- Loop labels: `loop_start`, `loop_continue`, `loop_exit`
- Conditionals: `check_valid`, `if_zero`, `validation_passed`
- Error handling: `error_handler`, `cleanup_and_exit`
- State machines: `state_0_init`, `state_1_processing`
- Jump tables: `jump_table`, `switch_case_0`

---

### 4. Data Structure Analysis

**4.1 Detect Data Region Boundaries**
```python
result = analyze_data_region(address, max_scan=2048, include_xref_map=True)
# Returns: start/end addresses, byte span, xref map, classification hint
```

**4.2 Analyze Field Usage (for structures)**
```python
# Automated field analysis (v1.5.0)
field_analysis = analyze_struct_field_usage(
    address="0x...",
    struct_name="MyStruct",  # optional
    max_functions=10
)
# Returns: field access counts, suggested names, usage patterns

# Get specific field context
context = get_field_access_context(
    struct_address="0x...",
    field_offset=4,
    num_examples=5
)
# Returns: assembly, function names, access types

# Get name suggestions
suggestions = suggest_field_names(struct_address="0x...", struct_size=28)
# Returns: Hungarian notation suggestions, confidence scores
```

**4.3 Field Naming Based on Usage Patterns**

| Pattern | Field Type | Naming |
|---------|-----------|---------|
| `if (x->field == 0)` | Boolean/flag | `fEnabled`, `bActive`, `isValid` |
| `if (x->field == -1)` | Sentinel | `dwSentinel`, `INVALID_VALUE` |
| `x->field++` | Counter | `nCount`, `dwIndex`, `iPosition` |
| `CMP field, N` then `JL/JG` | Threshold | `dwMaxSize`, `nThreshold` |
| `func(x->field)` | Function param | Check parameter name |
| `ptr = x->field` then `[ptr]` | Pointer | `pData`, `lpBuffer` |
| `x->field[i]` | Array | `szName[N]`, `pEntries[N]` |
| Loop counter to field | Array length | `nCount`, `dwArraySize` |
| Always same value | Constant | `Reserved`, `Padding` |

**4.4 Create/Refine Data Structures**

**Option A: Atomic Creation with Type Inference**
```python
create_and_apply_data_type(
    address="0x...",
    classification="STRUCTURE",  # or "PRIMITIVE", "ARRAY"
    name="ConfigData",
    comment="Configuration structure for resource loading",
    type_definition='{"name": "ConfigData", "fields": [
        {"name": "dwResourceType", "type": "dword"},
        {"name": "pResourceData", "type": "pointer"},
        {"name": "nElementCount", "type": "word"},
        {"name": "Reserved", "type": "word"}
    ]}'
)
```

**Option B: Manual Structure Creation**
```python
# 1. Create structure with descriptive field names (from usage analysis)
create_struct("ConfigData", [
    {"name": "dwResourceType", "type": "dword"},
    {"name": "pResourceData", "type": "pointer"},
    {"name": "nElementCount", "type": "word"},
    {"name": "Reserved", "type": "word"}
])

# 2. Apply to memory location
apply_data_type(address="0x...", type_name="ConfigData")

# 3. Rename instance (if global)
rename_data(address="0x...", new_name="GlobalConfigData")

# 4. Add comment
set_decompiler_comment(address="0x...", comment="Global configuration")
```

**Option C: Modify Existing Structure**
```python
# Get current layout
layout = get_struct_layout(struct_name="ConfigData")

# Rename fields based on usage analysis
modify_struct_field(
    struct_name="ConfigData",
    field_name="field1",
    new_name="dwResourceType",
    new_type="dword"  # optional
)

# Or for major changes, recreate
delete_data_type("ConfigData")
create_struct("ConfigData", [...])  # with refined fields
```

**4.5 Create Arrays/Tables**
```python
# Detect array bounds
bounds = detect_array_bounds(
    address="0x...",
    analyze_loop_bounds=True,
    analyze_indexing=True
)
# Returns: element size, element count, evidence

# Option 1: Structure array
create_struct("TableEntry", [
    {"name": "dwValue1", "type": "dword"},
    {"name": "dwValue2", "type": "dword"}
])
create_array_type(base_type="TableEntry", length=64, name="ConfigTable")
apply_data_type(address="0x...", type_name="ConfigTable")

# Option 2: Primitive array
create_and_apply_data_type(
    address="0x...",
    classification="ARRAY",
    name="ThresholdTable",
    type_definition='{"element_type": "dword", "count": 64}'
)
```

**4.6 Data Type Mapping**

| Assembly Size | C Type | Ghidra Type |
|--------------|--------|-------------|
| byte | char, BYTE, BOOL | `"byte"` |
| word | short, WORD | `"word"` |
| dword | int, DWORD, BOOL | `"dword"` |
| qword | long long, QWORD | `"qword"` |
| ptr (32-bit) | void*, struct* | `"pointer"` |
| char[N] | ASCII string | `"byte[N]"` or `"string"` |
| wchar_t[N] | Wide string | `"word[N]"` |

---

### 5. Comment Documentation

**5.1 Disassembly Comments** (max 32 characters)
- Concise operation descriptions
- Examples: "Load flags into EAX", "Check if buffer valid", "Call cleanup routine"

**5.2 Decompiler Comments**
- Algorithm context: "Iterates through player slots"
- Structure access: "Validates resource header"
- Magic numbers: "0x26 is security sentinel value"
- Validation logic: "Must be < MaxPlayers to proceed"
- Edge cases: "Returns -1 if slot inactive"

**5.3 Batch Comment Operations** (v1.5.1 - PREFERRED)
```python
batch_set_comments(
    function_address="0x...",
    plate_comment="High-level function summary\nAlgorithm: ...\nReturns: ...",
    disassembly_comments=[
        {"address": "0x...", "comment": "Save ECX register"},
        {"address": "0x...", "comment": "Load player slot index"},
        {"address": "0x...", "comment": "Check if slot active"},
        # ... up to 40+ comments
    ],
    decompiler_comments=[
        {"address": "0x...", "comment": "Security validation: value must be 0x26"},
        {"address": "0x...", "comment": "Iterate through all active player slots"},
        {"address": "0x...", "comment": "State jump table for player states 0, 1, 4"}
    ]
)
```

**5.4 Function Header Comment** (plate comment)
```python
set_plate_comment(
    function_address="0x...",
    comment="""Processes player slot states with iteration and state-based dispatch.

Algorithm:
- Iterates through player slots up to SecurityValidationValue limit
- Dispatches on player state (0, 1, 4) via jump table
- State 1: Sets UI variable for slot
- State 4: Resets render buffers if audio active
- Post-iteration: Validates random generator and entity state

Returns: void"""
)
```

---

### 6. Verification and Completeness

**6.1 Check Function Completeness**
```python
completeness = analyze_function_completeness(function_address="0x...")
# Returns: has_custom_name, has_prototype, completeness_score (0-100)
# Returns: undefined_variables, missing_comments
```

**6.2 Verify Documentation Applied**
- Function renamed (not FUN_*)
- Prototype set with calling convention
- All variables defined (no undefined1, undefined2)
- Labels created at key jump targets
- Comments added for complex logic
- Data structures created/refined

---

## Naming Conventions

### Functions (PascalCase)
- `ProcessPlayerSlotStates` (not `HandleSlots`, `PlayerLoop`)
- `ValidateSecurityToken` (not `CheckSecurity`)
- `InitializeGameState` (not `Init`, `Setup`)

### Variables (camelCase or Hungarian)
- `playerIndex`, `bufferSize`, `isValid`
- `dwFlags`, `pBuffer`, `nCount` (Hungarian notation)
- `ecx_savedState`, `eax_returnValue` (register artifacts when meaningful)

### Labels (snake_case)
- `loop_start`, `validation_failed`, `exit_function`
- `state_0_init`, `jump_table`, `error_handler`

### Structure Fields (Hungarian notation common)
- `dwResourceType`, `pDataBuffer`, `nElementCount`
- `fEnabled`, `bActive`, `szPlayerName`
- `Reserved1`, `Padding2`, `Unknown3` (for unidentified fields)

### Structure Names (PascalCase)
- `PlayerSlotData`, `ResourceConfig`, `GameStateTable`

---

## Implementation Order (CRITICAL)

```python
# 1. GATHER CONTEXT
decompile_function(name)
disassemble_function(address)
get_function_callees(name)
get_function_variables(name)
analyze_data_region(data_address)  # for each data reference

# 2. DATA STRUCTURES (type before name)
create_struct() or apply_data_type()  # Define types
rename_data()                          # Apply names
set_decompiler_comment()               # Document

# 3. FUNCTION DOCUMENTATION
rename_function()
set_function_prototype()  # includes return type
batch_set_variable_types()  # define undefined variables
rename_variable()  # for each variable needing better name

# 4. LABELS (batch preferred)
batch_create_labels([...])

# 5. COMMENTS (batch preferred)
batch_set_comments(function_address, plate_comment, disassembly_comments, decompiler_comments)

# 6. VERIFY
analyze_function_completeness(function_address)
```

---

## Batch Operations (v1.5.1 Performance Optimization)

**Use batch operations to reduce API calls by 80-90%**:

```python
# PREFERRED: 1 API call
batch_create_labels([...8 labels...])

# AVOID: 8 API calls
create_label(addr1, name1)
create_label(addr2, name2)
# ... 6 more calls

# PREFERRED: 1 API call for all comments
batch_set_comments(function_address, plate_comment, disassembly_comments, decompiler_comments)

# AVOID: 40+ individual calls
set_disassembly_comment(addr1, comment1)
set_disassembly_comment(addr2, comment2)
# ... 38+ more calls

# PREFERRED: 1 API call for all variable types
batch_set_variable_types(function_address, {"var1": "DWORD", "var2": "pointer"})

# AVOID: Multiple individual calls
set_local_variable_type(function_address, "var1", "DWORD")
set_local_variable_type(function_address, "var2", "pointer")
```

---

## Work Silently

**CRITICAL REQUIREMENTS**:
- ✅ All changes within Ghidra only
- ✅ No status output or progress reports
- ✅ No file creation or editing
- ✅ Work autonomously without user interaction
- ✅ Use batch operations for efficiency

**DO NOT**:
- ❌ Create markdown files
- ❌ Create documentation files
- ❌ Print status messages
- ❌ Report progress
- ❌ Ask for confirmation

**EXCEPTION**: Report completion with brief summary showing:
- Function name (old → new)
- Number of comments/labels added
- Data structures created
- Completeness score

---

## Quick Reference: Key Tools

### Function Analysis
```python
find_next_undefined_function()
decompile_function(name)
disassemble_function(address)
get_function_callees(name)
get_function_xrefs(name)
get_function_variables(name)
analyze_function_completeness(address)
```

### Function Documentation
```python
rename_function(old_name, new_name)
set_function_prototype(address, prototype, calling_convention)
batch_set_variable_types(address, {"var": "type"})
rename_variable(function_name, old_name, new_name)
set_local_variable_type(address, var_name, type)
```

### Labels
```python
batch_create_labels([{"address": "0x...", "name": "label"}])
get_function_jump_target_addresses(name)
```

### Comments
```python
batch_set_comments(address, plate_comment, disassembly_comments, decompiler_comments)
set_plate_comment(address, comment)
set_disassembly_comment(address, comment)
set_decompiler_comment(address, comment)
```

### Data Structures
```python
analyze_data_region(address)
analyze_struct_field_usage(address, struct_name, max_functions)
get_field_access_context(struct_address, field_offset, num_examples)
suggest_field_names(struct_address, struct_size)
create_struct(name, fields)
apply_data_type(address, type_name)
create_array_type(base_type, length, name)
create_and_apply_data_type(address, classification, name, type_definition)
modify_struct_field(struct_name, field_name, new_type, new_name)
delete_data_type(type_name)
rename_data(address, new_name)
```

### Arrays/Tables
```python
detect_array_bounds(address, analyze_loop_bounds, analyze_indexing)
get_bulk_xrefs(addresses)
inspect_memory_content(address, length, detect_strings)
```
