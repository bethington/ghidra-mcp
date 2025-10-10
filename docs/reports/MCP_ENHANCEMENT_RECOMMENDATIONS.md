# MCP Enhancement Recommendations
## Analysis Date: 2025-10-10

Based on completing a full function analysis workflow using the Ghidra MCP tools, the following enhancements are recommended to improve efficiency and completeness.

---

## Priority 1: Critical Missing Tools

### 1. Batch Comment Operations
**Current State**: Must make individual calls for each comment
**Pain Point**: Added 4 comments requiring 4 separate API calls
**Proposed Tool**: `batch_set_comments`

```python
@mcp.tool()
def batch_set_comments(
    function_address: str,
    decompiler_comments: list[dict] = None,  # [{"address": "0x...", "comment": "..."}]
    disassembly_comments: list[dict] = None,  # [{"address": "0x...", "comment": "..."}]
    plate_comment: str = None  # Function header summary
) -> str:
    """Add multiple comments to a function in a single operation."""
```

**Estimated Impact**: Reduce 10+ API calls to 1 for typical function documentation

---

### 2. Function Plate Comment (Header Summary)
**Current State**: No tool to add function-level header comments
**Gap**: Prompt requires "Add high-level algorithm summary in function header"
**Proposed Tool**: `set_plate_comment`

```python
@mcp.tool()
def set_plate_comment(
    function_address: str,
    comment: str
) -> str:
    """
    Set the plate (header) comment for a function.
    This appears above the function in both disassembly and decompiler views.
    """
```

**Java Implementation**:
```java
Function func = getFunctionAt(address);
func.setComment(comment);  // Plate comment
```

---

### 3. Get Function Variables
**Current State**: Must parse decompiled output to find variables
**Pain Point**: No programmatic way to list all variables needing renaming
**Proposed Tool**: `get_function_variables`

```python
@mcp.tool()
def get_function_variables(
    function_name: str
) -> str:
    """
    Get all variables in a function including parameters, locals, and stack variables.

    Returns:
        JSON with variable names, types, storage locations, and current names
    """
```

**Return Format**:
```json
{
  "parameters": [
    {"name": "param_1", "type": "int", "register": "ECX", "defined": true}
  ],
  "locals": [
    {"name": "local_8", "type": "undefined4", "stack_offset": -8, "defined": false}
  ]
}
```

---

### 4. Batch Rename Operations
**Current State**: Individual calls to rename function, then each variable
**Proposed Tool**: `batch_rename_function_components`

```python
@mcp.tool()
def batch_rename_function_components(
    function_address: str,
    function_name: str = None,
    parameter_renames: dict = None,  # {"old_name": "new_name"}
    local_renames: dict = None,
    return_type: str = None
) -> str:
    """Rename function and all its components in a single atomic operation."""
```

---

## Priority 2: Enhanced Existing Tools

### 5. Improved Type System Feedback
**Current State**: `create_struct` fails with cryptic "Unknown field type: void*"
**Issue**: No documentation of valid Ghidra type strings
**Proposed Enhancement**:

```python
@mcp.tool()
def get_valid_data_types(
    category: str = None  # "pointer", "integer", "float", "struct", etc.
) -> str:
    """
    Get list of valid type strings that Ghidra accepts.
    Helps users construct proper create_struct field definitions.
    """
```

**Alternative**: Enhance error messages in `create_struct` to suggest valid types:
```python
# Current error:
"Unknown field type: void*"

# Enhanced error:
"Unknown field type: void*. Did you mean 'pointer', 'void *', or 'LPVOID'?
Use get_valid_data_types() to see all options."
```

---

### 6. Enhanced apply_data_type with Validation
**Current State**: Tool exists but doesn't validate before applying
**Enhancement**: Add dry-run mode and validation feedback

```python
@mcp.tool()
def apply_data_type(
    address: str,
    type_name: str,
    clear_existing: bool = True,
    validate_only: bool = False  # NEW: Check without applying
) -> str:
    """
    Apply data type with optional validation.

    Returns:
        If validate_only=True: Returns size check, alignment check, conflict warnings
        If validate_only=False: Applies and returns success/failure
    """
```

---

## Priority 3: Workflow Optimization Tools

### 7. Analyze Function Completeness
**Use Case**: Verify all documentation requirements are met
**Proposed Tool**: `analyze_function_completeness`

```python
@mcp.tool()
def analyze_function_completeness(
    function_address: str
) -> str:
    """
    Analyze how completely a function has been documented.

    Returns:
        {
          "has_prototype": true,
          "has_calling_convention": true,
          "undefined_variables": ["local_8", "param_2"],
          "missing_types": ["address 0x123", "address 0x456"],
          "has_plate_comment": false,
          "instruction_comment_coverage": 0.45,  # 45% of instructions commented
          "magic_numbers_uncommented": ["0x20", "0x8"]
        }
    """
```

---

### 8. Smart Function Finder
**Current State**: `search_functions_by_name("FUN_")` returns all undefined functions
**Enhancement**: Add filtering and prioritization

```python
@mcp.tool()
def find_next_undefined_function(
    start_address: str = None,  # Start from specific address
    criteria: str = "name_pattern",  # "name_pattern", "no_prototype", "no_comments"
    pattern: str = "FUN_",
    direction: str = "ascending"  # "ascending", "descending", "xref_count"
) -> str:
    """
    Find the next function needing analysis based on intelligent criteria.

    Returns:
        Function address, name, xref count, current completeness score
    """
```

---

### 9. Batch Variable Type Setting
**Gap**: `set_local_variable_type` exists but requires individual calls
**Enhancement**: Batch version for efficiency

```python
@mcp.tool()
def batch_set_variable_types(
    function_address: str,
    variable_types: dict  # {"variableName": "newType"}
) -> str:
    """Set types for multiple variables in a single call."""
```

---

### 10. Function Analysis Context
**Use Case**: Better understand function purpose before renaming
**Proposed Tool**: `get_function_analysis_context`

```python
@mcp.tool()
def get_function_analysis_context(
    function_address: str,
    include_caller_context: bool = True,
    include_string_refs: bool = True,
    include_api_calls: bool = True
) -> str:
    """
    Get comprehensive context to help determine function purpose.

    Returns:
        {
          "callers": ["FunctionA", "FunctionB"],
          "caller_contexts": ["Called in error handling path", "..."],
          "string_refs": ["Error: Invalid input", "Success"],
          "api_calls": ["malloc", "free", "strcpy"],
          "suggested_purpose": "Memory allocation wrapper with validation"
        }
    """
```

---

## Priority 4: Advanced Features

### 11. Auto-Documentation AI Assist
**Concept**: Leverage existing analysis tools to auto-generate suggestions

```python
@mcp.tool()
def suggest_function_documentation(
    function_address: str,
    include_variable_names: bool = True,
    include_comments: bool = True,
    include_data_types: bool = True
) -> str:
    """
    AI-assisted analysis to suggest:
    - Function name based on behavior and xrefs
    - Variable names based on usage patterns
    - Comment suggestions for key operations
    - Data structure definitions for memory accesses

    Note: Suggestions must be reviewed and approved before applying.
    """
```

---

### 12. Undo/Rollback Support
**Safety Feature**: Allow reverting changes during analysis

```python
@mcp.tool()
def create_analysis_checkpoint(
    function_address: str,
    checkpoint_name: str
) -> str:
    """Save current function state for potential rollback."""

@mcp.tool()
def rollback_to_checkpoint(
    function_address: str,
    checkpoint_name: str
) -> str:
    """Restore function to previously saved state."""
```

---

## Implementation Priority Matrix

| Priority | Tool | Impact | Effort | Ratio |
|----------|------|--------|--------|-------|
| P1 | batch_set_comments | High | Low | 10/10 |
| P1 | set_plate_comment | High | Low | 10/10 |
| P1 | get_function_variables | High | Medium | 8/10 |
| P2 | get_valid_data_types | Medium | Low | 7/10 |
| P2 | apply_data_type validation | Medium | Low | 7/10 |
| P3 | analyze_function_completeness | High | High | 6/10 |
| P3 | find_next_undefined_function | Medium | Medium | 6/10 |
| P1 | batch_rename_function_components | High | Medium | 8/10 |
| P3 | get_function_analysis_context | Medium | High | 5/10 |
| P4 | suggest_function_documentation | Low | Very High | 3/10 |

---

## Recommended Implementation Order

1. **Week 1**: `set_plate_comment`, `batch_set_comments`
   *Reason*: Highest impact, lowest effort, addresses immediate prompt requirements

2. **Week 2**: `get_function_variables`, `batch_rename_function_components`
   *Reason*: Enables efficient variable renaming workflows

3. **Week 3**: `get_valid_data_types`, enhance `apply_data_type`
   *Reason*: Improves type system usability

4. **Week 4**: `analyze_function_completeness`, `find_next_undefined_function`
   *Reason*: Workflow optimization and quality assurance

5. **Future**: Advanced AI-assist and checkpoint features
   *Reason*: Nice-to-have, requires significant effort

---

## Testing Requirements

Each new tool must include:

1. **Unit tests**: Mock Ghidra API responses
2. **Integration tests**: Verify REST endpoints work with real Ghidra instance
3. **Functional tests**: Complete workflows (e.g., document entire function using batch tools)
4. **Performance tests**: Batch operations must be faster than individual calls
5. **Documentation**: API reference updates, example usage in README

---

## Backward Compatibility

All enhancements must maintain backward compatibility:
- Existing tools continue to work unchanged
- New batch tools supplement (not replace) individual operations
- Optional parameters default to existing behavior
- Version bumps follow semantic versioning (1.2.0 → 1.3.0 for new features)
