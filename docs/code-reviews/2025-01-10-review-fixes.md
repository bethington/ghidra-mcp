# Code Review Fixes - Implementation Guide

## Critical Fixes to Apply

### Fix #1: Rename create_and_apply_data_type_enhanced → create_and_apply_data_type

**Location**: `bridge_mcp_additions.py` lines 496-593

**Action**: This function should REPLACE the existing `create_and_apply_data_type` in the main bridge_mcp_ghidra.py file.

**Change**:
```python
# OLD (line 496):
def create_and_apply_data_type_enhanced(

# NEW:
def create_and_apply_data_type(
```

**Documentation Update**:
```python
"""
Apply data type, name, and comment in a single atomic operation.

ENHANCED in v1.3.0:
- ✅ Now accepts Python dicts AND JSON strings for type_definition (previously JSON only)
- ✅ Better validation with helpful error messages
- ✅ Helper functions available for common patterns
- ✅ Auto-verification with clear success/failure reporting
- ✅ Content verification to prevent string misidentification

Args:
    address: Target address (e.g., "0x6fb835b8")
    classification: Data classification: "PRIMITIVE", "STRUCTURE", "ARRAY", or "STRING"
    name: Name to apply (optional)
    comment: Comment to apply (optional)
    type_definition: Type definition as JSON string OR Python dict (ENHANCED):

                    For PRIMITIVE:
                      {"type": "dword"} OR '{"type": "dword"}'

                    For STRUCTURE:
                      {"name": "MyStruct", "fields": [...]} OR JSON string

                    For ARRAY:
                      {"element_type": "dword", "count": 64} OR JSON string

                    HELPER FUNCTIONS (recommended for readability):
                      type_def = create_primitive_definition("dword")
                      type_def = create_dword_array_definition(64)
                      type_def = create_pointer_array_definition("char", 18)
                      type_def = create_string_array_definition(18)
                      type_def = create_struct_definition("MyStruct", fields)

Returns:
    Success message with all operations performed

Example:
    # Using dict (NEW in v1.3.0)
    create_and_apply_data_type(
        address="0x6fb835b8",
        classification="ARRAY",
        name="ConfigArray",
        type_definition={"element_type": "dword", "count": 7}  # Dict!
    )

    # Using helper function (RECOMMENDED)
    type_def = create_dword_array_definition(7)
    create_and_apply_data_type(
        address="0x6fb835b8",
        classification="ARRAY",
        name="ConfigArray",
        type_definition=type_def
    )

    # Using JSON string (backwards compatible)
    create_and_apply_data_type(
        address="0x6fb835b8",
        classification="ARRAY",
        type_definition='{"element_type": "dword", "count": 7}'
    )
"""
```

---

### Fix #2: Rename Parameter in find_format_string_usages

**Location**: `bridge_mcp_additions.py` line 197

**Change**:
```python
# OLD:
def find_format_string_usages(format_pattern: str, offset: int = 0, limit: int = 100) -> str:

# NEW:
def find_format_string_usages(format_string: str, offset: int = 0, limit: int = 100) -> str:
    """
    Find all usages of a specific format string pattern.

    Args:
        format_string: Format string to search for (e.g., "%d", "%s", "%x")
                      Common patterns: "%d", "%s", "%x", "%p", "%f", "%c"
        offset: Pagination offset for large result sets (default: 0)
        limit: Maximum number of results to return (default: 100)
    ...
```

**Also update line 227-234**:
```python
# OLD:
if not format_pattern:
    raise GhidraValidationError("format_pattern is required")

params = {
    "pattern": format_pattern,
    "offset": offset,
    "limit": limit
}

# NEW:
if not format_string:
    raise GhidraValidationError("format_string is required")

params = {
    "pattern": format_string,  # Server still uses "pattern" - that's fine
    "offset": offset,
    "limit": limit
}
```

---

### Fix #3: Expose Helper Functions as MCP Tools

**Location**: `bridge_mcp_additions.py` lines 323-408

**Change**: Add `@mcp.tool()` decorator to all 5 helper functions:

```python
@mcp.tool()
def create_dword_array_definition(count: int) -> str:
    """
    Generate type definition for DWORD array.

    Creates a properly formatted type definition for use with create_and_apply_data_type().
    This is a helper tool that simplifies creating DWORD array types.

    Args:
        count: Number of DWORD elements in array (must be positive integer)

    Returns:
        JSON string ready for use as type_definition parameter

    Example:
        # Create 64-element DWORD array
        type_def = create_dword_array_definition(64)

        # Apply to memory address
        create_and_apply_data_type(
            address="0x6fb835d4",
            classification="ARRAY",
            name="ConfigArray",
            type_definition=type_def
        )
    """
    if not isinstance(count, int) or count <= 0:
        raise GhidraValidationError("count must be a positive integer")

    return json.dumps({"element_type": "dword", "count": count})


@mcp.tool()
def create_pointer_array_definition(base_type: str, count: int) -> str:
    """
    Generate type definition for pointer array.

    Creates a properly formatted type definition for arrays of pointers.
    Useful for string tables, function pointer arrays, or structure pointer arrays.

    Args:
        base_type: Base type for pointers (e.g., "char", "int", "MyStruct")
                  Common types: "char" (for strings), "void", struct names
        count: Number of pointer elements in array (must be positive integer)

    Returns:
        JSON string ready for use as type_definition parameter

    Example:
        # Create 18-element char* array (string table)
        type_def = create_pointer_array_definition("char", 18)

        # Apply to memory address
        create_and_apply_data_type(
            address="0x6fb8b984",
            classification="ARRAY",
            name="MonthNameTable",
            type_definition=type_def
        )
    """
    if not isinstance(count, int) or count <= 0:
        raise GhidraValidationError("count must be a positive integer")

    if not base_type or not isinstance(base_type, str):
        raise GhidraValidationError("base_type must be a non-empty string")

    return json.dumps({"element_type": f"{base_type} *", "count": count})


@mcp.tool()
def create_string_array_definition(count: int) -> str:
    """
    Generate type definition for string pointer array.

    Creates a properly formatted type definition specifically for arrays of string pointers.
    This is equivalent to create_pointer_array_definition("char", count) but more convenient.

    Args:
        count: Number of string pointers in array (must be positive integer)

    Returns:
        JSON string ready for use as type_definition parameter

    Example:
        # Create 12-element string array (month names)
        type_def = create_string_array_definition(12)

        # Apply to memory address
        create_and_apply_data_type(
            address="0x6fb8b984",
            classification="ARRAY",
            name="MonthNames",
            comment="Array of pointers to month name strings",
            type_definition=type_def
        )
    """
    if not isinstance(count, int) or count <= 0:
        raise GhidraValidationError("count must be a positive integer")

    return json.dumps({"element_type": "char *", "count": count})


@mcp.tool()
def create_struct_definition(name: str, fields: list) -> str:
    """
    Generate type definition for custom structure.

    Creates a properly formatted type definition for structures with custom fields.
    Useful when create_packed_struct is not needed (natural alignment is fine).

    Args:
        name: Structure name (must be valid identifier)
        fields: List of field dictionaries, each containing:
               - name: Field name (string)
               - type: Field type (string, e.g., "dword", "char[32]", "MyStruct*")
               - offset: (optional) Explicit byte offset for field

    Returns:
        JSON string ready for use as type_definition parameter

    Example:
        # Define configuration structure
        fields = [
            {"name": "id", "type": "dword"},
            {"name": "name", "type": "char[32]"},
            {"name": "flags", "type": "word"},
            {"name": "pNext", "type": "ConfigStruct*"}
        ]
        type_def = create_struct_definition("ConfigStruct", fields)

        # Apply to memory address
        create_and_apply_data_type(
            address="0x6fb835b8",
            classification="STRUCTURE",
            name="MainConfig",
            type_definition=type_def
        )
    """
    validate_function_name(name)

    if not isinstance(fields, list) or len(fields) == 0:
        raise GhidraValidationError("fields must be a non-empty list")

    for field in fields:
        if not isinstance(field, dict):
            raise GhidraValidationError("each field must be a dictionary")
        if "name" not in field or "type" not in field:
            raise GhidraValidationError("each field must have 'name' and 'type'")

    return json.dumps({"name": name, "fields": fields})


@mcp.tool()
def create_primitive_definition(type_name: str) -> str:
    """
    Generate type definition for primitive data type.

    Creates a properly formatted type definition for basic data types.
    Simplifies the common case of applying a single primitive type.

    Args:
        type_name: Primitive type name, one of:
                  - "byte", "word", "dword", "qword" (unsigned integers)
                  - "int8", "int16", "int32", "int64" (signed integers)
                  - "float", "double" (floating point)
                  - "char", "wchar" (characters)
                  - "string", "unicode" (null-terminated strings)
                  - "bool" (boolean)

    Returns:
        JSON string ready for use as type_definition parameter

    Example:
        # Apply DWORD type to address
        type_def = create_primitive_definition("dword")
        create_and_apply_data_type(
            address="0x6fb8057c",
            classification="PRIMITIVE",
            name="ConfigValue",
            type_definition=type_def
        )

        # Apply string type to address
        type_def = create_primitive_definition("string")
        create_and_apply_data_type(
            address="0x6fb7ffbc",
            classification="STRING",
            name="ErrorMessage",
            type_definition=type_def
        )
    """
    valid_types = [
        "byte", "word", "dword", "qword",
        "int8", "int16", "int32", "int64",
        "float", "double",
        "char", "wchar",
        "string", "unicode",
        "bool"
    ]

    if type_name not in valid_types:
        raise GhidraValidationError(
            f"type_name must be one of: {', '.join(valid_types)}"
        )

    return json.dumps({"type": type_name})
```

---

### Fix #4 (Optional): Shorten batch_decompile_xref_sources_chunked Name

**Location**: `bridge_mcp_additions.py` line 249

**Current**:
```python
def batch_decompile_xref_sources_chunked(
```

**Proposed**:
```python
def batch_decompile_xrefs(
```

**Rationale**:
- Shorter, clearer name
- "chunked" is implementation detail (always auto-handled)
- "sources" is implied (xrefs are always from sources to target)

**Documentation Update**:
```python
"""
Decompile functions that reference a target address (with automatic chunking).

Handles both small and large xref counts intelligently:
- Small count (<10): Decompiles all functions
- Large count (50+): Automatically chunks and returns most relevant functions

Prevents timeouts and token limit errors that can occur with high-xref data.

Args:
    target_address: Address being referenced (e.g., "0x6fb8057c")
    max_functions: Maximum functions to decompile (default: 10)
                  Increase for more coverage, decrease for faster results
    prioritize_user_functions: Prefer user-defined over library functions (default: True)
                               When True, FUN_* functions ranked lower than named functions
    include_usage_context: Extract specific usage lines from decompiled code (default: True)
                          Shows how target address is used in each function
...
```

**Also update**:
- Java endpoint name: `/batch_decompile_xref_sources_chunked` → `/batch_decompile_xrefs`
- All references in documentation

---

## Implementation Checklist

### Must Do (Critical Fixes)
- [x] Rename `create_and_apply_data_type_enhanced` → `create_and_apply_data_type`
- [x] Update all references to the function
- [x] Fix parameter name in `find_format_string_usages`: `format_pattern` → `format_string`
- [x] Add `@mcp.tool()` to 5 helper functions
- [x] Enhance helper function documentation as shown above

### Should Do (High Value)
- [x] Rename `batch_decompile_xref_sources_chunked` → `batch_decompile_xrefs`
- [x] Update Java endpoint name to `/batch_decompile_xrefs`
- [x] Update all documentation references

### Testing After Fixes
- [ ] Test `create_and_apply_data_type` with dict parameter
- [ ] Test `create_and_apply_data_type` with JSON string (backwards compatibility)
- [ ] Test all 5 helper functions as MCP tools
- [ ] Test `find_format_string_usages` with new parameter name
- [ ] Verify endpoint naming matches tool names

---

## Files to Update

1. **bridge_mcp_additions.py**
   - Line 197: Fix parameter name
   - Line 323-408: Add @mcp.tool() decorators
   - Line 496: Rename function
   - (Optional) Line 249: Rename function

2. **GhidraMCPPluginAdditions.java**
   - (Optional) Update endpoint name if tool renamed

3. **Documentation Files**
   - TOOLING_IMPROVEMENTS.md
   - INTEGRATION_GUIDE.md
   - COMPLETE_IMPLEMENTATION_SUMMARY.md

---

## Backward Compatibility

### create_and_apply_data_type Enhancement
✅ **Fully Backward Compatible**
- Still accepts JSON strings (existing behavior)
- Now also accepts dicts (new behavior)
- No breaking changes

### find_format_string_usages Parameter Rename
⚠️ **Minor Breaking Change**
- Users calling with named parameter `format_pattern=` will break
- Users calling with positional argument (most common) unaffected
- Low impact - internal consistency improvement

### Helper Functions as MCP Tools
✅ **Fully Backward Compatible**
- Functions still work as Python functions
- Now also callable as MCP tools
- No breaking changes

### batch_decompile_xref_sources_chunked Rename (Optional)
⚠️ **Breaking Change if Implemented**
- Old name would no longer exist
- Users would need to update tool calls
- **Recommendation**: Keep old name for v1.3, deprecate in v1.4, remove in v2.0

---

## Summary

**Critical fixes**: 2 (rename function, fix parameter)
**High-value enhancements**: 1 (expose helpers)
**Optional improvements**: 1 (rename long function)

**Estimated implementation time**: 1-2 hours
**Risk level**: LOW (mostly additive changes, backward compatible)
**Impact**: HIGH (better user experience, clearer API)
