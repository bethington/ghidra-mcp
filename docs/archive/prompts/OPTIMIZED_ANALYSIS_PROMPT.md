# Optimized Ghidra Function Analysis Prompt

## Overview
This is an improved version of the original analysis prompt with clearer requirements, concrete success criteria, and defined workflows optimized for the current Ghidra MCP toolset.

---

## Complete Prompt

```
Find the first function matching pattern "FUN_" in ascending address order starting from the current cursor position. If a specific function name is provided, use that instead.

ANALYSIS REQUIREMENTS:

1. FUNCTION ANALYSIS
   - Decompile the target function
   - Get all xrefs TO the function (callers)
   - Get all xrefs FROM the function (callees)
   - Analyze the function's purpose based on:
     * Caller context and usage patterns
     * Called functions and API usage
     * String references
     * Data structure access patterns

2. RENAME OPERATIONS (ALWAYS perform, no exceptions)
   - Function: Use PascalCase reflecting purpose inferred from analysis
     * Example: FUN_6fae7e70 → InvokeVirtualMethod
   - All parameters: Descriptive names, NO prefixes (no p, lp, dw, n, h, etc.)
     * Example: param_1 → objectInstance
   - All local variables: Descriptive names based on usage
     * Example: local_8 → vtablePointer
   - Register-derived variables: Include register ONLY when semantically meaningful
     * Good: eaxReturnValue (register provides context)
     * Bad: ecxParam1 (register doesn't add meaning)

3. FUNCTION SIGNATURE
   - Set complete function prototype with:
     * Return type (void, int, BOOL, pointer, struct, etc.)
     * All parameter types matching their usage
     * Calling convention (__cdecl, __stdcall, __fastcall, __thiscall)
   - Example: void InvokeVirtualMethod(void* objectInstance) __thiscall

4. LABELS (create/rename for all jump targets)
   - Use snake_case convention
   - Name based on PURPOSE, not location
   - Examples:
     * error_handler
     * success_path
     * validate_input
     * cleanup_and_return

5. DATA STRUCTURES AND TYPES
   - Identify all dereferenced memory locations
   - For each multi-field access pattern:
     * Create structure definition with descriptive field names
     * Apply structure to the base memory address using apply_data_type
   - For single-value accesses:
     * Apply appropriate primitive type (DWORD, pointer, BOOL, etc.)
   - Create missing types:
     * Structures for objects with multiple fields
     * Typedefs for complex pointer types
     * Enums for magic number sets

6. COMMENTS (comprehensive documentation)

   A. Decompiler Comments (at key addresses):
      - Algorithm context and purpose
      - Data structure member meanings
      - Magic number explanations (ALWAYS document hex constants)
      - Validation logic and edge cases
      - Error handling paths

   B. Disassembly Comments (MAXIMUM 32 characters):
      - Every memory access instruction
      - Every arithmetic operation with constants
      - Every jump/branch (condition being tested)
      - Every function call
      - Format: "Action performed" not "Get the value"
      - Examples:
        * "Load vtable pointer"
        * "Check input validity"
        * "Jump to error handler"

   C. Function Header Summary:
      - High-level algorithm description (2-4 sentences)
      - Input/output behavior
      - Side effects if any
      - Known edge cases or limitations

7. VERIFICATION (perform after all changes)
   - Decompile function again to confirm:
     * No undefined variables remain
     * All memory accesses have types
     * All parameters have descriptive names
     * Function prototype is complete and correct
   - If any issues found, fix them before completing

EXECUTION CONSTRAINTS:
- Show NO status or progress output
- Do NOT create or edit any files
- ALL changes must be performed within Ghidra only
- Use batch operations where possible to minimize API calls
- Work silently until all tasks complete
```

---

## Optimized Workflow Steps

### Step 1: Initial Analysis (Parallel Calls)
```python
# Make these calls simultaneously
- decompile_function(name=target)
- get_function_xrefs(name=target, limit=50)
- get_function_callees(name=target, limit=50)
- disassemble_function(address=target_address)
- get_function_jump_target_addresses(name=target)
```

### Step 2: Rename Operations (Sequential)
```python
# Must rename function first before renaming variables
1. rename_function(old_name=target, new_name=analyzed_name)
2. For each variable:
   - rename_variable(function_name=analyzed_name, old_name=var, new_name=new_var)
```

### Step 3: Set Function Signature
```python
set_function_prototype(
    function_address=address,
    prototype=complete_signature,
    calling_convention=determined_convention
)
```

### Step 4: Create Data Structures
```python
# For each identified structure
1. create_struct(name=struct_name, fields=field_list)
2. apply_data_type(address=base_addr, type_name=struct_name)

# For VTable example:
create_struct(name="VTable", fields=[
    {"name": "method_0x00", "type": "pointer"},
    {"name": "method_0x04", "type": "pointer"},
    # ... all vtable entries
])
```

### Step 5: Labels (if jump targets exist)
```python
# For each jump target address
create_label(address=target_addr, name=descriptive_snake_case_name)
```

### Step 6: Comments
```python
# Decompiler comment at function start
set_decompiler_comment(
    address=function_start,
    comment=high_level_summary
)

# Disassembly comments at each instruction
For each significant instruction:
    set_disassembly_comment(
        address=instruction_addr,
        comment=concise_description  # <= 32 chars
    )
```

### Step 7: Verification
```python
# Verify all changes applied
final_decompilation = decompile_function(name=new_function_name)
# Check for:
# - "undefined" in output
# - Generic names (param_1, local_8)
# - Untyped memory accesses
```

---

## Comparison: Original vs Optimized

| Aspect | Original Prompt | Optimized Prompt | Improvement |
|--------|----------------|------------------|-------------|
| Function selection | "Next undefined function" (ambiguous) | "First FUN_* in ascending order from cursor" | Clear, reproducible |
| Renaming criteria | "If needed" (subjective) | "ALWAYS perform, no exceptions" | Enforceable |
| Variable naming | "without prefixes" | "NO p, lp, dw, n, h prefixes" with examples | Specific |
| Comment scope | "Add comments explaining..." | Separate requirements for decompiler/disassembly/header | Complete |
| Data structures | "Add missing data structures" | "Identify → Create → Apply workflow" | Actionable |
| Verification | Not mentioned | "Decompile again and verify" step | Quality assurance |
| Workflow order | Not specified | 7 sequential steps with parallel optimizations | Efficient |

---

## Example Usage

### Before (Ambiguous):
```
Find the $funcName function. If needed, rename...
```

### After (Specific):
```
Find the first function matching pattern "FUN_" in ascending address order.

[Then follows clear 7-step workflow with verification]
```

---

## Success Criteria Checklist

After completing the prompt, the function MUST have:

- [ ] Descriptive PascalCase name based on analysis
- [ ] Complete function prototype with calling convention
- [ ] All parameters renamed (no param_1, param_2)
- [ ] All local variables renamed (no local_8, local_c)
- [ ] All jump targets labeled in snake_case
- [ ] Data structures created and applied to memory references
- [ ] Decompiler comment explaining algorithm
- [ ] Disassembly comments on key instructions (≤32 chars)
- [ ] No undefined variables in decompilation
- [ ] All memory accesses have proper types
- [ ] Verification step completed successfully

---

## Known Limitations (Current MCP Tools)

1. **No batch comment operation**: Must make individual calls for each comment
   - Workaround: Accept multiple API calls until batch tool added

2. **No function header comment tool**: Cannot add plate comment
   - Workaround: Use decompiler comment at function start address

3. **No variable list tool**: Cannot programmatically get all variables
   - Workaround: Parse decompiled output to identify variables

4. **Type system not documented**: Valid type strings unclear
   - Workaround: Use generic types like "pointer", "int", "DWORD"

5. **No completeness checker**: Must manually verify all requirements
   - Workaround: Decompile function again and visually inspect

---

## Future Enhancements

When the following tools are added, update this prompt:

1. `batch_set_comments` → Replace individual comment calls
2. `set_plate_comment` → Add proper function header
3. `get_function_variables` → List all variables programmatically
4. `analyze_function_completeness` → Automate verification step
5. `batch_rename_function_components` → Atomic rename operations

---

## Version History

- **v1.0** (Original): Basic prompt with ambiguous requirements
- **v2.0** (This version): Clear criteria, defined workflow, verification step
- **v2.1** (Planned): Integration with batch tools when available
