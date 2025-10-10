# Ghidra Function Analysis Prompt

## Overview
This prompt provides comprehensive instructions for analyzing and documenting a function in Ghidra using best practices for naming, typing, and documentation.

## Prompt Template

```
Find the next Undocumented or poorly documented function. If needed, rename the function, callees, pointers, variables to include register artifacts and parameters with names without prefixes using best practices for naming functions and variables, names based on their purpose and callers (xrefs) using PascalCase convention.

Set the current function's return datatype and name, function's prototype and calling convention.

Create or if existing then rename labels at jump targets with names based on their purpose using snake_case convention.

Add missing data structures or types and then set appropriate data types for referenced memory locations.

Add decompiler and disassembly (within 32 characters) comments explaining algorithm context, structures, magic_numbers, validation logic, edge_cases and purpose.

Add high-level algorithm summary in function header.

Define the function return data type.

Define all undefined variables and parameters.

Show no status or output of any kind. Do not create or edit any files, all changes should be within Ghidra.
```

## Key Requirements

### Naming Conventions
- **Functions**: PascalCase based on purpose and xrefs
- **Variables/Parameters**: No prefixes, descriptive names based on purpose
- **Labels**: snake_case based on purpose at jump targets
- **Callees/Pointers**: Descriptive names following PascalCase

### Type Definitions
- Set function return data type
- Define function prototype with calling convention
- Create missing data structures as needed
- Apply appropriate data types to referenced memory locations
- Define all undefined variables and parameters

### Documentation
- **Decompiler comments**: Algorithm context, structures, magic numbers, validation logic, edge cases, purpose
- **Disassembly comments**: Within 32 characters, concise explanations
- **Function header**: High-level algorithm summary

### Execution Constraints
- No status or output messages
- No file creation or editing
- All changes performed within Ghidra only

## Usage Example

Replace `$funcName` with the target function name:

```
Find the ProcessInputBuffer function. If needed, rename the function, callees, pointers...
```

## Workflow Checklist

- [ ] Locate target function
- [ ] Analyze xrefs and callers to understand purpose
- [ ] Rename function with descriptive PascalCase name
- [ ] Set function prototype and calling convention
- [ ] Define return type
- [ ] Rename variables and parameters (no prefixes)
- [ ] Create/rename labels at jump targets (snake_case)
- [ ] Create missing data structures
- [ ] Apply data types to memory references
- [ ] Add decompiler comments (context, structures, magic numbers, etc.)
- [ ] Add disassembly comments (≤32 chars)
- [ ] Add function header summary
- [ ] Define all undefined variables/parameters

## Best Practices

1. **Understand before naming**: Analyze xrefs and usage patterns first
2. **Be descriptive**: Names should convey purpose and usage
3. **Consistent conventions**: PascalCase for functions, snake_case for labels
4. **Complete typing**: No undefined variables or parameters
5. **Thorough documentation**: Explain the why, not just the what
6. **Validate edge cases**: Document unusual conditions and error handling