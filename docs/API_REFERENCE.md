# Ghidra MCP API Reference

Generated on: 2025-09-23 12:34:06

## Core

### /check_connection
- **Method:** GET
- **Description:** Verify plugin connectivity

### /get_metadata
- **Method:** GET
- **Description:** Get program metadata

### /get_current_address
- **Method:** GET
- **Description:** Get current cursor address

### /get_current_function
- **Method:** GET
- **Description:** Get current function info

### /get_entry_points
- **Method:** GET
- **Description:** List program entry points

## Functions

### /list_functions
- **Method:** GET
- **Description:** List all functions

### /functions
- **Method:** GET
- **Description:** List functions (alias)

### /methods
- **Method:** GET
- **Description:** List methods

### /list_methods
- **Method:** GET
- **Description:** List methods (alias)

### /searchFunctions
- **Method:** GET
- **Description:** Search functions by name

### /get_function_by_address
- **Method:** GET
- **Description:** Get function at address

### /decompile
- **Method:** GET
- **Description:** Decompile function

### /decompile_function
- **Method:** GET
- **Description:** Decompile function (alias)

### /disassemble_function
- **Method:** GET
- **Description:** Disassemble function

## Function Analysis

### /function_xrefs
- **Method:** GET
- **Description:** Get function cross-references

### /get_function_xrefs
- **Method:** GET
- **Description:** Get function xrefs (alias)

### /function_callees
- **Method:** GET
- **Description:** Get functions called by function

### /function_callers
- **Method:** GET
- **Description:** Get functions calling function

### /function_call_graph
- **Method:** GET
- **Description:** Get function call graph

### /full_call_graph
- **Method:** GET
- **Description:** Get complete program call graph

### /function_labels
- **Method:** GET
- **Description:** Get labels in function

### /function_jump_targets
- **Method:** GET
- **Description:** Get jump targets in function

### /function_jump_target_addresses
- **Method:** GET
- **Description:** Get jump target addresses

## Memory Analysis

### /xrefs_to
- **Method:** GET
- **Description:** Get references to address

### /xrefs_from
- **Method:** GET
- **Description:** Get references from address

### /segments
- **Method:** GET
- **Description:** List memory segments

### /list_segments
- **Method:** GET
- **Description:** List segments (alias)

### /readMemory
- **Method:** GET
- **Description:** Read memory at address

## Data Types

### /list_data_types
- **Method:** GET
- **Description:** List available data types

### /search_data_types
- **Method:** GET
- **Description:** Search data types by pattern

### /get_type_size
- **Method:** GET
- **Description:** Get size of data type

### /get_struct_layout
- **Method:** GET
- **Description:** Get structure field layout

### /get_enum_values
- **Method:** GET
- **Description:** Get enumeration values

### /analyze_data_types
- **Method:** GET
- **Description:** Analyze data types at address

### /validate_data_type
- **Method:** GET
- **Description:** Validate data type application

### /export_data_types
- **Method:** GET
- **Description:** Export data types

## Data Type Creation

### /create_struct
- **Method:** POST
- **Description:** Create structure data type

### /create_union
- **Method:** POST
- **Description:** Create union data type

### /create_enum
- **Method:** POST
- **Description:** Create enumeration data type

### /create_typedef
- **Method:** POST
- **Description:** Create type definition

### /clone_data_type
- **Method:** POST
- **Description:** Clone existing data type

### /auto_create_struct
- **Method:** POST
- **Description:** Auto-create struct from memory

### /import_data_types
- **Method:** POST
- **Description:** Import data types

### /apply_data_type
- **Method:** POST
- **Description:** Apply data type to address

## Symbols And Names

### /imports
- **Method:** GET
- **Description:** List imported symbols

### /list_imports
- **Method:** GET
- **Description:** List imports (alias)

### /exports
- **Method:** GET
- **Description:** List exported symbols

### /list_exports
- **Method:** GET
- **Description:** List exports (alias)

### /namespaces
- **Method:** GET
- **Description:** List namespaces

### /classes
- **Method:** GET
- **Description:** List classes

### /list_globals
- **Method:** GET
- **Description:** List global variables

### /strings
- **Method:** GET
- **Description:** List strings

### /list_strings
- **Method:** GET
- **Description:** List strings (alias)

### /data
- **Method:** GET
- **Description:** List data items

## Modification

### /renameFunction
- **Method:** POST
- **Description:** Rename function

### /rename_function
- **Method:** POST
- **Description:** Rename function (alias)

### /rename_function_by_address
- **Method:** POST
- **Description:** Rename function by address

### /renameData
- **Method:** POST
- **Description:** Rename data

### /rename_data
- **Method:** POST
- **Description:** Rename data (alias)

### /renameVariable
- **Method:** POST
- **Description:** Rename variable

### /rename_variable
- **Method:** POST
- **Description:** Rename variable (alias)

### /rename_label
- **Method:** POST
- **Description:** Rename label

### /rename_global_variable
- **Method:** POST
- **Description:** Rename global variable

### /create_label
- **Method:** POST
- **Description:** Create new label

### /set_decompiler_comment
- **Method:** POST
- **Description:** Set decompiler comment

### /set_disassembly_comment
- **Method:** POST
- **Description:** Set disassembly comment

### /set_function_prototype
- **Method:** POST
- **Description:** Set function prototype

### /set_local_variable_type
- **Method:** POST
- **Description:** Set local variable type

## Utilities

### /convert_number
- **Method:** GET
- **Description:** Convert number formats

