# Ghidra MCP Tools Reference

Complete reference of all 108 Ghidra MCP tools organized by operation type.

**Version:** 1.8.0
**Generated:** 2025-01-18

---

## Table of Contents

- [Read-Only Tools](#read-only-tools)
  - [Function Analysis](#function-analysis)
  - [Data Analysis](#data-analysis)
  - [Symbol & Label Operations](#symbol--label-operations)
  - [Cross-References](#cross-references)
  - [Data Types](#data-types)
  - [Program Metadata](#program-metadata)
  - [Search & Discovery](#search--discovery)
  - [Call Graph Analysis](#call-graph-analysis)
  - [Malware Analysis](#malware-analysis)
- [Write Tools](#write-tools)
  - [Function Modifications](#function-modifications)
  - [Data Modifications](#data-modifications)
  - [Symbol & Label Creation](#symbol--label-creation)
  - [Data Type Management](#data-type-management)
  - [Comments & Documentation](#comments--documentation)
  - [Batch Operations](#batch-operations)
  - [Advanced Analysis Control](#advanced-analysis-control)
  - [Script Execution](#script-execution)
- [Tool Statistics](#tool-statistics)

---

## Read-Only Tools

### Function Analysis

#### `list_functions`
List all function names in the program with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of function names with pagination info

#### `get_function_by_address`
Get a function by its address.
- **Args:** `address` (hex format, e.g., "0x1400010a0")
- **Returns:** Function information including name, signature, and address range

#### `get_current_function`
Get the function currently selected by the user.
- **Args:** None
- **Returns:** Information about the currently selected function

#### `decompile_function`
Decompile a specific function by name and return the decompiled C code.
- **Args:** `name` (function name)
- **Returns:** Decompiled C code as a string

#### `batch_decompile_functions`
Decompile multiple functions in a single request (max 20 functions).
- **Args:** `function_names` (list of function names)
- **Returns:** Dictionary mapping function names to decompiled code
- **Version:** v1.7.1

#### `disassemble_function`
Get assembly code (address: instruction; comment) for a function.
- **Args:** `address` (hex format)
- **Returns:** List of assembly instructions with addresses and comments

#### `get_function_labels`
Get all labels within the specified function by name.
- **Args:** `name` (function name), `offset` (default: 0), `limit` (default: 20)
- **Returns:** List of labels found within the function

#### `get_function_variables`
List all variables in a function including parameters and locals.
- **Args:** `function_name` (function name)
- **Returns:** JSON with function variables including names, types, and storage locations
- **Version:** v1.5.0

#### `analyze_function_completeness`
Analyze how completely a function has been documented.
- **Args:** `function_address` (hex format)
- **Returns:** JSON with completeness analysis including custom name status, prototype, comments, undefined variables, and completeness score (0-100)
- **Version:** v1.5.0

#### `analyze_function_complexity`
Calculate various complexity metrics for a function.
- **Args:** `function_name` (function name)
- **Returns:** Dictionary with complexity metrics including cyclomatic complexity, lines of code, branch count

#### `analyze_function_complete`
Comprehensive function analysis in a single call - replaces 5+ individual calls.
- **Args:** `name`, `include_xrefs`, `include_callees`, `include_callers`, `include_disasm`, `include_variables`
- **Returns:** JSON with complete function analysis
- **Version:** v1.6.0

#### `find_dead_code`
Identify potentially unreachable code blocks within a function.
- **Args:** `function_name` (function name)
- **Returns:** List of potentially unreachable code blocks with addresses

### Data Analysis

#### `list_data_items`
List defined data labels and their values with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of data labels with addresses, names, and values

#### `list_data_items_by_xrefs`
List defined data items sorted by cross-reference count (most referenced first).
- **Args:** `offset` (default: 0), `limit` (default: 100), `format` ("text" or "json", default: "json")
- **Returns:** Sorted list of data items with xref counts
- **Version:** v1.7.4

#### `get_current_address`
Get the address currently selected by the user.
- **Args:** None
- **Returns:** Current cursor/selection address in hex format

#### `analyze_data_region`
Comprehensive single-call analysis of a data region.
- **Args:** `address`, `max_scan_bytes` (default: 1024), `include_xref_map`, `include_assembly_patterns`, `include_boundary_detection`
- **Returns:** JSON with boundary detection, byte-by-byte xref mapping, stride detection, classification hints
- **Version:** v1.7.3

#### `inspect_memory_content`
Read raw memory bytes and provide hex/ASCII representation with string detection.
- **Args:** `address`, `length` (default: 64), `detect_strings` (default: True)
- **Returns:** JSON with hex dump, ASCII representation, string detection heuristics
- **Version:** v1.7.3

#### `detect_array_bounds`
Automatically detect array/table size and element boundaries from assembly patterns.
- **Args:** `address`, `analyze_loop_bounds` (default: True), `analyze_indexing` (default: True), `max_scan_range` (default: 2048)
- **Returns:** JSON with probable element size/count, confidence, evidence
- **Version:** v1.7.3

#### `analyze_data_types`
Analyze data types at a given address with specified depth.
- **Args:** `address`, `depth` (default: 1)
- **Returns:** Detailed analysis of data types at the specified address

#### `analyze_struct_field_usage`
Analyze how structure fields are accessed in decompiled code.
- **Args:** `address`, `struct_name` (optional), `max_functions` (default: 10)
- **Returns:** JSON with field usage analysis including suggested names and access patterns
- **Version:** v1.7.3

#### `get_field_access_context`
Get assembly/decompilation context for specific field offsets.
- **Args:** `struct_address`, `field_offset`, `num_examples` (default: 5)
- **Returns:** JSON with field access contexts showing usage examples
- **Version:** v1.7.3

#### `suggest_field_names`
AI-assisted field name suggestions based on usage patterns and data types.
- **Args:** `struct_address`, `struct_size` (optional, auto-detected if 0)
- **Returns:** JSON with field name suggestions following naming conventions
- **Version:** v1.7.3

### Symbol & Label Operations

#### `list_classes`
List all namespace/class names in the program with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of namespace/class names with pagination info

#### `list_segments`
List all memory segments in the program with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of memory segments with addresses, names, and properties

#### `list_imports`
List imported symbols in the program with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of imported symbols with names and addresses

#### `list_exports`
List exported functions/symbols with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of exported functions/symbols with names and addresses

#### `list_namespaces`
List all non-global namespaces in the program with pagination.
- **Args:** `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of namespace names and hierarchical paths

#### `list_globals`
List matching globals in the database (paginated, filtered).
- **Args:** `offset` (default: 0), `limit` (default: 100), `filter` (optional)
- **Returns:** List of global variables/symbols with details

#### `list_strings`
List all defined strings in the program with their addresses.
- **Args:** `offset` (default: 0), `limit` (default: 100), `filter` (optional)
- **Returns:** List of strings with addresses

#### `get_entry_points`
Get all entry points in the database.
- **Args:** None
- **Returns:** List of entry points with addresses and names

#### `can_rename_at_address`
Check what kind of symbol exists at an address.
- **Args:** `address` (hex format)
- **Returns:** JSON indicating whether rename_data, create_label, or rename_function should be used
- **Version:** v1.6.0

### Cross-References

#### `get_xrefs_to`
Get all references to the specified address (xref to).
- **Args:** `address`, `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of references to the specified address

#### `get_xrefs_from`
Get all references from the specified address (xref from).
- **Args:** `address`, `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of references from the specified address

#### `get_function_xrefs`
Get all references to the specified function by name.
- **Args:** `name` (function name), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of references to the specified function

#### `get_function_jump_target_addresses`
Get all jump target addresses from a function's disassembly.
- **Args:** `name` (function name), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of jump target addresses from the function

#### `get_bulk_xrefs`
Get cross-references for multiple addresses in a single batch request.
- **Args:** `addresses` (comma-separated hex addresses or JSON array)
- **Returns:** JSON with xref mappings for all requested addresses
- **Version:** v1.7.3

#### `get_assembly_context`
Get assembly instructions with context for multiple xref source addresses.
- **Args:** `xref_sources`, `context_instructions` (default: 5), `include_patterns` (default: "LEA,MOV,CMP,IMUL,ADD,SUB")
- **Returns:** JSON with assembly context around xref instructions
- **Version:** v1.7.3

#### `batch_decompile_xref_sources`
Decompile all functions that reference a target address in one batch operation.
- **Args:** `target_address`, `include_function_names`, `include_usage_context`, `limit` (default: 10), `offset` (default: 0)
- **Returns:** JSON with pagination metadata and decompiled functions
- **Version:** v1.7.3

### Data Types

#### `list_data_types`
List all data types available in the program with optional category filtering.
- **Args:** `category` (optional), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of data types with names, categories, and sizes

#### `get_data_type_size`
Get the size and alignment information for a data type.
- **Args:** `type_name` (data type name)
- **Returns:** Size, alignment, and path information for the data type

#### `get_struct_layout`
Get the detailed layout of a structure including field offsets.
- **Args:** `struct_name` (structure name)
- **Returns:** Detailed structure layout with field offsets, sizes, and types

#### `search_data_types`
Search for data types by name pattern.
- **Args:** `pattern` (search pattern), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of matching data types with details

#### `get_enum_values`
Get all values and names in an enumeration.
- **Args:** `enum_name` (enumeration name)
- **Returns:** List of all enumeration values with names and numeric values

#### `validate_data_type`
Validate if a data type can be properly applied at a given address.
- **Args:** `address`, `type_name`
- **Returns:** Validation results including memory availability, alignment, and conflicts

#### `export_data_types`
Export data types in various formats.
- **Args:** `format` ("c", "json", "summary", default: "c"), `category` (optional)
- **Returns:** Exported data types in the specified format

#### `get_valid_data_types`
Get list of valid Ghidra data type strings.
- **Args:** `category` (optional, not currently used)
- **Returns:** JSON with lists of builtin_types and windows_types
- **Version:** v1.5.0

#### `validate_data_type_exists`
Check if a data type exists in Ghidra's type manager.
- **Args:** `type_name` (data type name)
- **Returns:** JSON with validation results including existence, category, size, and path
- **Version:** v1.6.0

### Program Metadata

#### `check_connection`
Check if the Ghidra plugin is running and accessible.
- **Args:** None
- **Returns:** Connection status message

#### `get_version`
Get version information about the GhidraMCP plugin and Ghidra.
- **Args:** None
- **Returns:** JSON with plugin version, Ghidra version, Java version, endpoint count, implementation status

#### `get_metadata`
Get metadata about the current program/database.
- **Args:** None
- **Returns:** JSON with program name, architecture, base address, entry points, and other metadata

#### `format_number_conversions`
Convert a number (decimal, hexadecimal) to different representations.
- **Args:** `text` (number to convert), `size` (1, 2, 4, or 8 bytes, default: 4)
- **Returns:** String with multiple number representations (decimal, hex, binary, etc.)

### Search & Discovery

#### `search_functions_by_name`
Search for functions whose name contains the given substring.
- **Args:** `query` (search string), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of matching functions with names and addresses

#### `search_functions_enhanced`
Enhanced function search with filtering and sorting.
- **Args:** `name_pattern`, `min_xrefs`, `max_xrefs`, `calling_convention`, `has_custom_name`, `regex`, `sort_by`, `offset`, `limit`
- **Returns:** JSON with search results and filtering options
- **Version:** v1.6.0

#### `find_next_undefined_function`
Find the next function needing analysis.
- **Args:** `start_address`, `criteria` (default: "name_pattern"), `pattern` (default: "FUN_"), `direction` (default: "ascending")
- **Returns:** JSON with found function details or {found: false}
- **Version:** v1.5.0

#### `search_byte_patterns`
Search for byte patterns with optional wildcards (e.g., 'E8 ?? ?? ?? ??').
- **Args:** `pattern` (hex pattern), `mask` (optional, use ? for wildcards)
- **Returns:** List of addresses where the pattern was found
- **Version:** v1.7.1

### Call Graph Analysis

#### `get_function_callees`
Get all functions called by the specified function (callees).
- **Args:** `name` (function name), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of functions called by the specified function

#### `get_function_callers`
Get all functions that call the specified function (callers).
- **Args:** `name` (function name), `offset` (default: 0), `limit` (default: 100)
- **Returns:** List of functions that call the specified function

#### `get_function_call_graph`
Get a call graph subgraph centered on the specified function.
- **Args:** `name`, `depth` (default: 2), `direction` ("callers", "callees", "both")
- **Returns:** List of call graph relationships

#### `get_full_call_graph`
Get the complete call graph for the entire program.
- **Args:** `format` ("edges", "adjacency", "dot", "mermaid"), `limit` (default: 500)
- **Returns:** Complete call graph in the specified format

### Malware Analysis

#### `extract_iocs`
Extract Indicators of Compromise (IOCs) from the binary.
- **Args:** None
- **Returns:** Dictionary of IOCs organized by type (IPs, URLs, file paths, registry keys)
- **Version:** v1.7.1

#### `detect_crypto_constants` [ROADMAP v2.0]
Identify cryptographic constants and algorithms in the binary.
- **Status:** Placeholder - Not yet implemented
- **Planned:** Detection of AES, DES, SHA, MD5, RSA constants

#### `find_similar_functions` [ROADMAP v2.0]
Find functions similar to target using structural analysis.
- **Args:** `target_function`, `threshold` (0.0-1.0, default: 0.8)
- **Status:** Placeholder - Not yet implemented
- **Planned:** Control flow graph comparison, instruction pattern analysis

#### `analyze_control_flow` [ROADMAP v2.0]
Analyze control flow complexity, cyclomatic complexity, and basic blocks.
- **Args:** `function_name`
- **Status:** Placeholder - Not yet implemented
- **Planned:** McCabe metric, loop analysis, complexity scoring

#### `find_anti_analysis_techniques` [ROADMAP v2.0]
Detect anti-analysis, anti-debugging, and evasion techniques.
- **Status:** Placeholder - Not yet implemented
- **Planned:** Detection of debugger checks, VM detection, obfuscation

#### `extract_iocs_with_context` [ROADMAP v2.0]
Enhanced IOC extraction with analysis context and confidence scoring.
- **Status:** Placeholder - Not yet implemented
- **Planned:** Context-aware IOC extraction with confidence scores

#### `detect_malware_behaviors` [ROADMAP v2.0]
Automatically detect common malware behaviors and techniques.
- **Status:** Placeholder - Not yet implemented
- **Planned:** Keylogging, ransomware, rootkit detection with MITRE ATT&CK mapping

#### `auto_decrypt_strings` [ROADMAP v2.0]
Automatically identify and decrypt common string obfuscation patterns.
- **Status:** Placeholder - Not yet implemented
- **Planned:** XOR, Base64, ROT13, stack strings detection

#### `analyze_api_call_chains` [ROADMAP v2.0]
Identify and visualize suspicious Windows API call sequences.
- **Status:** Placeholder - Not yet implemented
- **Planned:** Process injection, persistence, privilege escalation detection

---

## Write Tools

### Function Modifications

#### `rename_function`
Rename a function by its current name to a new user-defined name.
- **Args:** `old_name` (current function name), `new_name` (new function name)
- **Returns:** Success or failure message

#### `rename_function_by_address`
Rename a function by its address.
- **Args:** `function_address` (hex format), `new_name` (new function name)
- **Returns:** Success or failure message

#### `set_function_prototype`
Set a function's prototype and optionally its calling convention.
- **Args:** `function_address`, `prototype`, `calling_convention` (optional: __cdecl, __stdcall, __fastcall, __thiscall)
- **Returns:** Success or failure message

#### `validate_function_prototype`
Validate a function prototype before applying it (without modifying).
- **Args:** `function_address`, `prototype`, `calling_convention` (optional)
- **Returns:** JSON with validation results showing errors, warnings, parsed components
- **Version:** v1.6.0

#### `set_local_variable_type`
Set a local variable's type.
- **Args:** `function_address`, `variable_name`, `new_type`
- **Returns:** Success or failure message

#### `rename_variable`
Rename a local variable within a function.
- **Args:** `function_name`, `old_name` (current variable name), `new_name` (new variable name)
- **Returns:** Success or failure message

#### `set_function_no_return`
Set a function's "No Return" attribute to control flow analysis.
- **Args:** `function_address`, `no_return` (true/false)
- **Returns:** Success message with old and new state
- **Version:** v1.7.0

#### `set_variable_storage`
Set custom storage for a local variable or parameter.
- **Args:** `function_address`, `variable_name`, `storage` (e.g., "Stack[-0x10]:4", "EBP:4", "register:EBP")
- **Returns:** Success message with old and new storage details
- **Version:** v1.7.0

#### `force_decompile`
Force fresh decompilation of a function (clears cache).
- **Args:** `function_address`
- **Returns:** Success message followed by fresh decompiled C code
- **Version:** v1.7.0

#### `clear_instruction_flow_override`
Clear instruction-level flow override at a specific address.
- **Args:** `address` (instruction address)
- **Returns:** Success message showing old and new flow override state
- **Version:** v1.7.1

#### `disassemble_bytes`
Disassemble a range of undefined bytes at a specific address.
- **Args:** `start_address`, `end_address` (optional), `length` (optional), `restrict_to_execute_memory` (default: True)
- **Returns:** JSON with disassembly result
- **Version:** v1.7.1

### Data Modifications

#### `rename_data`
Rename a data label at the specified address (ONLY for defined data).
- **Args:** `address` (hex format), `new_name` (new data label name)
- **Returns:** Success or failure message
- **Note:** Use create_label() for undefined addresses

#### `rename_data_smart`
Intelligently rename data at an address (auto-detects defined vs undefined).
- **Args:** `address`, `new_name`
- **Returns:** Success or failure message with operation details

#### `rename_or_label`
Intelligently rename data or create label (server-side detection).
- **Args:** `address`, `name`
- **Returns:** Success or failure message with operation details

#### `apply_data_type`
Apply a specific data type at the given memory address.
- **Args:** `address`, `type_name`, `clear_existing` (default: True)
- **Returns:** Success or failure message with applied data type details

#### `create_and_apply_data_type`
Apply data type, name, and comment in a single atomic operation.
- **Args:** `address`, `classification` ("PRIMITIVE", "STRUCTURE", "ARRAY"), `name` (optional), `comment` (optional), `type_definition` (JSON string or dict)
- **Returns:** Success message with all operations performed
- **Version:** v1.7.3

#### `rename_global_variable`
Rename a global variable.
- **Args:** `old_name` (current global variable name), `new_name` (new global variable name)
- **Returns:** Success or failure message

### Symbol & Label Creation

#### `create_label`
Create a new label at the specified address.
- **Args:** `address` (hex format), `name` (label name)
- **Returns:** Success or failure message

#### `batch_create_labels`
Create multiple labels in a single atomic operation.
- **Args:** `labels` (list of {"address": "0x...", "name": "..."} objects)
- **Returns:** JSON with success status, counts, and errors
- **Version:** v1.5.1

#### `rename_label`
Rename an existing label at the specified address.
- **Args:** `address`, `old_name`, `new_name`
- **Returns:** Success or failure message

### Data Type Management

#### `create_struct`
Create a new structure data type with specified fields.
- **Args:** `name`, `fields` (list of {"name": "...", "type": "...", "offset": ...})
- **Returns:** Success or failure message with created structure details

#### `create_enum`
Create a new enumeration data type with name-value pairs.
- **Args:** `name`, `values` (dict of name-value pairs), `size` (1, 2, 4, or 8, default: 4)
- **Returns:** Success or failure message with created enumeration details

#### `create_union`
Create a new union data type with specified fields.
- **Args:** `name`, `fields` (list of {"name": "...", "type": "..."})
- **Returns:** Success or failure message with created union details

#### `create_typedef`
Create a typedef (type alias) for an existing data type.
- **Args:** `name` (typedef name), `base_type` (base data type name)
- **Returns:** Success or failure message with typedef creation details

#### `clone_data_type`
Clone/copy an existing data type with a new name.
- **Args:** `source_type`, `new_name`
- **Returns:** Success or failure message with cloning details

#### `create_array_type`
Create an array data type.
- **Args:** `base_type`, `length`, `name` (optional)
- **Returns:** Success or failure message with created array type details

#### `create_pointer_type`
Create a pointer data type.
- **Args:** `base_type`, `name` (optional)
- **Returns:** Success or failure message with created pointer type details

#### `create_data_type_category`
Create a new data type category.
- **Args:** `category_path` (e.g., "MyTypes" or "MyTypes/SubCategory")
- **Returns:** Success or failure message with category creation details

#### `move_data_type_to_category`
Move a data type to a different category.
- **Args:** `type_name`, `category_path`
- **Returns:** Success or failure message with move operation details

#### `create_function_signature`
Create a function signature data type.
- **Args:** `name`, `return_type`, `parameters` (optional JSON string)
- **Returns:** Success or failure message with function signature creation details

#### `delete_data_type`
Delete a data type from the program.
- **Args:** `type_name`
- **Returns:** Success or failure message with details

#### `modify_struct_field`
Modify a field in an existing structure.
- **Args:** `struct_name`, `field_name`, `new_type` (optional), `new_name` (optional)
- **Returns:** Success or failure message with details

#### `add_struct_field`
Add a new field to an existing structure.
- **Args:** `struct_name`, `field_name`, `field_type`, `offset` (default: -1 for end)
- **Returns:** Success or failure message with details

#### `remove_struct_field`
Remove a field from an existing structure.
- **Args:** `struct_name`, `field_name`
- **Returns:** Success or failure message with details

#### `import_data_types` [ROADMAP v2.0]
Import data types from various sources.
- **Args:** `source` (C header/JSON), `format` ("c", "json", default: "c")
- **Status:** Placeholder - Not yet implemented
- **Planned:** Parse C headers, JSON definitions, Ghidra .gdt files

### Comments & Documentation

#### `set_decompiler_comment`
Set a comment for a given address in the function pseudocode (PRE_COMMENT).
- **Args:** `address`, `comment`
- **Returns:** Success or failure message

#### `set_disassembly_comment`
Set a comment for a given address in the function disassembly (EOL_COMMENT).
- **Args:** `address`, `comment`
- **Returns:** Success or failure message

#### `set_plate_comment`
Set function plate (header) comment.
- **Args:** `function_address`, `comment`
- **Returns:** Success or failure message
- **Version:** v1.5.0

#### `batch_set_comments`
Set multiple comments in a single operation.
- **Args:** `function_address`, `decompiler_comments` (optional), `disassembly_comments` (optional), `plate_comment` (optional)
- **Returns:** JSON with success status and counts of comments set
- **Version:** v1.5.0

### Batch Operations

#### `batch_rename_functions`
Rename multiple functions atomically.
- **Args:** `renames` (dict mapping old names to new names)
- **Returns:** Dictionary with rename results and any errors

#### `batch_rename_variables`
Rename multiple variables in a function atomically.
- **Args:** `function_address`, `variable_renames` (dict of old_name: new_name)
- **Returns:** JSON with detailed results including success/failure counts
- **Version:** v1.6.0

#### `batch_set_variable_types`
Set types for multiple variables in a single operation.
- **Args:** `function_address`, `variable_types` (dict of variable_name: type_name)
- **Returns:** JSON with success status and count of variables typed
- **Version:** v1.5.0

#### `batch_rename_function_components`
Rename function and all its components atomically.
- **Args:** `function_address`, `function_name` (optional), `parameter_renames` (optional), `local_renames` (optional), `return_type` (optional)
- **Returns:** JSON with success status and counts of renamed components
- **Version:** v1.5.0

#### `document_function_complete`
Document a function completely in one atomic operation.
- **Args:** `function_address`, `new_name`, `prototype`, `calling_convention`, `variable_renames`, `variable_types`, `labels`, `plate_comment`, `decompiler_comments`, `disassembly_comments`
- **Returns:** JSON with operation results
- **Version:** v1.6.0

### Advanced Analysis Control

#### `run_script`
Run a Ghidra script programmatically (.java or .py).
- **Args:** `script_path` (absolute path), `args` (optional JSON string)
- **Returns:** Script execution result or error message
- **Version:** v1.7.0

#### `list_scripts`
List available Ghidra scripts.
- **Args:** `filter` (optional filter string for script names)
- **Returns:** JSON with array of script information
- **Version:** v1.7.0

---

## Tool Statistics

### By Category

| Category | Read-Only | Write | Total |
|----------|-----------|-------|-------|
| Function Operations | 15 | 12 | 27 |
| Data Operations | 10 | 7 | 17 |
| Symbol & Label Operations | 9 | 4 | 13 |
| Data Type Management | 10 | 17 | 27 |
| Cross-References | 7 | 0 | 7 |
| Comments & Documentation | 0 | 5 | 5 |
| Call Graph Analysis | 4 | 0 | 4 |
| Search & Discovery | 4 | 0 | 4 |
| Program Metadata | 4 | 0 | 4 |
| Malware Analysis | 9 | 0 | 9 |
| Batch Operations | 0 | 7 | 7 |
| Advanced Analysis | 0 | 2 | 2 |

### Implementation Status

- **Implemented:** 98 tools (90.7%)
- **ROADMAP v2.0:** 10 tools (9.3%)
  - Malware Analysis: 8 tools
  - Data Type Management: 1 tool (import_data_types)
  - Search & Discovery: 1 tool (find_similar_functions)

### Total Tools: 108

---

## Quick Reference

### Most Common Operations

**Read Functions:**
```python
list_functions(offset=0, limit=100)
decompile_function("FunctionName")
get_function_by_address("0x401000")
```

**Write Functions:**
```python
rename_function("FUN_401000", "MyFunction")
set_function_prototype("0x401000", "int main(int argc, char* argv[])")
set_decompiler_comment("0x401000", "This is the entry point")
```

**Batch Operations:**
```python
batch_decompile_functions(["func1", "func2", "func3"])
batch_rename_variables("0x401000", {"param_1": "argc", "param_2": "argv"})
document_function_complete("0x401000", new_name="main", prototype="int main(int argc, char* argv[])")
```

**Data Analysis:**
```python
analyze_data_region("0x404000")
inspect_memory_content("0x404000", length=64)
detect_array_bounds("0x404000")
```

---

**Generated by:** Ghidra MCP Server v1.8.0
**Project:** https://github.com/xebyte/ghidra-mcp
**Documentation:** See docs/API_REFERENCE.md for detailed endpoint documentation
