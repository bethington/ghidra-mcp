# Ghidra MCP Tools Reference

Complete documentation of all 111 MCP tools available in the Ghidra MCP Server. For version history, see [CHANGELOG.md](../CHANGELOG.md).

## Quick Navigation

- **System Tools**: Connection, metadata, versioning (6 tools)
- **Function Analysis**: Decompile, analyze, rename functions (20 tools)
- **Data Structures**: Create/apply structures, types, enums (18 tools)
- **Symbol Management**: Labels, globals, imports/exports (16 tools)
- **Cross-references**: Find callers, callees, xrefs (10 tools)
- **String & Memory**: Strings, IOCs, memory inspection (8 tools)
- **Advanced Analysis**: Call graphs, patterns, batch operations (15 tools)
- **Script Management**: Generate, save, run Ghidra scripts (6 tools)
- **Documentation**: Comments, labels, documentation (6 tools)
- **Data Items**: Lists data, sorts by xrefs, detection (4 tools)

---

## System & Connection Tools

### check_connection()
Verify MCP server connectivity and Ghidra availability.

```python
response = check_connection()
# Returns: {"status": "connected", "message": "..."}
```

**Use when**: Starting analysis, verifying server health

---

### get_version()
Get version information about plugin and Ghidra.

```python
info = get_version()
# Returns: {"plugin_version": "X.Y.Z", "ghidra_version": "11.4.2", ...}
```

**Use when**: Checking compatibility, troubleshooting

---

### get_metadata()
Get program metadata (name, architecture, base address, etc.).

```python
meta = get_metadata()
# Returns: {"name": "sample.exe", "architecture": "x86-32", "base_address": "0x400000"}
```

**Use when**: Starting binary analysis, documenting program info

---

### get_entry_points()
Get all entry points in the program.

```python
entries = get_entry_points()
# Returns: [{"name": "entry_point_0", "address": "0x401000"}, ...]
```

**Use when**: Finding program start points, understanding execution flow

---

### get_current_selection()
Get current cursor position and function context.

```python
selection = get_current_selection()
# Returns: {"address": "0x401000", "function": {"name": "main", "address": "0x401000"}}
```

**Use when**: Working with user-selected addresses

---

### list_segments()
List all memory segments in the program.

```python
segments = list_segments(limit=100)
# Returns: [{"name": ".text", "address": "0x401000", "size": "0x1000"}, ...]
```

**Use when**: Understanding memory layout, analyzing segment properties

---

## Function Analysis Tools

### list_functions()
List all functions in the program.

```python
functions = list_functions(offset=0, limit=100)
# Returns: [{"name": "main", "address": "0x401000"}, ...]
```

**Use when**: Discovering functions, getting overview of binary

---

### search_functions_by_name()
Search for functions matching a name pattern.

```python
results = search_functions_by_name(query="main", limit=50)
# Returns: [{"name": "main", "address": "0x401000"}, ...]
```

**Use when**: Finding specific functions

---

### search_functions_enhanced()
Advanced function search with filtering and sorting.

```python
results = search_functions_enhanced(
    name_pattern="FUN_",
    min_xrefs=2,
    sort_by="xref_count",
    limit=50
)
# Returns: [{"name": "FUN_401000", "address": "...", "xref_count": 5}, ...]
```

**Use when**: Finding important functions, analyzing patterns

---

### get_function_by_address()
Get function information by address.

```python
func = get_function_by_address(address="0x401000")
# Returns: {"name": "main", "address": "0x401000", "signature": "..."}
```

**Use when**: Analyzing code at specific address

---

### decompile_function()
Get decompiled pseudocode for a function.

```python
code = decompile_function(name="main", force=False)
# Returns: "void main(int argc, char *argv[]) { ... }"
```

**Parameters**:
- `name`: Function name (required if address not provided)
- `address`: Function address as hex string (alternative to name)
- `force`: Force fresh decompilation, clearing cache

**Use when**: Reading function logic, understanding code

---

### disassemble_function()
Get assembly instructions for a function.

```python
asm = disassemble_function(address="0x401000")
# Returns: [{"address": "0x401000", "instruction": "PUSH EBP", "comment": "..."}, ...]
```

**Use when**: Low-level analysis, identifying patterns

---

### rename_function()
Rename a function.

```python
result = rename_function(old_name="FUN_401000", new_name="InitializeApp")
# Returns: {"success": true, "old_name": "FUN_401000", "new_name": "InitializeApp"}
```

**Use when**: Improving readability, documenting important functions

---

### rename_function_by_address()
Rename a function by its address.

```python
result = rename_function_by_address(function_address="0x401000", new_name="main")
```

**Use when**: Address is known instead of name

---

### get_function_variables()
List all variables in a function.

```python
vars = get_function_variables(function_name="main")
# Returns: [{"name": "argc", "type": "int", "storage": "stack[-0x8]"}, ...]
```

**Use when**: Understanding function parameters and locals

---

### rename_variable()
Rename a local variable in a function.

```python
result = rename_variable(
    function_name="main",
    old_name="param_1",
    new_name="user_input"
)
```

**Use when**: Improving code clarity

---

### set_local_variable_type()
Set the type of a local variable.

```python
result = set_local_variable_type(
    function_address="0x401000",
    variable_name="param_1",
    new_type="int"
)
```

**Use when**: Correcting auto-detected types

---

### set_variable_storage()
Override variable storage location.

```python
result = set_variable_storage(
    function_address="0x401000",
    variable_name="unaff_EBP",
    storage="Stack[-0x4]:4"
)
```

**Use when**: Fixing register reuse issues

---

### set_function_prototype()
Set function signature and calling convention.

```python
result = set_function_prototype(
    function_address="0x401000",
    prototype="int main(int argc, char* argv[])",
    calling_convention="__cdecl"
)
```

**Use when**: Correcting function signatures

---

### get_function_xrefs()
Get all functions that call the specified function.

```python
callers = get_function_xrefs(name="main", limit=50)
# Returns: [{"from": "entry_point_0", ...}, ...]
```

**Use when**: Understanding function usage

---

### get_function_callees()
Get all functions called by the specified function.

```python
callees = get_function_callees(name="main", limit=50)
# Returns: [{"name": "printf", "address": "..."}, ...]
```

**Use when**: Understanding function dependencies

---

### get_function_call_graph()
Get localized call graph around a function.

```python
graph = get_function_call_graph(name="main", depth=2, direction="both")
# Returns: ["main -> printf", "entry_point_0 -> main", ...]
```

**Use when**: Visualizing call relationships

---

### get_function_jump_target_addresses()
Get all jump target addresses in a function.

```python
targets = get_function_jump_target_addresses(name="main", limit=100)
# Returns: ["0x401010", "0x401020", ...]
```

**Use when**: Understanding control flow

---

### batch_decompile_functions()
Decompile multiple functions in one call.

```python
results = batch_decompile_functions(["main", "printf", "malloc"])
# Returns: {"main": "void main() { ... }", "printf": "...", ...}
```

**Use when**: Analyzing many functions, 93% API call reduction vs individual calls

---

### batch_decompile_xref_sources()
Decompile all functions that reference a specific address.

```python
results = batch_decompile_xref_sources(
    target_address="0x6fb835b8",
    limit=10,
    offset=0
)
# Returns paginated decompilations with usage context
```

**Use when**: Understanding how globals/tables are used

---

## Data Structure Tools

### create_struct()
Create a new structure type.

```python
result = create_struct(
    name="PlayerCharacter",
    fields=[
        {"name": "name", "type": "char[32]"},
        {"name": "level", "type": "int"},
        {"name": "health", "type": "short"}
    ]
)
# Returns: {"success": true, "name": "PlayerCharacter", "size": 40}
```

**Use when**: Documenting data structures

---

### add_struct_field()
Add a field to an existing structure.

```python
result = add_struct_field(
    struct_name="PlayerCharacter",
    field_name="mana",
    field_type="short"
)
```

**Use when**: Extending structures

---

### apply_data_type()
Apply a data type to a memory address.

```python
result = apply_data_type(
    address="0x401000",
    type_name="PlayerCharacter"
)
```

**Use when**: Annotating memory with structures

---

### create_and_apply_data_type()
Create and apply data type in single atomic operation.

```python
result = create_and_apply_data_type(
    address="0x401000",
    classification="STRUCTURE",
    name="MyData",
    type_definition={
        "name": "DataStruct",
        "fields": [{"name": "field1", "type": "int"}]
    }
)
```

**Use when**: Bulk structure creation

---

### create_array_type()
Create an array data type.

```python
result = create_array_type(
    base_type="dword",
    length=64,
    name="MyArray"
)
# Returns: {"name": "MyArray", "size": 256}
```

**Use when**: Creating array types

---

### create_enum()
Create an enumeration type.

```python
result = create_enum(
    name="GameState",
    values={
        "IDLE": 0,
        "RUNNING": 1,
        "PAUSED": 2
    },
    size=4
)
```

**Use when**: Documenting enumerated values

---

### get_enum_values()
Get all values in an enumeration.

```python
values = get_enum_values(enum_name="GameState")
# Returns: [{"name": "IDLE", "value": 0}, ...]
```

---

### list_data_types()
List all data types in the program.

```python
types = list_data_types(category="struct", limit=100)
# Returns: [{"name": "PlayerCharacter", "category": "struct", "size": 40}, ...]
```

**Use when**: Discovering defined structures

---

### delete_data_type()
Delete a data type definition.

```python
result = delete_data_type(type_name="MyStruct")
```

**Use when**: Cleaning up analysis

---

### detect_array_bounds()
Automatically detect array size and element boundaries.

```python
analysis = detect_array_bounds(
    address="0x401000",
    analyze_loop_bounds=True
)
# Returns: {"probable_element_size": 12, "probable_element_count": 4, ...}
```

**Use when**: Discovering array structure

---

### inspect_memory_content()
Read and analyze raw memory bytes.

```python
memory = inspect_memory_content(
    address="0x401000",
    length=64,
    detect_strings=True
)
# Returns: {"hex_dump": "4A 75 6C 79...", "ascii_repr": "July...", ...}
```

**Use when**: Understanding memory layout

---

### export_data_types()
Export all data types in various formats.

```python
types = export_data_types(format="c", category="struct")
# Returns C header definitions
```

**Use when**: Generating header files

---

## Symbol Management Tools

### list_data_items()
List all defined data items in program.

```python
items = list_data_items(limit=100)
# Returns: [{"name": "data_401000", "address": "0x401000", "type": "int"}, ...]
```

**Use when**: Discovering global data

---

### list_data_items_by_xrefs()
List data items sorted by cross-reference count.

```python
items = list_data_items_by_xrefs(limit=50, format="json")
# Returns: Most-used data items first
```

**Use when**: Finding important globals

---

### rename_data()
Rename a data label.

```python
result = rename_data(address="0x401000", new_name="PlayerCount")
```

**Use when**: Documenting global variables

---

### rename_or_label()
Intelligently rename or create label at address.

```python
result = rename_or_label(address="0x401000", name="InitialValue")
# Auto-detects whether to rename or create label
```

**Use when**: Unsure if address has label

---

### create_label()
Create a label at an address.

```python
result = create_label(address="0x401010", name="loop_start")
```

**Use when**: Marking important locations

---

### rename_label()
Rename an existing label.

```python
result = rename_label(
    address="0x401010",
    old_name="loc_401010",
    new_name="loop_start"
)
```

**Use when**: Clarifying code flow

---

### batch_create_labels()
Create multiple labels atomically.

```python
result = batch_create_labels([
    {"address": "0x401010", "name": "loop_start"},
    {"address": "0x401020", "name": "loop_check"},
    {"address": "0x401030", "name": "loop_end"}
])
# Returns: {"labels_created": 3, "labels_failed": 0}
```

**Use when**: Annotating many addresses

---

### list_globals()
List all global variables.

```python
globals = list_globals(filter="player", limit=50)
# Returns: [{"name": "player_count", "address": "0x401000", "type": "int"}, ...]
```

**Use when**: Finding specific globals

---

### rename_global_variable()
Rename a global variable.

```python
result = rename_global_variable(old_name="g_01234", new_name="PlayerTable")
```

**Use when**: Improving readability

---

### list_imports()
List imported functions and symbols.

```python
imports = list_imports(limit=100)
# Returns: [{"name": "printf", "dll": "libc", ...}, ...]
```

**Use when**: Understanding external dependencies

---

### list_exports()
List exported functions and symbols.

```python
exports = list_exports(limit=100)
# Returns: [{"name": "GetVersion", "address": "0x401000"}, ...]
```

**Use when**: Documenting public API

---

### list_external_locations()
List all external locations (imports, ordinals).

```python
externals = list_external_locations(limit=100)
# Returns: [{"label": "Ordinal_100", "dll": "game.dll", "address": "0x402000"}, ...]
```

**Use when**: Working with ordinal imports

---

### get_external_location()
Get details of specific external location.

```python
location = get_external_location(address="0x402000", dll_name="game.dll")
# Returns: {"label": "sgptDataTables", "dll": "game.dll", ...}
```

**Use when**: Researching specific import

---

### rename_external_location()
Rename an external location (e.g., Ordinal_X to real name).

```python
result = rename_external_location(
    address="0x402000",
    new_name="sgptDataTables"
)
```

**Use when**: Fixing broken ordinal imports

---

## Cross-Reference Tools

### get_xrefs_to()
Get all references to an address.

```python
xrefs = get_xrefs_to(address="0x401000", limit=50)
# Returns: [{"from": "0x401010", "type": "DATA"}, ...]
```

**Use when**: Finding who uses this data/function

---

### get_xrefs_from()
Get all references from an address.

```python
xrefs = get_xrefs_from(address="0x401000", limit=50)
# Returns: [{"to": "0x402000", "type": "CALL"}, ...]
```

**Use when**: Finding what this code references

---

### get_bulk_xrefs()
Get cross-references for multiple addresses at once.

```python
xrefs = get_bulk_xrefs(addresses="0x401000,0x401010,0x401020")
# Returns: {"0x401000": [...], "0x401010": [...], ...}
```

**Use when**: Analyzing byte-by-byte patterns

---

### get_assembly_context()
Get assembly context around xref addresses.

```python
context = get_assembly_context(
    xref_sources="0x401010,0x401020",
    context_instructions=5
)
# Returns assembly with context before/after
```

**Use when**: Understanding instruction patterns

---

### get_field_access_context()
Get usage context for structure fields.

```python
context = get_field_access_context(
    struct_address="0x401000",
    field_offset=4,
    num_examples=5
)
# Returns where this field is accessed
```

**Use when**: Understanding field purpose

---

### get_function_labels()
Get all labels in a function.

```python
labels = get_function_labels(name="main", limit=20)
# Returns: [{"address": "0x401010", "name": "loop_start"}, ...]
```

**Use when**: Understanding control flow

---

## String & IOC Tools

### list_strings()
List all strings in the binary.

```python
strings = list_strings(limit=100, offset=0, filter="error")
# Returns: [{"address": "0x401000", "value": "error message"}, ...]
```

**Use when**: Discovering messages and hardcoded strings

---

### extract_iocs()
Extract Indicators of Compromise (IPs, URLs, paths).

```python
iocs = extract_iocs()
# Returns: {
#   "ips": ["192.168.1.1"],
#   "urls": ["http://example.com"],
#   "file_paths": ["C:\\Windows\\..."],
#   "registry_keys": ["HKEY_LOCAL_MACHINE\\..."]
# }
```

**Use when**: Malware analysis, finding external connections

---

### search_byte_patterns()
Search for byte patterns with wildcards.

```python
addresses = search_byte_patterns(pattern="E8 ?? ?? ?? ??")
# Returns: ["0x401000", "0x401010", ...]  # All CALL instructions
```

**Patterns**: Use `??` for wildcards (e.g., `558BEC` for prologue)

**Use when**: Finding specific code sequences

---

## Script Management Tools

### generate_ghidra_script()
Generate optimized Ghidra scripts for batch processing.

```python
script = generate_ghidra_script(
    script_purpose="Document all functions in binary",
    workflow_type="document_functions"
)
# Returns: {"success": true, "script_content": "...", "script_name": "..."}
```

**Use when**: Automating bulk operations (10x faster than MCP)

---

### save_ghidra_script()
Save generated script to disk.

```python
result = save_ghidra_script(
    script_name="DocumentFunctions",
    script_content=script["script_content"]
)
# Returns: {"script_path": "ghidra_scripts/DocumentFunctions.java", ...}
```

**Use when**: Storing scripts for later execution

---

### list_ghidra_scripts()
List all available Ghidra scripts.

```python
scripts = list_ghidra_scripts(filter_pattern="Document.*")
# Returns: [{"name": "DocumentFunctions", "path": "...", "size": 2048}, ...]
```

**Use when**: Discovering available scripts

---

### get_ghidra_script()
Get content of a Ghidra script.

```python
content = get_ghidra_script(script_name="DocumentFunctions")
# Returns: "public class DocumentFunctions extends GhidraScript { ... }"
```

**Use when**: Reviewing script before running

---

### run_ghidra_script()
Execute a Ghidra script with output capture.

```python
result = run_ghidra_script(
    script_name="DocumentFunctions",
    timeout_seconds=300
)
# Returns: {"success": true, "console_output": "...", "errors": [...]}
```

**Use when**: Running batch automation

---

### update_ghidra_script()
Update existing Ghidra script with new content.

```python
result = update_ghidra_script(
    script_name="DocumentFunctions",
    new_content=improved_content
)
```

**Use when**: Fixing or improving scripts

---

## Documentation Tools

### set_decompiler_comment()
Add comment to decompiled pseudocode.

```python
result = set_decompiler_comment(
    address="0x401010",
    comment="Loop processes input buffer"
)
```

**Use when**: Annotating code

---

### set_disassembly_comment()
Add comment to assembly instruction.

```python
result = set_disassembly_comment(
    address="0x401010",
    comment="Stack frame setup"
)
```

**Use when**: Documenting assembly

---

### set_plate_comment()
Add function header comment.

```python
result = set_plate_comment(
    function_address="0x401000",
    comment="Initializes game engine and loads assets"
)
```

**Use when**: Documenting function purpose

---

### batch_set_comments()
Set multiple comments atomically.

```python
result = batch_set_comments(
    function_address="0x401000",
    plate_comment="Initializes engine",
    decompiler_comments=[
        {"address": "0x401010", "comment": "Allocate memory"},
        {"address": "0x401020", "comment": "Load configuration"}
    ]
)
```

**Use when**: Bulk annotation

---

## Advanced Analysis Tools

### get_full_call_graph()
Get complete call graph for entire program.

```python
graph = get_full_call_graph(format="edges", limit=500)
# Returns: ["main -> printf", "main -> malloc", ...]
```

**Formats**: "edges", "adjacency", "dot", "mermaid"

**Use when**: Visualizing program structure

---

### list_calling_conventions()
List available calling conventions.

```python
conventions = list_calling_conventions()
# Returns: ["__cdecl", "__stdcall", "__fastcall", "__thiscall", ...]
```

**Use when**: Setting function signatures

---

### list_classes()
List all namespaces/classes.

```python
classes = list_classes(limit=100)
# Returns: [{"name": "Player", "methods": 5}, ...]
```

**Use when**: Understanding OOP structure

---

### list_namespaces()
List all namespaces.

```python
namespaces = list_namespaces(limit=100)
```

**Use when**: C++ namespace analysis

---

### batch_rename_functions()
Rename multiple functions atomically.

```python
result = batch_rename_functions({
    "FUN_401000": "Initialize",
    "FUN_401010": "ProcessInput",
    "FUN_401020": "Cleanup"
})
```

**Use when**: Bulk renaming

---

### batch_rename_function_components()
Rename function signature and variables in one call.

```python
result = batch_rename_function_components(
    function_address="0x401000",
    function_name="new_main",
    parameter_renames={"param_1": "argc"},
    local_renames={"var_1": "buffer"}
)
```

**Use when**: Comprehensive function documentation

---

### batch_create_labels()
See Symbol Management section

---

### document_function_complete()
Complete function documentation in single atomic operation.

```python
result = document_function_complete(
    function_address="0x401000",
    new_name="main",
    prototype="int main(int argc, char* argv[])",
    variable_renames={"param_1": "argc"},
    labels=[{"address": "0x401010", "name": "loop"}],
    plate_comment="Program entry point"
)
```

**Use when**: Full function documentation

---

### disassemble_bytes()
Disassemble undefined bytes at address.

```python
result = disassemble_bytes(
    start_address="0x401000",
    length=21
)
# Returns: {"success": true, "bytes_disassembled": 21}
```

**Use when**: Converting data back to code

---

## Performance Notes

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| decompile_function | 0.5-2s | Larger functions take longer |
| list_functions | <100ms | Cached after first call |
| batch_decompile_functions(10) | 2-5s | 93% API call reduction |
| get_xrefs_to | 100-500ms | Depends on xref count |
| get_full_call_graph | 1-5s | Large programs take longer |
| rename_function | 50-100ms | Usually fast |
| create_struct | 50-100ms | Usually fast |

---

## Error Handling

All tools may return errors. Common patterns:

```python
try:
    result = decompile_function(name="main")
except requests.exceptions.Timeout:
    print("Operation timed out")
except requests.exceptions.ConnectionError:
    print("MCP server not responding")
```

See `docs/ERROR_CODES.md` for comprehensive error guide.

---

## Examples

See `examples/` directory for working code:
- `analyze-functions.py` - Complete analysis workflow
- `create-struct-workflow.py` - Data structure discovery
- `batch-rename.py` - Function renaming automation
- `extract-strings.py` - String and IOC extraction
- `document-binary.py` - Comprehensive binary documentation

---

## Tool Categories by Use Case

### "I want to understand the binary"
1. get_metadata()
2. list_functions()
3. search_functions_enhanced()
4. decompile_function()
5. list_strings()

### "I want to document it"
1. rename_function()
2. set_decompiler_comment()
3. set_plate_comment()
4. document_function_complete()
5. export_data_types()

### "I want to find bugs/malware"
1. extract_iocs()
2. search_byte_patterns()
3. get_xrefs_to()
4. list_strings()
5. get_full_call_graph()

### "I want to automate analysis"
1. generate_ghidra_script()
2. batch_decompile_functions()
3. batch_create_labels()
4. batch_rename_functions()
5. run_ghidra_script()

---

See `README.md` for installation and quick start.
