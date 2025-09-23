# Data Type Analysis and Management Tools

This document describes the comprehensive data type analysis and management tools that have been added to the Ghidra MCP plugin. These tools provide advanced capabilities for working with data types in reverse engineering workflows.

## Overview

The Ghidra MCP plugin now includes 12 specialized data type tools that enable:
- Deep analysis of data structures in memory
- Creation and management of custom data types
- Validation and optimization of data type assignments
- Export/import capabilities for data type definitions
- Automated structure inference from memory patterns

## Available Tools

### 1. analyze_data_types
**Purpose**: Analyze data types at a given address with specified recursion depth

**MCP Tool**: `mcp_ghidra_analyze_data_types(address: str, depth: int = 1)`

**Parameters**:
- `address`: Target address in hex format (e.g., "0x1400010a0")
- `depth`: Analysis depth for following pointers and references (default: 1)

**Returns**: Detailed analysis of data types including composite structures and pointer chains

**Use Cases**:
- Understanding complex data structures
- Following pointer relationships
- Analyzing nested structures and unions

### 2. create_union
**Purpose**: Create a new union data type with specified fields

**MCP Tool**: `mcp_ghidra_create_union(name: str, fields: list)`

**Parameters**:
- `name`: Name for the new union
- `fields`: List of field definitions with name and type

**Example**:
```python
fields = [
    {"name": "as_int", "type": "int"},
    {"name": "as_float", "type": "float"},
    {"name": "as_bytes", "type": "char[4]"}
]
```

**Returns**: Success/failure message with created union details

### 3. get_type_size
**Purpose**: Get size and alignment information for a data type

**MCP Tool**: `mcp_ghidra_get_type_size(type_name: str)`

**Parameters**:
- `type_name`: Name of the data type to query

**Returns**: Size, alignment, and path information for the data type

**Use Cases**:
- Verifying data type properties
- Planning memory layout optimizations
- Understanding platform-specific type sizes

### 4. get_struct_layout
**Purpose**: Get detailed layout of a structure including field offsets

**MCP Tool**: `mcp_ghidra_get_struct_layout(struct_name: str)`

**Parameters**:
- `struct_name`: Name of the structure to analyze

**Returns**: Detailed structure layout with field offsets, sizes, and types

**Use Cases**:
- Understanding structure padding
- Optimizing memory usage
- Analyzing compiler-generated layouts

### 5. search_data_types
**Purpose**: Search for data types by name pattern

**MCP Tool**: `mcp_ghidra_search_data_types(pattern: str, offset: int = 0, limit: int = 100)`

**Parameters**:
- `pattern`: Search pattern to match against data type names
- `offset`: Pagination offset (default: 0)
- `limit`: Maximum number of results (default: 100)

**Returns**: List of matching data types with their details

**Use Cases**:
- Finding related data types
- Discovering existing type definitions
- Building type inventories

### 6. auto_create_struct
**Purpose**: Automatically create a structure by analyzing memory layout

**MCP Tool**: `mcp_ghidra_auto_create_struct(address: str, size: int, name: str)`

**Parameters**:
- `address`: Target address in hex format
- `size`: Size in bytes to analyze (0 for automatic detection)
- `name`: Name for the new structure

**Returns**: Success/failure message with created structure details

**Use Cases**:
- Rapid prototyping of unknown structures
- Initial structure discovery
- Automated reverse engineering workflows

### 7. get_enum_values
**Purpose**: Get all values and names in an enumeration

**MCP Tool**: `mcp_ghidra_get_enum_values(enum_name: str)`

**Parameters**:
- `enum_name`: Name of the enumeration to query

**Returns**: List of all enumeration values with names and numeric values

**Use Cases**:
- Understanding enumeration constants
- Documenting API constants
- Analyzing state machines

### 8. create_typedef
**Purpose**: Create a typedef (type alias) for an existing data type

**MCP Tool**: `mcp_ghidra_create_typedef(name: str, base_type: str)`

**Parameters**:
- `name`: Name for the new typedef
- `base_type`: Name of the base data type to alias

**Returns**: Success/failure message with typedef creation details

**Use Cases**:
- Creating semantic type names
- Improving code readability
- Standardizing type usage

### 9. clone_data_type
**Purpose**: Clone/copy an existing data type with a new name

**MCP Tool**: `mcp_ghidra_clone_data_type(source_type: str, new_name: str)`

**Parameters**:
- `source_type`: Name of the source data type to clone
- `new_name`: Name for the cloned data type

**Returns**: Success/failure message with cloning details

**Use Cases**:
- Creating type variations
- Building type libraries
- Preserving original definitions while experimenting

### 10. validate_data_type
**Purpose**: Validate if a data type can be properly applied at a given address

**MCP Tool**: `mcp_ghidra_validate_data_type(address: str, type_name: str)`

**Parameters**:
- `address`: Target address in hex format
- `type_name`: Name of the data type to validate

**Returns**: Validation results including memory availability, alignment, and conflicts

**Use Cases**:
- Preventing invalid type assignments
- Checking memory constraints
- Ensuring proper alignment

### 11. export_data_types
**Purpose**: Export data types in various formats

**MCP Tool**: `mcp_ghidra_export_data_types(format: str = "c", category: str = None)`

**Parameters**:
- `format`: Export format ("c", "json", "summary") - default: "c"
- `category`: Optional category filter for data types

**Supported Formats**:
- **C**: Standard C structure/enum declarations
- **JSON**: Structured data for programmatic processing
- **Summary**: Human-readable overview

**Returns**: Exported data types in the specified format

**Use Cases**:
- Documentation generation
- Code generation
- Cross-tool compatibility

### 12. import_data_types
**Purpose**: Import data types from various sources (placeholder for future enhancement)

**MCP Tool**: `mcp_ghidra_import_data_types(source: str, format: str = "c")`

**Parameters**:
- `source`: Source data containing type definitions
- `format`: Format of the source data ("c", "json")

**Returns**: Import results and status

**Note**: Currently a placeholder for future implementation

## Integration Examples

### Basic Analysis Workflow
```python
# 1. Search for interesting data types
types = mcp_ghidra_search_data_types("Window")

# 2. Get detailed layout of a structure
layout = mcp_ghidra_get_struct_layout("WindowStruct")

# 3. Analyze data at a specific address
analysis = mcp_ghidra_analyze_data_types("0x140001000", depth=3)

# 4. Validate before applying a type
validation = mcp_ghidra_validate_data_type("0x140001000", "WindowStruct")
```

### Custom Type Creation
```python
# 1. Create a union for different interpretations
union_fields = [
    {"name": "raw_bytes", "type": "byte[8]"},
    {"name": "as_double", "type": "double"},
    {"name": "as_long", "type": "long"}
]
mcp_ghidra_create_union("DataUnion", union_fields)

# 2. Create a typedef for semantic clarity
mcp_ghidra_create_typedef("ProcessID", "int")

# 3. Auto-generate structure from memory
mcp_ghidra_auto_create_struct("0x140001000", 64, "InferredStruct")
```

### Documentation and Export
```python
# Export all structures as C code
c_code = mcp_ghidra_export_data_types("c", "struct")

# Export specific category as JSON
json_data = mcp_ghidra_export_data_types("json", "enum")

# Get summary of all types
summary = mcp_ghidra_export_data_types("summary")
```

## Implementation Details

### Java Plugin Extensions
The data type tools are implemented as HTTP endpoints in the GhidraMCPPlugin class:
- `/analyze_data_types` - Deep data type analysis
- `/create_union` - Union creation with field validation
- `/get_type_size` - Type size and alignment queries
- `/get_struct_layout` - Structure layout analysis
- `/search_data_types` - Pattern-based type search
- `/auto_create_struct` - Automated structure inference
- `/get_enum_values` - Enumeration value extraction
- `/create_typedef` - Type alias creation
- `/clone_data_type` - Type cloning and modification
- `/validate_data_type` - Type placement validation
- `/export_data_types` - Multi-format type export
- `/import_data_types` - Type import (placeholder)

### Python MCP Bridge
Each tool is exposed through the MCP bridge with comprehensive documentation and type hints for easy integration with MCP clients.

### Error Handling
All tools include robust error handling with detailed error messages for:
- Invalid addresses or type names
- Memory access violations
- Type creation conflicts
- Transaction management failures

## Performance Considerations

- **Pagination**: Search and listing operations support pagination for large datasets
- **Caching**: Type lookups use efficient caching mechanisms
- **Transactions**: All modifications use proper Ghidra transactions for data integrity
- **Memory**: Large export operations are streamed to prevent memory issues

## Future Enhancements

1. **Import Implementation**: Complete the data type import functionality
2. **Advanced Analysis**: Add more sophisticated type inference algorithms  
3. **Visualization**: Generate graphical representations of type relationships
4. **Templates**: Support for C++ template types and STL containers
5. **Debugging**: Integration with debugging symbols and metadata
6. **Validation**: Enhanced validation rules for complex type relationships

## Testing

Use the provided test script to verify all functionality:
```bash
python scripts/test_data_type_tools.py --server http://localhost:8089
```

The test script validates:
- Server connectivity
- Basic type operations
- Structure and union creation
- Address-based analysis
- Export functionality
- Error handling

## Conclusion

These data type tools significantly enhance the Ghidra MCP plugin's capabilities for automated reverse engineering workflows. They provide the foundation for sophisticated analysis automation while maintaining the flexibility needed for diverse reverse engineering tasks.