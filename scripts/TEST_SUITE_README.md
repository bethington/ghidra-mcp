# MCP Tools Test Suite

This directory contains comprehensive tests for all 57 MCP tools and their corresponding REST API endpoints in the GhidraMCP plugin.

## Overview

The test suite includes three types of tests:

1. **Endpoint Tests** (`test_mcp_tools_endpoints.py`) - Direct REST API endpoint testing
2. **Functional Tests** (`test_mcp_tools_functional.py`) - Workflow-based testing scenarios  
3. **Unit Tests** (`test_mcp_tools_unit.py`) - Pytest-based structured unit tests

## Quick Start

### Prerequisites

1. **Ghidra with MCP Plugin**: Ensure Ghidra is running with the GhidraMCP plugin loaded
2. **Python 3.10+**: Required for running the test scripts
3. **Test Dependencies**: Install with `pip install -r test_requirements.txt`

### Running All Tests

```bash
# Run all test suites
python run_mcp_tests.py

# Run specific test type
python run_mcp_tests.py --test-type endpoint
python run_mcp_tests.py --test-type functional  
python run_mcp_tests.py --test-type unit

# Use custom server URL
python run_mcp_tests.py --server http://localhost:8080/

# Verbose output
python run_mcp_tests.py --verbose

# Save to custom directory
python run_mcp_tests.py --output-dir my_test_results
```

### Running Individual Test Scripts

```bash
# Endpoint tests - Tests all 57 tools directly
python test_mcp_tools_endpoints.py [server_url]

# Functional tests - Tests workflows and scenarios
python test_mcp_tools_functional.py [server_url]

# Unit tests - Pytest-style structured tests
pytest test_mcp_tools_unit.py -v
```

## Test Categories

### Navigation Tools (13 tests)
- `list_functions` - List all functions with pagination
- `list_classes` - List namespace/class names  
- `list_segments` - List memory segments
- `list_imports` - List imported symbols
- `list_exports` - List exported symbols
- `list_namespaces` - List non-global namespaces
- `list_methods` - List all method names
- `list_data_items` - List defined data items
- `list_strings` - List all strings
- `get_current_address` - Get current cursor address
- `get_current_function` - Get currently selected function
- `get_function_by_address` - Get function at specific address
- `list_globals` - List global variables
- `get_entry_points` - Get program entry points

### Analysis Tools (11 tests)
- `decompile_function` - Decompile function by name
- `decompile_function_by_address` - Decompile function by address
- `disassemble_function` - Get assembly code for function
- `get_function_callees` - Get functions called by a function
- `get_function_callers` - Get functions that call a function
- `get_function_call_graph` - Get call graph for function
- `get_function_jump_target_addresses` - Get jump targets in function
- `get_function_xrefs` - Get cross-references to function
- `get_xrefs_to` - Get references to an address
- `get_xrefs_from` - Get references from an address  
- `get_full_call_graph` - Get complete program call graph

### Data Tools (13 tests)
- `list_data_types` - List available data types
- `create_struct` - Create new structure definition
- `create_enum` - Create new enumeration
- `apply_data_type` - Apply data type to memory location
- `analyze_data_types` - Analyze data types at address
- `create_union` - Create union data type
- `get_data_type_size` - Get size of data type
- `get_struct_layout` - Get structure field layout
- `auto_create_struct_from_memory` - Auto-create struct from memory
- `get_enum_values` - Get enumeration values
- `create_typedef` - Create type alias
- `clone_data_type` - Clone existing data type
- `validate_data_type` - Validate data type application

### Modification Tools (11 tests)  
- `rename_function` - Rename function by name
- `rename_function_by_address` - Rename function by address
- `create_label` - Create label at address
- `rename_label` - Rename existing label
- `set_disassembly_comment` - Set comment in disassembly
- `set_decompiler_comment` - Set comment in decompiler
- `set_function_prototype` - Set function signature
- `set_local_variable_type` - Set local variable type
- `rename_variable` - Rename local variable
- `rename_data` - Rename data item
- `rename_global_variable` - Rename global variable

### Search Tools (3 tests)
- `search_functions_by_name` - Search functions by name pattern
- `get_function_labels` - Get labels within function
- `search_data_types` - Search data types by pattern

### Metadata Tools (3 tests)
- `check_connection` - Test plugin connectivity
- `get_metadata` - Get program metadata
- `format_number_conversions` - Convert number representations

### Export Tools (2 tests)
- `export_data_types` - Export data types
- `import_data_types` - Import data types

### Memory Tools (1 test)
- `read_memory` - Read memory at address

## Test Output

### Test Results Directory Structure
```
test_results/
├── test_summary.json              # Overall test summary
├── endpoint_test_report.json      # Detailed endpoint test results  
├── endpoint_test_output.txt       # Endpoint test console output
├── functional_test_output.txt     # Functional test console output
├── unit_test_output.txt          # Unit test console output
└── unit_test_results.xml         # JUnit XML format results
```

### Understanding Test Results

**Success Criteria:**
- **Endpoint Tests**: HTTP 200 responses for valid requests
- **Functional Tests**: Workflow completion without critical errors
- **Unit Tests**: Assertions pass for each test case

**Expected Failures:**
- Modification operations may fail in read-only environments
- Function-specific tests may fail if test functions don't exist
- Address-specific tests may fail for invalid memory addresses

**Success Rates:**
- 80%+ = Excellent (tools working well)
- 60-79% = Good (some expected failures)
- <60% = Issues requiring investigation

## Troubleshooting

### Common Issues

**Connection Errors:**
```
❌ Cannot connect to Ghidra server at http://127.0.0.1:8089/
```
- Ensure Ghidra is running
- Verify GhidraMCP plugin is loaded and enabled
- Check server URL and port

**Missing Dependencies:**
```
❌ pytest not available, skipping unit tests
```
- Install test dependencies: `pip install -r test_requirements.txt`

**Test Timeouts:**
```
❌ Endpoint tests timed out
```
- Increase timeout: `python run_mcp_tests.py --timeout 30`
- Check if Ghidra is responding slowly

### Debugging Failed Tests

1. **Check Individual Test Output**: Look at `*_output.txt` files for detailed error messages
2. **Run Tests Individually**: Test specific categories to isolate issues
3. **Verify Ghidra State**: Ensure a binary is loaded and analyzed in Ghidra
4. **Check Permissions**: Some modification tests require write permissions

### Custom Server Configuration

If running Ghidra on a different host/port:

```bash
# Custom server
python run_mcp_tests.py --server http://192.168.1.100:8080/

# Custom port  
python run_mcp_tests.py --server http://localhost:9090/
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: MCP Tools Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r scripts/test_requirements.txt
      - name: Start Ghidra (headless)
        run: # Start Ghidra with test binary
      - name: Run MCP Tests
        run: python scripts/run_mcp_tests.py --output-dir test-results
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: test-results/
```

## Contributing

When adding new MCP tools:

1. **Add Endpoint Test**: Update `test_mcp_tools_endpoints.py` with new tool test
2. **Add Unit Test**: Add test class/method in `test_mcp_tools_unit.py`
3. **Update Functional Tests**: Add to relevant workflow if applicable
4. **Update Documentation**: Update this README with new tool information

### Test Best Practices

- Use realistic test data that might exist in typical binaries
- Handle both success and expected failure cases
- Include proper error handling and timeouts
- Document any special requirements or expected behaviors
- Test both positive and negative scenarios

## Performance Considerations

- Tests are designed to be non-destructive when possible
- Modification tests use unique names to avoid conflicts
- Pagination limits are kept small to reduce test time
- Timeouts prevent hung tests from blocking the suite

## Support

For issues with the test suite:
1. Check Ghidra console for plugin errors
2. Verify network connectivity to Ghidra
3. Review test output files for specific error messages
4. Ensure test binary is properly loaded and analyzed in Ghidra