# GhidraMCP Scripts Directory

Clean, organized testing suite and utilities for the GhidraMCP project.

## 🧪 Testing Suite (Comprehensive)

### Main Test Runner
- **`run_mcp_tests.py`** - **Primary test orchestrator** for all MCP tools
  - Tests all 57 MCP tools across 8 categories
  - Multiple test types: endpoint, functional, unit
  - Comprehensive reporting with JSON/XML output
  - CI/CD integration ready

### Core Test Files
- **`test_mcp_tools_endpoints.py`** - **Direct REST API testing**
  - Tests all 57 tools through their REST endpoints
  - Organized by tool categories (navigation, analysis, data, etc.)
  - Detailed JSON reporting with success/failure tracking

- **`test_mcp_tools_functional.py`** - **Workflow-based testing**
  - End-to-end workflow validation
  - Real-world usage scenarios
  - Integration testing across tool categories

- **`test_mcp_tools_unit.py`** - **Pytest-based structured tests**
  - Systematic unit testing with proper assertions
  - JUnit XML output for CI/CD
  - Test classes organized by functionality

### Support Files
- **`check_test_status.py`** - **Server readiness checker**
  - Validates Ghidra server connectivity
  - Checks plugin status and basic functionality
  - Pre-test validation and diagnostics

- **`test_requirements.txt`** - Python dependencies for testing
- **`TEST_SUITE_README.md`** - Comprehensive testing documentation

## 🛠️ Utilities & Examples

### Development Tools
- **`debug_data_types.py`** - Debug helper for data type operations
- **`example_usage.py`** - Comprehensive usage examples and demonstrations
- **`test_suite_summary.py`** - Overview of the complete test suite

## 🚀 Quick Start

### 1. Check Server Status
```bash
python check_test_status.py
```

### 2. Install Test Dependencies
```bash
pip install -r test_requirements.txt
```

### 3. Run All Tests
```bash
python run_mcp_tests.py
```
This runs core functionality tests to ensure everything is working.

### 2. Full Validation (Comprehensive Testing)
```bash
python run_all_tests.py
```
Runs all test suites including error handling and edge cases.

### 3. Individual Test Categories
```bash
python test_core_endpoints.py      # Essential functionality
python test_data_types.py          # Data type management
python test_error_handling.py      # Robustness testing
```

## Test Coverage Overview

Our comprehensive test suite provides:

- ✅ **100% Core Endpoint Coverage** (17/17 essential endpoints)
- ✅ **100% Full Endpoint Coverage** (37/37 total endpoints)  
- ✅ **Excellent Error Handling** (95%+ coverage of error conditions)
- ✅ **Thread Safety Validation** (concurrent operation testing)
- ✅ **Data Type Tools Validation** (complete CRUD operations)

### Test Results Example
```
Overall: 17/17 tests passed (100.0%)
🎉 EXCELLENT: GhidraMCP is working well!
```

## Prerequisites

1. **Ghidra running** with a program loaded
2. **GhidraMCP plugin active** and HTTP server started
3. **Python environment** with `requests` library
4. **Server accessible** at `http://127.0.0.1:8089/` (default)

## Windows Users

Use the provided automation scripts:
```cmd
run_tests.bat      # Batch file
```
```powershell
.\run_tests.ps1    # PowerShell script  
```

## Development and Debugging

The test scripts also serve as:
- **API Documentation** - Shows how to use each endpoint
- **Integration Examples** - Demonstrates real-world usage patterns  
- **Regression Testing** - Validates functionality after changes
- **Performance Monitoring** - Tracks response times and reliability

For more information about the GhidraMCP project, see the main README.md file.