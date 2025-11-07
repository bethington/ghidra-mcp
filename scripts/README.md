# 🛠️ GhidraMCP Scripts Directory

> **Professional utilities and automation tools** for GhidraMCP development, testing, and deployment.

---

## 📂 Directory Organization

```
scripts/
├── 🔄 Data Processing
│   ├── data-extract.ps1              # Extract data from Ghidra
│   ├── data-process.ps1              # Process extracted data
│   ├── process_char_arrays.py        # Character array processing
│   └── make_data_meaningful.py       # Data naming automation
│
├── ⚡ Function Processing
│   ├── functions-extract.ps1         # Extract function data
│   ├── functions-process.ps1         # Process functions  
│   ├── hybrid-function-processor.ps1 # Hybrid processing workflow
│   └── FunctionsTodo.txt             # Function processing task list
│
├── 🧪 Testing & Validation
│   ├── test_convention_detection.py      # Test calling convention detection
│   ├── test_d2_detection.py              # Test D2 convention detection
│   ├── test_d2_simple.py                 # Simple D2 tests
│   ├── test_data_xrefs_tool.py           # Test xref tools
│   ├── validate_function_accuracy.py     # Validate function analysis
│   ├── verify_all_structures.py          # Structure verification
│   ├── quick_detection_test.py           # Quick detection tests
│   ├── ghidra_rest_api_functional_tests.py  # REST API tests
│   ├── ghidra_server_health_check.py     # Server health monitoring
│   └── ghidra_plugin_deployment_verifier.py # Plugin verification
│
├── 🔧 Fix & Repair
│   ├── fix_undefined_types.py            # Fix undefined type issues
│   ├── apply_edge_case_fixes.py          # Apply edge case fixes
│   ├── apply_test_fixes.py               # Apply test-identified fixes
│   ├── automated_edge_case_fix.py        # Automated fixing
│   ├── run_edge_case_validation.py       # Validate edge cases
│   └── ClearCallReturnOverrides.java     # Clear call/return overrides
│
├── 📊 Reporting & Analysis
│   ├── final_comprehensive_report.py     # Generate comprehensive reports
│   ├── ghidra_mcp_usage_examples.py      # Usage examples
│   └── search_punit_references.py        # Search pUnit references
│
├── 🔍 Verification
│   └── verify_version.py                 # Version consistency verification
│
├── 📝 Configuration
│   ├── scripts_config.py                 # Shared configuration
│   ├── process_whitelist.json            # Processing whitelist
│   ├── TEST_SUITE_README.md              # Test suite documentation
│   └── CONFIGURATION_MIGRATION_GUIDE.md  # Configuration migration
│
└── � Documentation
    └── README.md                          # This file
```

---

## � Centralized Configuration

### **`scripts_config.py`** - Central Configuration System

**Purpose**: Shared configuration for all GhidraMCP scripts

**Features**:
- Server URL and connection settings management
- Comprehensive endpoint definitions (41 endpoints across 6 categories)
- Standardized message formatting and symbols
- Sample data for testing and examples
- Validation patterns and rules
- Path and logging configuration

**Usage**:
```python
from scripts_config import Config, EndpointConfig, MessageConfig

# Get server URL
server_url = Config.SERVER_URL

# Access endpoints
endpoint = EndpointConfig.FUNCTIONS_LIST

# Use message formatting
print(MessageConfig.success("Operation completed"))
```

**Benefits**:
- ✅ Eliminates hardcoded values
- ✅ Ensures consistency across scripts
- ✅ Simplifies maintenance
- ✅ Centralized updates

---

## 🚀 Quick Start

### Data Extraction & Processing

```powershell
# Extract all data items from Ghidra
.\data-extract.ps1

# Process extracted data with meaningful names
.\data-process.ps1

# Process character arrays specifically
python process_char_arrays.py

# Make data meaningful (auto-naming)
python make_data_meaningful.py
```

### Function Analysis

```powershell
# Extract all functions
.\functions-extract.ps1 -All

# Extract excluding library functions
.\functions-extract.ps1 -All -ExcludeLibraryFunctions

# Process functions (forward pass)
.\functions-process.ps1

# Process functions (reverse pass)
.\functions-process.ps1 -Reverse

# Hybrid processing workflow
.\hybrid-function-processor.ps1
```

### Health & Diagnostics

```powershell
# Check server health
python ghidra_server_health_check.py

# Verify plugin deployment
python ghidra_plugin_deployment_verifier.py

# Quick detection test
python quick_detection_test.py
```

---

#### **`ghidra_rest_api_functional_tests.py`** - API Functional Testing
- **Purpose**: Comprehensive REST API functionality testing with real data
- **Features**:
  - Real API response validation
  - Data integrity verification
  - Performance measurements
  - Error condition handling
  - Detailed test reporting
- **Usage**: `python ghidra_rest_api_functional_tests.py [server_url]`
- **When to use**: API validation, regression testing, performance analysis

### � **Examples & Documentation**

#### **`ghidra_mcp_usage_examples.py`** - API Usage Examples
- **Purpose**: Comprehensive examples of GhidraMCP API usage
- **Features**:
  - All major functionality categories
  - Proper error handling patterns
  - Real-world usage scenarios
  - Type hints and documentation
- **Usage**: `python ghidra_mcp_usage_examples.py [server_url]`
- **When to use**: Learning API, integration examples, development reference

## 🚀 Quick Start Guide

### **1. Initial Setup Verification**
```bash
# Check if GhidraMCP is ready for use
python scripts/ghidra_server_health_check.py

# If issues found, verify deployment
python scripts/ghidra_plugin_deployment_verifier.py
```

### **2. API Testing**
```bash
# Run functional tests
python scripts/ghidra_rest_api_functional_tests.py

# Explore API examples
python scripts/ghidra_mcp_usage_examples.py
```

### **3. Development Workflow**
```bash
# 1. Health check before development
python scripts/ghidra_server_health_check.py

# 2. Review API examples for integration patterns
python scripts/ghidra_mcp_usage_examples.py

# 3. Run functional tests for regression testing
python scripts/ghidra_rest_api_functional_tests.py
```

## 📊 Script Categories

| Category | Scripts | Purpose |
|----------|---------|---------|
| **Configuration** | 2 | Centralized config and usage examples |
| **Health** | 1 | Server diagnostics and readiness |
| **Deployment** | 1 | Plugin deployment verification |
| **Testing** | 1 | Functional API testing |
| **Examples** | 1 | Usage documentation and examples |
| **Total** | **6** | Complete toolkit |

## 🔧 Requirements

All scripts share these requirements:
- **Python 3.7+**
- **requests library**: `pip install requests`
- **GhidraMCP plugin installed** and running in Ghidra
- **Binary loaded and analyzed** in Ghidra (for full functionality)

## 🎯 Best Practices

### **Development Workflow**
1. **Always run health check first** - `ghidra_server_health_check.py`
2. **Verify deployment after changes** - `ghidra_plugin_deployment_verifier.py`
3. **Use examples for integration** - `ghidra_mcp_usage_examples.py`
4. **Run functional tests for validation** - `ghidra_rest_api_functional_tests.py`

### **Error Handling**
- All scripts include comprehensive error handling
- Clear error messages with suggested solutions
- Graceful degradation when services unavailable

### **Testing Integration**
- Scripts can be used in CI/CD pipelines
- Exit codes indicate success/failure status
- JSON output available for automated processing

## 📝 Documentation Status

| Script | Documentation | Error Handling | Configuration | Status |
|--------|---------------|----------------|---------------|---------|
| `scripts_config.py` | ✅ Complete | ✅ Comprehensive | ✅ **Core Config** | 🟢 Ready |
| `config_usage_example.py` | ✅ Complete | ✅ Comprehensive | ✅ Uses Config | 🟢 Ready |
| `ghidra_server_health_check.py` | ✅ Complete | ✅ Comprehensive | ✅ Uses Config | 🟢 Ready |
| `ghidra_plugin_deployment_verifier.py` | ✅ Complete | ✅ Comprehensive | ✅ Uses Config | 🟢 Ready |
| `ghidra_rest_api_functional_tests.py` | ✅ Complete | ✅ Comprehensive | ✅ Uses Config | 🟢 Ready |
| `ghidra_mcp_usage_examples.py` | ✅ Complete | ✅ Comprehensive | ✅ Uses Config | 🟢 Ready |

**Status: ✅ All scripts use centralized configuration and are production-ready.**

## 🎯 Configuration Benefits

- **Consistency**: All scripts use the same server URLs, timeouts, and endpoints
- **Maintainability**: Change settings in one place, affects all scripts
- **Extensibility**: Easy to add new endpoints, settings, or validation rules
- **Standardization**: Consistent message formatting and error handling
- **Testing**: Shared sample data and validation patterns
- **Documentation**: Self-documenting configuration with examples
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