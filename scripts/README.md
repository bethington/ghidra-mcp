# GhidraMCP Scripts Directory

Professional utilities and tools for GhidraMCP development, testing, and deployment.

## � **Centralized Configuration**

### **`scripts_config.py`** - Centralized Configuration System
- **Purpose**: Shared configuration for all GhidraMCP scripts
- **Features**:
  - Server URL and connection settings management
  - Comprehensive endpoint definitions (41 endpoints across 6 categories)
  - Standardized message formatting and symbols
  - Sample data for testing and examples
  - Validation patterns and rules
  - Path and logging configuration
- **Usage**: `from scripts_config import Config, EndpointConfig, MessageConfig`
- **Benefits**: Eliminates hardcoded values, ensures consistency, simplifies maintenance

### **`config_usage_example.py`** - Configuration Usage Examples
- **Purpose**: Demonstrates how to use the centralized configuration
- **Features**: Complete examples of all configuration categories
- **Usage**: `python config_usage_example.py`

## �📋 Available Scripts

### 🏥 **Health & Diagnostics**

#### **`ghidra_server_health_check.py`** - Server Health Diagnostics
- **Purpose**: Comprehensive health check for GhidraMCP server readiness
- **Features**:
  - Server connectivity validation
  - Plugin installation verification
  - Program loading status check
  - Core functionality testing
  - Detailed diagnostic reporting
- **Usage**: `python ghidra_server_health_check.py [server_url]`
- **When to use**: Before running tests, after plugin installation, troubleshooting

#### **`ghidra_plugin_deployment_verifier.py`** - Deployment Verification
- **Purpose**: Verifies plugin deployment and provides deployment guidance
- **Features**:
  - Core endpoint functionality testing
  - Step-by-step deployment instructions
  - Post-deployment validation
  - Installation status reporting
- **Usage**: `python ghidra_plugin_deployment_verifier.py [server_url]`
- **When to use**: After building plugin, during deployment process

### 🧪 **Testing & Validation**

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