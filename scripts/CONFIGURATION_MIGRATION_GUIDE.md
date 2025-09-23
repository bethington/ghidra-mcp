# GhidraMCP Scripts Configuration Migration Guide

## 🔄 What Changed

### **NEW: Centralized Configuration System**
All scripts now use a centralized configuration file (`scripts_config.py`) instead of hardcoded values.

### **Benefits of the Change:**
- ✅ **Consistency**: All scripts use same server URLs, timeouts, endpoints
- ✅ **Maintainability**: Change settings once, affects all scripts
- ✅ **Extensibility**: Easy to add new endpoints or settings
- ✅ **Standardization**: Consistent message formatting across scripts

## 📋 Configuration Categories

### **1. Server Configuration**
```python
# OLD: Hardcoded in each script
BASE_URL = "http://127.0.0.1:8089/"
timeout = 30

# NEW: Centralized configuration
from scripts_config import get_server_url, get_timeout
server_url = get_server_url()  # Supports CLI args, env vars, defaults
timeout = get_timeout()
```

### **2. Endpoint Definitions**
```python
# OLD: Hardcoded endpoint lists in each script
endpoints = [
    ("GET", "/methods", "List available methods"),
    ("GET", "/list_functions", "List functions"),
    # ... more endpoints
]

# NEW: Centralized endpoint categories
from scripts_config import EndpointConfig
core_endpoints = EndpointConfig.CORE_ENDPOINTS
all_endpoints = EndpointConfig.get_all_endpoints()
data_type_endpoints = EndpointConfig.get_endpoints_by_category("data_types")
```

### **3. Message Formatting**
```python
# OLD: Inconsistent symbols and formatting
print("✅ Success")
print("❌ Error")

# NEW: Standardized message formatting
from scripts_config import MessageConfig, format_success, format_error
print(format_success("Success message"))
print(format_error("Error message"))
print(MessageConfig.format_test_result(8, 10))  # "⚠️ Tests: 8/10 passed (80.0%)"
```

### **4. Sample Data**
```python
# OLD: Hardcoded test data in each script
sample_struct = {
    "name": "TestStruct",
    "fields": [{"name": "id", "type": "int"}]
}

# NEW: Shared sample data
from scripts_config import SampleDataConfig
sample_struct = SampleDataConfig.SAMPLE_STRUCT
sample_enum = SampleDataConfig.SAMPLE_ENUM
search_terms = SampleDataConfig.SEARCH_TERMS
```

## 🛠️ Migration Steps

### **For Existing Script Users:**
1. **No action required** - Scripts maintain the same command-line interface
2. **Environment variables supported** - Set `GHIDRA_MCP_SERVER_URL` if needed
3. **Command-line args still work** - `python script.py http://custom-url/`

### **For Script Developers:**
1. **Import configuration**:
   ```python
   from scripts_config import (
       Config, EndpointConfig, MessageConfig,
       get_server_url, get_timeout, format_success
   )
   ```

2. **Replace hardcoded values**:
   ```python
   # OLD
   server_url = "http://127.0.0.1:8089/"
   
   # NEW  
   server_url = get_server_url()
   ```

3. **Use endpoint categories**:
   ```python
   # OLD
   endpoints = [("GET", "/methods", "List methods")]
   
   # NEW
   endpoints = EndpointConfig.CORE_ENDPOINTS
   ```

4. **Standardize messages**:
   ```python
   # OLD
   print("✅ Test passed")
   
   # NEW
   print(format_success("Test passed"))
   ```

## 📊 Configuration Overview

### **Available Configurations:**
- **ServerConfig**: Connection settings, timeouts, retry logic
- **EndpointConfig**: 41 endpoints across 6 categories
- **MessageConfig**: Standardized symbols and formatting
- **TestConfig**: Testing parameters and thresholds
- **SampleDataConfig**: Shared test data and examples
- **ValidationConfig**: Validation patterns and rules

### **Environment Variables:**
- `GHIDRA_MCP_SERVER_URL`: Override default server URL
- Scripts respect command-line arguments and environment variables

### **Path Configuration:**
- `Config.SCRIPTS_DIR`: Scripts directory path
- `Config.PROJECT_ROOT`: Project root directory  
- `Config.LOGS_DIR`: Logs directory (auto-created)

## 🎯 Best Practices

### **For New Scripts:**
1. **Always import configuration**: `from scripts_config import ...`
2. **Use endpoint categories**: Don't hardcode endpoint lists
3. **Use standardized messages**: Consistent user experience
4. **Leverage sample data**: For testing and examples
5. **Follow validation patterns**: Use built-in validation functions

### **Configuration Example:**
```python
#!/usr/bin/env python3
"""
Example Script with Centralized Configuration
"""
from scripts_config import (
    EndpointConfig, MessageConfig, get_server_url, 
    get_timeout, format_success, format_error
)
import requests

def main():
    server_url = get_server_url()
    
    # Test core endpoints
    for method, endpoint, description in EndpointConfig.CORE_ENDPOINTS:
        try:
            url = server_url.rstrip('/') + endpoint
            response = requests.get(url, timeout=get_timeout())
            
            if response.ok:
                print(format_success(f"{description}: Working"))
            else:
                print(format_error(f"{description}: HTTP {response.status_code}"))
                
        except Exception as e:
            print(format_error(f"{description}: {str(e)}"))

if __name__ == "__main__":
    main()
```

## ✅ Migration Complete

The centralized configuration system is now active across all GhidraMCP scripts. All existing functionality is preserved while providing better maintainability and consistency.

**No breaking changes** - existing script usage patterns continue to work as before.