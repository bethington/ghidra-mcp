# Error Codes & Troubleshooting Guide

This document provides comprehensive error handling guidance for the Ghidra MCP Server.

## Common Error Categories

### Connection & Connectivity Issues

#### E001: Connection Refused
**Symptoms**: `Connection refused` when running MCP client

**Causes**:
- Ghidra MCP server not running
- Ghidra not open with a loaded binary
- Port 8089 blocked by firewall
- Different host/port configuration

**Solutions**:
```bash
# 1. Start MCP server
python bridge_mcp_ghidra.py

# 2. Verify server is listening
netstat -an | findstr 8089

# 3. Test connection
curl http://127.0.0.1:8089/get_version

# 4. If on different machine, use:
python bridge_mcp_ghidra.py --ghidra-server http://remote-host:8089/
```

**Prevention**: Add health check to startup scripts:
```python
import requests
try:
    response = requests.get("http://127.0.0.1:8089/get_version", timeout=5)
    print("✓ MCP server is running")
except:
    print("✗ MCP server not responding")
```

---

#### E002: Timeout Error
**Symptoms**: `Request timed out` after 30 seconds

**Causes**:
- Ghidra performing expensive decompilation
- Large binary analysis taking too long
- Network latency
- Server temporarily unresponsive

**Solutions**:
```python
# Increase timeout for expensive operations
import requests

# Decompilation often needs longer timeout
response = requests.get(
    "http://127.0.0.1:8089/decompile_function",
    params={"name": "main"},
    timeout=60  # Increase from default 30
)

# Batch operations may need even longer
timeout_by_operation = {
    "decompile_function": 60,
    "batch_decompile_functions": 120,
    "get_full_call_graph": 90,
    "list_functions": 30,
    "get_xrefs_to": 30
}
```

**Prevention**: Monitor Ghidra window for analysis completion before making requests

---

#### E003: Connection Reset/Dropped
**Symptoms**: `Connection reset by peer` mid-operation

**Causes**:
- MCP server crashed
- Ghidra crashed or became unresponsive
- Network instability
- Server reached resource limits

**Solutions**:
```python
# Implement retry logic
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

session = requests.Session()
retry = Retry(
    total=3,  # Retry up to 3 times
    connect=3,
    backoff_factor=0.5  # Wait 0.5s, 1s, 2s between retries
)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)

response = session.get("http://127.0.0.1:8089/get_version")
```

**Prevention**: Restart MCP server and Ghidra if connection drops:
```bash
# Kill MCP server and restart
pkill -f bridge_mcp_ghidra.py
python bridge_mcp_ghidra.py
```

---

### Function & Symbol Errors

#### E101: Function Not Found
**Symptoms**: `Error: Function 'FUN_401000' not found`

**Causes**:
- Function name doesn't exist in loaded binary
- Binary not loaded in Ghidra
- Function name is case-sensitive
- Function renamed or removed during analysis

**Solutions**:
```python
# 1. List available functions
functions = requests.get(
    "http://127.0.0.1:8089/list_functions",
    params={"limit": 100}
).json()

# 2. Search for similar names
matching = [f for f in functions if "main" in f.get("name", "").lower()]

# 3. Verify binary is loaded
metadata = requests.get(
    "http://127.0.0.1:8089/get_metadata"
).json()
print(f"Binary: {metadata.get('name', 'None')}")
```

**Prevention**: Always validate function names before operations:
```python
def safe_decompile(func_name):
    functions = list_available_functions()
    if func_name not in [f["name"] for f in functions]:
        print(f"✗ Function '{func_name}' not found")
        return None
    return decompile_function(func_name)
```

---

#### E102: Data Type Not Found
**Symptoms**: `Error: Cannot apply data type 'MyStruct' - type not found`

**Causes**:
- Structure not created yet
- Structure name misspelled
- Structure in different namespace
- Structure was deleted

**Solutions**:
```python
# 1. List available data types
types = requests.get(
    "http://127.0.0.1:8089/list_data_types",
    params={"category": "struct"}
).json()

# 2. Create structure first
requests.post(
    "http://127.0.0.1:8089/create_struct",
    json={
        "name": "MyStruct",
        "fields": [
            {"name": "field1", "type": "int"},
            {"name": "field2", "type": "uint"}
        ]
    }
)

# 3. Then apply it
requests.post(
    "http://127.0.0.1:8089/apply_data_type",
    params={
        "address": "0x401000",
        "type_name": "MyStruct"
    }
)
```

**Prevention**: Use batch operations that create and apply in single transaction:
```python
# This creates and applies atomically
result = requests.post(
    "http://127.0.0.1:8089/create_and_apply_data_type",
    params={
        "address": "0x401000",
        "classification": "STRUCTURE",
        "type_definition": {
            "name": "MyStruct",
            "fields": [...]
        }
    }
)
```

---

### Decompilation & Analysis Errors

#### E201: Decompilation Failed
**Symptoms**: `Error decompiling function main`

**Causes**:
- Function too large or complex
- Function has obfuscated code
- Incomplete analysis by Ghidra
- Memory pressure on Ghidra

**Solutions**:
```python
# 1. Force re-analysis with fresh decompilation
result = requests.get(
    "http://127.0.0.1:8089/decompile_function",
    params={
        "name": "main",
        "force": True  # Force fresh decompilation
    }
)

# 2. Try on subset first
result = requests.get(
    "http://127.0.0.1:8089/decompile_function",
    params={"address": "0x401000"}  # Use address instead of name
)

# 3. Check function size (if very large, decompilation may be incomplete)
functions = requests.get(
    "http://127.0.0.1:8089/list_functions",
    params={"limit": 100}
).json()
main_func = [f for f in functions if f["name"] == "main"][0]
```

**Prevention**: Monitor Ghidra analysis progress before decompiling

---

#### E202: No Cross-references Found
**Symptoms**: `Empty array returned for get_function_xrefs`

**Causes**:
- Function genuinely has no callers (might be entry point)
- Analysis not complete
- Cross-references not analyzed yet
- Function is dead code

**Solutions**:
```python
# 1. Check function info
func = requests.get(
    "http://127.0.0.1:8089/get_function_by_address",
    params={"address": "0x401000"}
).json()

# 2. Analyze call graph to understand context
callees = requests.get(
    "http://127.0.0.1:8089/get_function_callees",
    params={"name": "main"}
).json()

# 3. If function has no callers, it might be:
# - Entry point (check with get_entry_points)
# - Dead code (not used anywhere)
# - Called dynamically (can't be detected statically)
```

**Prevention**: Understand expected functions before querying

---

### Data Structure Errors

#### E301: No Defined Data at Address
**Symptoms**: `Error: No defined data at address 0x401000`

**Causes**:
- Address contains code, not data
- Data not yet defined at that address
- Address is unmapped memory
- Address formatting incorrect (missing 0x prefix)

**Solutions**:
```python
# 1. Inspect memory content first
result = requests.get(
    "http://127.0.0.1:8089/inspect_memory_content",
    params={
        "address": "0x401000",
        "length": 64
    }
)

# 2. Apply data type to define the data
result = requests.post(
    "http://127.0.0.1:8089/apply_data_type",
    params={
        "address": "0x401000",
        "type_name": "dword"  # Define as 4-byte integer
    }
)

# 3. Then rename
result = requests.post(
    "http://127.0.0.1:8089/rename_data",
    params={
        "address": "0x401000",
        "new_name": "MyDataLabel"
    }
)
```

**Prevention**: Use `create_and_apply_data_type` for atomic operation:
```python
result = requests.post(
    "http://127.0.0.1:8089/create_and_apply_data_type",
    params={
        "address": "0x401000",
        "classification": "PRIMITIVE",
        "type_definition": {"type": "dword"},
        "name": "MyData"
    }
)
```

---

#### E302: Array Size Mismatch
**Symptoms**: `Error: Cannot create array - element size exceeds structure bounds`

**Causes**:
- Array element type too large for allocated space
- Incorrect array count specified
- Structure field overlap

**Solutions**:
```python
# 1. Detect proper array size first
result = requests.get(
    "http://127.0.0.1:8089/detect_array_bounds",
    params={"address": "0x401000"}
)
bounds = result.json()
# Returns: probable_element_size, probable_element_count, total_bytes

# 2. Create array with detected values
array_type = requests.post(
    "http://127.0.0.1:8089/create_array_type",
    params={
        "base_type": "dword",
        "length": bounds["probable_element_count"],
        "name": "MyArray"
    }
).json()

# 3. Apply the array
result = requests.post(
    "http://127.0.0.1:8089/apply_data_type",
    params={
        "address": "0x401000",
        "type_name": array_type["name"]
    }
)
```

**Prevention**: Use `detect_array_bounds` before creating arrays

---

### Batch Operation Errors

#### E401: Batch Operation Partial Failure
**Symptoms**: `"labels_created": 8, "labels_failed": 2, "errors": [...] `

**Causes**:
- Some items in batch succeed, some fail
- Address validation failure for some items
- Name conflicts for some items
- Permission issues for some items

**Solutions**:
```python
# 1. Process batch results individually
result = requests.post(
    "http://127.0.0.1:8089/batch_create_labels",
    json={
        "labels": [
            {"address": "0x401000", "name": "start"},
            {"address": "0x401010", "name": "loop_check"},
            # More labels...
        ]
    }
).json()

# Check results
print(f"Created: {result['labels_created']}")
print(f"Failed: {result['labels_failed']}")

if result.get("errors"):
    for error in result["errors"]:
        print(f"  - {error}")

# 2. Retry failed items individually
for error in result.get("errors", []):
    # Fix issue and retry
    pass

# 3. Use smaller batches if many failures
# Instead of 100 items, try 10 items per batch
```

**Prevention**: Validate all items before sending batch:
```python
def validate_labels(labels):
    for label in labels:
        address = label["address"]
        if not address.startswith("0x"):
            print(f"Invalid address: {address}")
        if not label["name"]:
            print("Empty name")
```

---

### Authentication & Permission Errors

#### E501: Localhost-Only Connection
**Symptoms**: `Error: Connection from non-localhost address denied`

**Causes**:
- Trying to connect from different machine/IP
- Security restriction: MCP server only accepts localhost

**Solutions**:
```bash
# 1. Connect from same machine as Ghidra
python bridge_mcp_ghidra.py  # On machine with Ghidra

# 2. Or use SSH tunneling to remote Ghidra:
ssh -L 8089:127.0.0.1:8089 user@remote-host

# 3. Then connect locally (tunneled to remote)
python my_script.py  # Uses 127.0.0.1:8089 (tunneled)
```

**Prevention**: Use SSH tunnel or VPN for remote access

---

## Quick Reference Table

| Error Code | Issue | Quick Fix |
|-----------|-------|-----------|
| E001 | Connection refused | Start MCP server: `python bridge_mcp_ghidra.py` |
| E002 | Request timeout | Increase `timeout=60` in requests.get() |
| E003 | Connection reset | Restart MCP server and Ghidra |
| E101 | Function not found | Verify binary loaded, list available functions |
| E102 | Data type not found | Create struct first, then apply |
| E201 | Decompilation failed | Use `force=True` parameter |
| E202 | No xrefs found | Function might be entry point or dead code |
| E301 | No data at address | Apply data type first, then rename |
| E302 | Array size mismatch | Use `detect_array_bounds` first |
| E401 | Batch partial failure | Check error details, retry failed items |
| E501 | Non-localhost connection | Use SSH tunnel for remote access |

---

## Debugging Workflow

### Step 1: Enable Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# See all HTTP requests
import http.client as http_client
http_client.HTTPConnection.debuglevel = 1
```

### Step 2: Check MCP Server Status
```bash
# 1. Verify it's running
curl http://127.0.0.1:8089/get_version

# 2. Check Ghidra CodeBrowser window
# - Binary should be open
# - Analysis should be complete (green checkmark)

# 3. Check MCP server logs
# See console output of bridge_mcp_ghidra.py
```

### Step 3: Simplify Request
```python
# Start with simplest possible request
result = requests.get("http://127.0.0.1:8089/get_metadata")

# If this works, try next tool
result = requests.get("http://127.0.0.1:8089/list_functions", params={"limit": 5})

# Gradually increase complexity
```

### Step 4: Check Address Format
```python
# All addresses should be hex strings with 0x prefix
addresses = [
    "0x401000",       # Correct
    "0x00401000",     # Also correct
    "401000",         # Incorrect! Missing 0x
    "0x401000LL",     # Incorrect! Extra suffix
]
```

### Step 5: Validate Responses
```python
import json

try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()  # Raises HTTPError for bad status
    data = response.json()
except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.ConnectionError:
    print("Connection refused")
except json.JSONDecodeError:
    print("Response is not valid JSON")
    print(response.text)
```

---

## Support Resources

- **Documentation**: See `README.md` and `DOCUMENTATION_INDEX.md`
- **Examples**: See `examples/` directory for working code
- **Logs**: Check MCP server output for detailed error messages
- **GitHub Issues**: Report bugs with error code and reproduction steps

---

## Contributing Improvements

Have solutions for other errors? Help improve this guide:
1. Add your error code to this document
2. Include symptoms, causes, and solutions
3. Add to Quick Reference table
4. Submit PR with improvements
