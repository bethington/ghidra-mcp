# list_data_items_by_xrefs Tool Guide

## Overview

The `list_data_items_by_xrefs` tool returns all defined data items in a Ghidra program sorted by cross-reference count in descending order (most referenced first). This is extremely useful for identifying the most important data structures in a binary.

**Version:** 1.7.4
**Tool Type:** MCP Tool
**REST Endpoint:** `/list_data_items_by_xrefs`

## Use Cases

- **Prioritize data structure analysis**: Start with the most frequently accessed data items
- **Identify global tables**: Find heavily-referenced lookup tables, configuration structures, etc.
- **Detect hot data**: Discover data items that are central to program execution
- **Optimize reverse engineering workflow**: Focus on data with the most impact first

## Usage

### MCP Tool (Python)

```python
from mcp import ClientSession

# Get top 50 most referenced data items as JSON
result = await mcp.call_tool("list_data_items_by_xrefs", {
    "limit": 50,
    "format": "json"
})

# Get all data items sorted by xrefs (text format)
result = await mcp.call_tool("list_data_items_by_xrefs", {
    "limit": 10000,
    "format": "text"
})
```

### Direct Ghidra MCP Call

```python
import mcp_ghidra

# JSON format (default)
items = mcp_ghidra.list_data_items_by_xrefs(limit=100, format="json")

# Text format
items_text = mcp_ghidra.list_data_items_by_xrefs(limit=100, format="text")
```

### REST API (Direct)

```bash
# JSON format (recommended for programmatic access)
curl "http://127.0.0.1:8089/list_data_items_by_xrefs?offset=0&limit=20&format=json"

# Text format (human-readable)
curl "http://127.0.0.1:8089/list_data_items_by_xrefs?offset=0&limit=20&format=text"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `offset` | int | 0 | Pagination offset for starting position |
| `limit` | int | 100 | Maximum number of items to return |
| `format` | str | "json" | Output format: "json" or "text" |

## Output Formats

### JSON Format

Returns a structured array of data item objects:

```json
[
  {
    "address": "0x6fb835b8",
    "name": "FrameThresholdDataTable",
    "type": "pointer",
    "size": "4 bytes",
    "xref_count": 125
  },
  {
    "address": "0x6fb7f528",
    "name": "SehFrameLocaleMapping",
    "type": "IMAGE_SECTION_HEADER",
    "size": "40 bytes",
    "xref_count": 87
  },
  ...
]
```

**Fields:**
- `address`: Memory address in hex format (with "0x" prefix)
- `name`: Symbol name or auto-generated DAT_ label
- `type`: Data type (e.g., "pointer", "dword", structure name)
- `size`: Human-readable size (e.g., "4 bytes", "128 bytes")
- `xref_count`: Number of cross-references to this data item

### Text Format

Returns human-readable lines:

```
FrameThresholdDataTable @ 6fb835b8 [pointer] (4 bytes) - 125 xrefs
SehFrameLocaleMapping @ 6fb7f528 [IMAGE_SECTION_HEADER] (40 bytes) - 87 xrefs
GlobalConfigData @ 6fba9dec [ConfigStruct] (28 bytes) - 45 xrefs
...
```

**Format:** `name @ address [type] (size) - N xrefs`

## Sorting Behavior

Results are **always** sorted by `xref_count` in **descending order**. Items with the most cross-references appear first, making it easy to identify the most heavily-used data structures.

**Example:** An item with 125 xrefs will appear before one with 87 xrefs, which appears before one with 45 xrefs, etc.

## Performance Considerations

- **Fast for small datasets**: < 1 second for programs with < 10,000 data items
- **Moderate for large datasets**: 2-5 seconds for programs with 50,000+ data items
- **Memory efficient**: Processes data in a single pass without storing entire program memory

## Pagination

For programs with many data items, use pagination:

```python
# Get first 100 items
page1 = list_data_items_by_xrefs(offset=0, limit=100)

# Get next 100 items
page2 = list_data_items_by_xrefs(offset=100, limit=100)

# Get items 200-299
page3 = list_data_items_by_xrefs(offset=200, limit=100)
```

## Comparison with list_data_items

| Feature | `list_data_items` | `list_data_items_by_xrefs` |
|---------|-------------------|----------------------------|
| **Includes xref counts** | ❌ No | ✅ Yes |
| **Sorted by xrefs** | ❌ No (address order) | ✅ Yes (descending) |
| **JSON output** | ❌ No (text only) | ✅ Yes |
| **Use case** | Sequential browsing | Prioritized analysis |

## Examples

### Example 1: Find Top 10 Most Referenced Data

```python
import json
import requests

# Get top 10 as JSON
response = requests.get("http://127.0.0.1:8089/list_data_items_by_xrefs",
                       params={"limit": 10, "format": "json"})
data = json.loads(response.text)

print("Top 10 Most Referenced Data Items:")
print(f"{'Rank':<6} {'Address':<12} {'Xrefs':<8} {'Name':<30}")
print("-" * 60)

for i, item in enumerate(data, 1):
    print(f"{i:<6} {item['address']:<12} {item['xref_count']:<8} {item['name']:<30}")
```

**Output:**
```
Top 10 Most Referenced Data Items:
Rank   Address      Xrefs    Name
------------------------------------------------------------
1      0x6fb835b8   125      FrameThresholdDataTable
2      0x6fb7f528   87       SehFrameLocaleMapping
3      0x6fba9dec   45       GlobalConfigData
...
```

### Example 2: Filter by Minimum Xref Count

```python
# Get all items with at least 10 xrefs
response = requests.get("http://127.0.0.1:8089/list_data_items_by_xrefs",
                       params={"limit": 10000, "format": "json"})
data = json.loads(response.text)

# Filter items with 10+ xrefs
important_items = [item for item in data if item["xref_count"] >= 10]

print(f"Found {len(important_items)} items with 10+ xrefs")
```

### Example 3: Export to CSV

```python
import csv
import json
import requests

# Fetch all data items
response = requests.get("http://127.0.0.1:8089/list_data_items_by_xrefs",
                       params={"limit": 50000, "format": "json"})
data = json.loads(response.text)

# Write to CSV
with open("data_by_xrefs.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Address", "Name", "Type", "Size", "Xref Count"])

    for item in data:
        writer.writerow([
            item["address"],
            item["name"],
            item["type"],
            item["size"],
            item["xref_count"]
        ])

print(f"Exported {len(data)} items to data_by_xrefs.csv")
```

## Testing

A comprehensive test suite is provided in `test_data_xrefs_tool.py`:

```bash
python test_data_xrefs_tool.py
```

This tests:
1. Text format output
2. JSON format output
3. Sorting correctness
4. Top items display

## Troubleshooting

### Issue: Tool returns unsorted data

**Cause:** Old plugin version still loaded in Ghidra.

**Solution:** Restart Ghidra to load the updated plugin (v1.7.4+).

### Issue: "No program loaded" error

**Cause:** No binary is open in Ghidra's CodeBrowser.

**Solution:** Open a program in Ghidra before using the tool.

### Issue: Empty results

**Cause:** Program has no defined data items.

**Solution:** Run Ghidra's auto-analysis or manually define data types.

## Version History

- **v1.7.4** (Current): Initial release of `list_data_items_by_xrefs`
  - Added xref count sorting
  - Added JSON output format
  - Optimized for large programs

## See Also

- `list_data_items`: Get all data items (unsorted, no xref counts)
- `get_xrefs_to`: Get detailed xrefs for a specific address
- `get_bulk_xrefs`: Get xrefs for multiple addresses efficiently
- `analyze_data_region`: Comprehensive data region analysis with xref mapping
