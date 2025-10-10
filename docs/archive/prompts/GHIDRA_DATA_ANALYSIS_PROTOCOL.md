# Ghidra Data Analysis Protocol

## Overview

This document defines the comprehensive protocol for analyzing and typing global data in Ghidra using the MCP server tools. The protocol emphasizes complete structural analysis with byte-level accuracy.

## Initial State Assessment

### 1. Locate Current Cursor Position
- Identify the current cursor position in Ghidra using `get_current_address`
- Verify the data is a global variable or data region

### 2. Evaluate Existing Names
- Check if data already has a meaningful, descriptive name
- **Do not rename if already well-named** - verify accuracy instead
- Only rename if the current name is generic (e.g., `DAT_xxxxx`) or incorrect

## Naming Standards

### Variable Naming Convention
- **PascalCase only** - no prefixes (e.g., `FrameThresholdTable`, not `g_frameThresholdTable`)
- Names must reflect purpose and usage based on cross-reference analysis
- Follow best practices for reverse engineering naming

## Analysis Requirements

### Assembly Pattern Analysis
Examine assembly code to identify data structures:
- **LEA instructions** - pointer calculations, structure field access
- **Offset patterns** - repeated offsets indicate structure fields
- **Loop analysis** - identify array bounds and iteration patterns
- **CMP instructions** - bounds checks reveal array sizes

### Pre-Change Calculations
Before applying any types or names:
1. Calculate data strides (spacing between elements)
2. Determine structure sizes from access patterns
3. Calculate complete data spans from start to end boundaries
4. Document findings before making changes

### Decompilation Context
- Decompile all referencing functions
- Understand how data is used in context
- Identify field purposes from usage patterns

## Externally Referenced Data Block Analysis

### Critical Rule
**Any data with external references (xrefs) represents a complete data block that must be fully analyzed and typed.**

### Step 1: Identify Complete Data Region

#### Boundary Detection
The data block spans from:
- **Start**: The xref'd address (cursor position)
- **End**: The FIRST of:
  - Next address with an xref to a different data item, OR
  - Next known named label (non-default name), OR
  - End of defined data region

#### Byte Span Calculation
```
total_bytes = end_boundary_address - start_address
```

Example:
```
Start: 0x6fb835b8
End:   0x6fb835d4
Span:  0x6fb835d4 - 0x6fb835b8 = 0x1C bytes (28 decimal)
```

### Step 2: Byte-by-Byte Analysis

#### Enumerate Every Byte Address
Check xrefs for **EVERY SINGLE BYTE** in the span:
```
cursor+0:  0x6fb835b8
cursor+1:  0x6fb835b9
cursor+2:  0x6fb835ba
cursor+3:  0x6fb835bb
cursor+4:  0x6fb835bc
cursor+5:  0x6fb835bd
...
cursor+27: 0x6fb835d3
```

#### Multi-Byte Type Accounting
When a field is accessed as a multi-byte type:
- **DWORD at offset +12** occupies bytes `+12, +13, +14, +15`
- **WORD at offset +4** occupies bytes `+4, +5`
- **QWORD at offset +16** occupies bytes `+16, +17, +18, +19, +20, +21, +22, +23`

Each constituent byte must be accounted for in the structure definition.

#### Check Cross-References
For each byte address:
1. Query `get_xrefs_to(address)` or `get_bulk_xrefs(addresses)`
2. Document which bytes have references and which don't
3. Identify reference types (READ, WRITE, DATA, etc.)

### Step 3: Analyze Data Layout

#### Pattern Recognition
- **Repeating patterns**: Same access pattern at regular intervals = array
- **Related fields**: Different offsets accessed in same function = structure
- **Accessed as unit**: Multiple fields used together = single structure instance

#### Structure vs Array Decision
- **Array**: Repeating pattern with stride, accessed via loop/index
- **Structure**: Unique field access patterns, accessed via fixed offsets
- **Hybrid**: Array of structures (repeating multi-field pattern)

### Step 4: Create Complete Structure Definition

#### Mandatory Requirements
1. **NO GAPS**: Every byte from start to boundary must be defined
2. **Exact size match**: Structure size must equal calculated byte span
3. **All bytes accounted**: Named fields + unknown/padding = total bytes

#### Field Definition Strategy

##### For Bytes With Cross-References
Use descriptive names based on usage:
```c
struct DataBlock {
    dword dwResourceType;    // +0x00, referenced in LoadResource
    dword dwFlags;           // +0x04, checked in ValidateFlags
    void* pData;             // +0x08, pointer to data buffer
    dword dwSize;            // +0x0C, buffer size in bytes
};
```

##### For Bytes Without Cross-References
Use contextual placeholder names:
```c
struct DataBlock {
    dword dwKnownField;      // +0x00, accessed
    byte Unknown1;           // +0x04, no xref
    byte Padding2;           // +0x05, alignment
    word Reserved3;          // +0x06, no xref
    dword dwAnotherField;    // +0x08, accessed
};
```

Naming for unaccessed bytes:
- **Unknown1, Unknown2, ...** - purpose unclear
- **Unused1, Unused2, ...** - appears unused
- **Reserved1, Reserved2, ...** - possibly reserved for future use
- **Padding1, Padding2, ...** - structural alignment padding

#### Size Verification
Manually verify byte coverage:

Example for 16-byte (0x10) span:
```
Offset  | Field          | Size | Bytes Covered
--------|----------------|------|------------------
+0x00   | dwField1       | 4    | 0, 1, 2, 3
+0x04   | wField2        | 2    | 4, 5
+0x06   | Unknown1       | 1    | 6
+0x07   | Padding1       | 1    | 7
+0x08   | pPointer       | 4    | 8, 9, 10, 11
+0x0C   | dwField3       | 4    | 12, 13, 14, 15
--------|----------------|------|------------------
Total:  16 bytes         ✓ Matches 0x10 span
```

### Step 5: Apply Data Type

#### For Repeating Patterns (Arrays)
1. Create structure definition for single element
2. Calculate element count: `total_bytes / element_size`
3. Apply array type: `StructType[count]` at base address
4. **Do NOT apply to individual elements** - only the base

Example:
```python
# Create element structure
create_struct(
    name="FrameThresholdEntry",
    fields=[
        {"name": "dwMinTime", "type": "dword"},
        {"name": "dwMaxTime", "type": "dword"},
        {"name": "dwThreshold", "type": "dword"}
    ]
)

# Apply as array: 28 bytes ÷ 12 bytes/element = array[2]
create_array_type(base_type="FrameThresholdEntry", length=2)
apply_data_type(address="0x6fb835b8", type_name="FrameThresholdEntry[2]")
```

#### For Single-Instance Structures
1. Create structure definition spanning entire region
2. Apply structure type directly at base address
3. Verify applied size matches byte span

Example:
```python
# Create complete structure (28 bytes total)
create_struct(
    name="ConfigurationBlock",
    fields=[
        {"name": "dwVersion", "type": "dword"},      # +0x00, 4 bytes
        {"name": "dwFlags", "type": "dword"},        # +0x04, 4 bytes
        {"name": "Unknown1", "type": "dword"},       # +0x08, 4 bytes (no xref)
        {"name": "pDataPointer", "type": "void*"},   # +0x0C, 4 bytes
        {"name": "dwDataSize", "type": "dword"},     # +0x10, 4 bytes
        {"name": "Reserved1", "type": "dword"},      # +0x14, 4 bytes (no xref)
        {"name": "dwChecksum", "type": "dword"}      # +0x18, 4 bytes
    ]
    # Total: 7 fields × 4 bytes = 28 bytes ✓
)

apply_data_type(address="0x6fb835b8", type_name="ConfigurationBlock")
```

#### Never Leave as Standalone Primitives
❌ **WRONG**: Applying `dword` to an address with xrefs
```python
apply_data_type(address="0x6fb835b8", type_name="dword")  # Incomplete!
```

✓ **CORRECT**: Encapsulate in structure or array
```python
create_struct(name="DataBlock", fields=[...])
apply_data_type(address="0x6fb835b8", type_name="DataBlock")
```

## Data Typing Guidelines

### When to Set Types
- **Set**: Data is currently undefined or incorrectly typed
- **Skip**: Data already has correct type and name
- **Update**: Existing type is primitive but should be structure

### Adding Comments
Add end-of-line (EOL) comments with:
- Field position/offset
- Field meaning and purpose
- Valid ranges or constraints
- Relationships to other data

Example:
```
dwFrameCount: // +0x00, number of animation frames (1-255)
pTextureData: // +0x04, pointer to texture atlas
wTextureId:   // +0x08, texture lookup ID, references TextureTable
```

### Adjacent Data Preservation
- Check types and names of surrounding data
- Preserve existing correct types/names
- Don't modify adjacent data unless part of same structure

## Arrays and Tables

### Structure Definition First
1. Analyze repeating element pattern
2. Create structure for single element
3. Ensure structure size matches stride

### Element Count Calculation
Calculate from:
- **Bounds checks**: `CMP ECX, 10` → 10 elements
- **Total size**: `total_bytes / element_size`
- **Loop patterns**: Iteration count in referencing code

### Array Application
Apply array type at base address:
```python
create_array_type(base_type="ElementStruct", length=element_count)
apply_data_type(address="0x6fb80000", type_name="ElementStruct[element_count]")
```

**Do NOT apply to individual elements** - Ghidra will handle indexing.

## Function and Variable Renaming

### Discovered Functions
- Rename functions with descriptive PascalCase names
- Base names on functionality observed in decompilation
- Example: `FUN_006fb6a000` → `ProcessFrameThresholds`

### Variables and Parameters
- Rename local variables and parameters for clarity
- Use PascalCase convention
- Example: `local_10` → `FrameIndex`, `param_1` → `ThresholdData`

### Register Artifacts
- Rename significant register-based variables
- Example: `uVar1` → `ResourceType`, `iVar2` → `LoopIndex`

### Preservation Policy
- **Check existing names first**
- **Do not rename if already descriptive**
- Only change generic/auto-generated names (e.g., `FUN_`, `DAT_`, `local_`, `param_`)

## Execution Standards

### Silent Operation
- **Work silently** - no verbose status updates
- All changes applied directly in Ghidra
- **No file creation or editing** outside Ghidra

### Ghidra-Only Changes
- Use MCP tools exclusively: `create_struct`, `apply_data_type`, `rename_data`, `set_disassembly_comment`
- Do not create markdown files, documentation, or reports
- Do not edit source code files

### Quality Verification
Before completing:
1. Verify structure size matches byte span exactly
2. Confirm all bytes in range are accounted for
3. Check that applied type shows correct size in Ghidra
4. Validate no gaps exist in structure definition

## Summary Checklist

- [ ] Identified cursor position and current data state
- [ ] Checked for existing meaningful names (preserved if good)
- [ ] Analyzed assembly patterns (LEA, CMP, loops, offsets)
- [ ] Calculated data span from start to boundary
- [ ] Enumerated ALL byte addresses in span (cursor+0, +1, +2, ...)
- [ ] Checked xrefs for every single byte address
- [ ] Accounted for multi-byte type components (dword = 4 bytes, etc.)
- [ ] Identified pattern: array, structure, or hybrid
- [ ] Created complete structure definition with NO GAPS
- [ ] Verified structure size exactly matches byte span
- [ ] Applied appropriate type (array or structure)
- [ ] Added descriptive EOL comments
- [ ] Renamed functions/variables with PascalCase (if needed)
- [ ] Verified adjacent data preserved
- [ ] All work done silently in Ghidra using MCP tools only

## Example Workflow

### Scenario: 28-byte data block at 0x6fb835b8

1. **Get current address**: `0x6fb835b8`
2. **Check name**: `DAT_6fb835b8` (generic, needs rename)
3. **Analyze xrefs**: References from 2 functions
4. **Find boundary**: Next xref at `0x6fb835d4`
5. **Calculate span**: `0x6fb835d4 - 0x6fb835b8 = 0x1C (28 bytes)`
6. **Check each byte**:
   ```
   0x6fb835b8: xref from 0x6fb6cae9 (READ)
   0x6fb835b9: no xref
   0x6fb835ba: no xref
   0x6fb835bb: no xref
   0x6fb835bc: xref from 0x6fb6c9fe (READ)
   ... (continue for all 28 bytes)
   ```
7. **Identify pattern**: Two 12-byte elements + 4-byte header (or similar)
8. **Create structure**:
   ```python
   create_struct(
       name="FrameThresholdConfig",
       fields=[
           {"name": "dwConfigFlags", "type": "dword"},    # +0x00, 4 bytes
           {"name": "dwMinThreshold", "type": "dword"},   # +0x04, 4 bytes
           {"name": "dwMaxThreshold", "type": "dword"},   # +0x08, 4 bytes
           {"name": "pCallbackFunc", "type": "void*"},    # +0x0C, 4 bytes
           {"name": "dwReserved1", "type": "dword"},      # +0x10, 4 bytes
           {"name": "dwReserved2", "type": "dword"},      # +0x14, 4 bytes
           {"name": "dwChecksum", "type": "dword"}        # +0x18, 4 bytes
       ]
       # Total: 7×4 = 28 bytes ✓
   )
   ```
9. **Apply type**: `apply_data_type("0x6fb835b8", "FrameThresholdConfig")`
10. **Rename**: `rename_data("0x6fb835b8", "GlobalFrameConfig")`
11. **Verify**: Structure shows 28 bytes in Ghidra ✓

---

**Version**: 1.0
**Last Updated**: 2025-10-10
**Protocol Status**: Active
