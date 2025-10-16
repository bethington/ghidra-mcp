# Register Reuse Fix Guide

## Problem Overview

When compilers optimize code, they often reuse callee-saved registers (like EBP, EBX, ESI, EDI) as local variables after saving them on the stack. This pattern is very common in optimized binaries:

```assembly
PUSH EBP              ; Save EBP for later restoration
MOVZX EBP, word [...] ; Reuse EBP as a local variable!
; ... function body uses EBP as local variable
POP EBP               ; Restore original EBP value
```

**Ghidra's Problem**: The decompiler shows these reused registers as `unaff_EBP`, `unaff_EDI`, etc., which means "unaffected by the function call" - but this is misleading because they ARE affected, they're just being reused.

## Example from ProcessMouseClickUIEvent

### Assembly Pattern
```assembly
6fb4c86a: PUSH EBP                        ; Save EBP
6fb4c86b: MOVZX EBP,word ptr [EBX + 0xe] ; EBP = MouseY from event struct
6fb4c86f: PUSH EDI                        ; Save EDI
6fb4c870: MOVZX EDI,word ptr [EBX + 0xc] ; EDI = MouseX from event struct
...
6fb4ca97: POP EBP                         ; Restore EBP
6fb4ca6c: POP EDI                         ; Restore EDI
```

### Bad Decompilation (Before Fix)
```c
void ProcessMouseClickUIEvent(UIEventRecord *EventRecord) {
    uint32_t unaff_EBP;  // What is this??
    int unaff_EDI;       // What is this??

    // Code uses unaff_EBP and unaff_EDI everywhere
    SendCustomPacketWithFields((uint8_t)unaff_EDI, unaff_EBP);
}
```

### Good Decompilation (After Fix)
```c
void ProcessMouseClickUIEvent(UIEventRecord *EventRecord) {
    uint MouseY;  // Clear semantic meaning
    uint MouseX;  // Clear semantic meaning

    MouseY = EventRecord->MouseY;
    MouseX = EventRecord->MouseX;

    // Code now makes sense
    SendCustomPacketWithFields((uint8_t)MouseX, MouseY);
}
```

## Systematic Fix Process

### Step 1: Identify Register Reuse

Look for variables named `unaff_<REGISTER>` in the decompilation:
- `unaff_EBP` / `unaff_RBP`
- `unaff_EBX` / `unaff_RBX`
- `unaff_ESI` / `unaff_RSI`
- `unaff_EDI` / `unaff_RDI`

### Step 2: Analyze Assembly Usage

Examine the disassembly to understand what the register actually contains:

1. **Find the initialization**: Look for the first `MOV` or `MOVZX` that loads into the register
   ```assembly
   MOVZX EBP, word ptr [EBX + 0xe]  ; Loading a word from struct offset 0xe
   ```

2. **Identify the data type**:
   - `MOVZX` with `word ptr` → likely a `uint16_t` or coordinate
   - `MOV` with `dword ptr` → likely a `uint32_t` or pointer
   - `LEA` → definitely a pointer

3. **Check usage patterns**:
   - Used in comparisons? → likely a coordinate, counter, or bound
   - Used as memory base? → likely a pointer
   - Incremented/decremented? → likely a loop counter or index
   - Passed to functions? → check function parameters for hints

### Step 3: Determine Semantic Meaning

Look for context clues in the surrounding code:

**Example 1: Mouse Coordinates**
```assembly
MOVZX EBP, word ptr [EBX + 0xe]  ; Offset 0xe in UIEventRecord struct
MOVZX EDI, word ptr [EBX + 0xc]  ; Offset 0xc in UIEventRecord struct
CMP EDI, [GridLayoutTable3BaseY] ; Comparing with Y coordinate
CMP EBP, [GridLayoutTable3BaseX] ; Comparing with X coordinate
```
→ `EBP` is MouseY, `EDI` is MouseX (note: X and Y seem swapped in this code!)

**Example 2: Loop Counter**
```assembly
XOR ESI, ESI          ; ESI = 0
loop_start:
    INC ESI           ; ESI++
    CMP ESI, 0x10     ; while (ESI < 16)
    JL loop_start
```
→ `ESI` is a loop counter, could be named `itemIndex` or `loopCounter`

**Example 3: Pointer**
```assembly
LEA EBX, [ECX + 0x100]  ; Load address
MOV EAX, [EBX + 0x4]    ; Dereference with offset
```
→ `EBX` is a pointer, could be named `ptrData` or `nodePtr`

### Step 4: Choose Meaningful Names

Follow these naming conventions:

**For coordinates/positions:**
- `MouseX`, `MouseY`
- `ScreenX`, `ScreenY`
- `ClickX`, `ClickY`

**For indices/counters:**
- `itemIndex`, `slotIndex`
- `loopCounter`, `iterationCount`
- `arrayIndex`, `tableIndex`

**For pointers:**
- `ptrNode`, `ptrData`
- `nodePtr`, `dataPtr`
- `current`, `next` (for linked lists)

**For generic values:**
- `value`, `result`, `temp`
- `flags`, `state`, `mode`

### Step 5: Apply the Rename

Using the Ghidra MCP API:

```python
import requests

server = "http://127.0.0.1:8089"

# Rename a single variable
requests.post(f"{server}/rename_variable", json={
    'function_name': 'ProcessMouseClickUIEvent',
    'old_name': 'unaff_EBP',
    'new_name': 'MouseY'
})

requests.post(f"{server}/rename_variable", json={
    'function_name': 'ProcessMouseClickUIEvent',
    'old_name': 'unaff_EDI',
    'new_name': 'MouseX'
})
```

### Step 6: Verify the Fix

After renaming:
1. Check the decompilation - `unaff_` variables should be gone
2. Read through the function logic - does it make sense now?
3. Verify register types match usage (e.g., pointer vs integer)

## Automated Script Usage

The `fix_register_reuse.py` script automates this process:

```bash
# Fix the currently selected function in Ghidra
python fix_register_reuse.py --current

# Fix a specific function by address
python fix_register_reuse.py 0x6fb4c830

# Use a different Ghidra server
python fix_register_reuse.py --current --server http://127.0.0.1:8089
```

The script will:
1. Identify all `unaff_` variables
2. Analyze assembly to understand register usage
3. Suggest meaningful names based on patterns
4. Apply the renames automatically

## Common Patterns Reference

### Pattern 1: Event Record Processing
```assembly
PUSH EBP
MOV EBP, [EventStruct + offsetY]
PUSH EDI
MOV EDI, [EventStruct + offsetX]
```
→ `EBP` = Y coordinate, `EDI` = X coordinate

### Pattern 2: Loop with Index
```assembly
PUSH ESI
XOR ESI, ESI              ; ESI = 0
loop:
    ; ... loop body using ESI
    INC ESI
    CMP ESI, MaxCount
    JL loop
POP ESI
```
→ `ESI` = loop index/counter

### Pattern 3: Linked List Traversal
```assembly
PUSH EBX
MOV EBX, [ListHead]
traverse:
    TEST EBX, EBX         ; while (node != NULL)
    JZ done
    ; ... process node at EBX
    MOV EBX, [EBX + NextOffset]  ; node = node->next
    JMP traverse
done:
POP EBX
```
→ `EBX` = current node pointer

### Pattern 4: Accumulator
```assembly
PUSH EDI
XOR EDI, EDI              ; EDI = 0
; ... code that adds to EDI
ADD EDI, SomeValue
; ... more accumulation
ADD EDI, AnotherValue
POP EDI
```
→ `EDI` = accumulator/sum

## Troubleshooting

### Issue: Rename doesn't take effect

**Cause**: Ghidra's decompiler cache may be stale.

**Solution**:
1. Close and reopen the decompiler window in Ghidra
2. Or use `force_decompile` API endpoint
3. Or restart Ghidra (last resort)

### Issue: Multiple variables for the same register

**Cause**: Ghidra created both a named variable AND a `unaff_` variable.

**Solution**: Rename the `unaff_` version to match the named version, then delete duplicates.

### Issue: Wrong variable type after rename

**Cause**: Register was inferred as wrong type based on first usage.

**Solution**: Use `set_local_variable_type` to correct the type:
```python
requests.post(f"{server}/set_local_variable_type", json={
    'function_address': '0x6fb4c830',
    'variable_name': 'MouseY',
    'new_type': 'uint16_t'  # or 'uint32_t', 'void*', etc.
})
```

### Issue: Variable name conflicts with existing variable

**Cause**: The meaningful name you want is already taken.

**Solution**:
1. Check if the existing variable is actually the same thing
2. If so, delete the duplicate
3. If not, use a more specific name (e.g., `MouseY_coord` vs `MouseY_pixel`)

## Integration with Batch Function Documentation

When documenting functions systematically, include register reuse fixes:

```python
# 1. Analyze function
analysis = analyze_function_complete(function_name)

# 2. Fix register reuse first
fix_register_reuse(function_name)

# 3. Then document with meaningful names
document_function_complete(
    function_address=address,
    new_name="ProcessMouseClickUIEvent",
    variable_renames={
        "MouseY": "mouseY",  # Now using the fixed name
        "MouseX": "mouseX"
    },
    plate_comment="Process mouse click UI events..."
)
```

## Best Practices

1. **Fix register reuse BEFORE function documentation**
   - Makes variable naming much clearer
   - Prevents confusion during documentation

2. **Look at assembly context, not just decompilation**
   - Assembly shows the true register usage
   - Decompilation can be misleading before fixes

3. **Use consistent naming across similar functions**
   - If MouseX/MouseY in one event handler, use same in others
   - Helps pattern recognition when reading code

4. **Document register mappings in function comments**
   ```c
   /* Process mouse click UI events
      EBP = MouseY coordinate (from EventRecord+0xe)
      EDI = MouseX coordinate (from EventRecord+0xc)
      ESI = Audio context pointer
   */
   ```

5. **Verify types match usage**
   - Coordinates are usually `uint16_t` or `int`
   - Pointers should be typed correctly (`void*`, `Node*`, etc.)
   - Flags/modes are often `uint32_t` or enums

## References

- [Ghidra MCP API Documentation](../API_REFERENCE.md)
- [Function Documentation Workflow](./prompts/OPTIMIZED_FUNCTION_DOCUMENTATION.md)
- [Variable Storage Guide](./VARIABLE_STORAGE_GUIDE.md)
