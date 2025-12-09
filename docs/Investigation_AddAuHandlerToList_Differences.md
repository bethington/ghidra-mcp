# Investigation: AddAuHandlerToList Function Differences Across Versions

## Summary
The AddAuHandlerToList function was suspected to have a symbol conflict (GetInstanceHandle vs GetLastError), but investigation revealed **the functions are legitimately different** between Storm.dll 1.07 and 1.08.

## Findings

### Storm.dll 1.07
- **Function Address**: 0x6ffc2f40
- **Callees**: GetProcessHeap, HeapAlloc, **GetInstanceHandle**
- **GetInstanceHandle** (0x6ffdba20):
  - Returns g_dwInstanceHandle (module HINSTANCE)
  - Set during DllMain initialization
  - Exported as Ordinal 302
  - Use: Get DLL module handle

### Storm.dll 1.08
- **Function Address**: 0x6ffc3050 (different location!)
- **Callees**: **GetLastError**, GetProcessHeap, HeapAlloc
- **GetLastError** (0x6ffdbfe0):
  - Returns g_dwLastError (error code)
  - Set by error handling functions
  - Exported as Ordinal 463
  - Use: Get last error code

## Root Cause
The function bodies are different between versions. This is a legitimate code change, not a symbol naming issue:
1. Different CALL instruction offsets within each function
2. Different target function being called (0x6ffdba20 vs 0x6ffdbfe0)
3. Different purposes (module instance vs error code)

## Symbol Conflict Clarification
- **Ordinal_577** is located at 0x6ffdb9a0 (NOT 0x6ffdba20)
- **Ordinal_577** is a string-to-number converter function (completely unrelated)
- **No actual symbol conflict exists** - the addresses are different
- Previous confusion arose from the similar ordinal numbers (577, 302, 463)

## Symbol Table Status
Both versions have clean, non-conflicting symbol tables:
- GetInstanceHandle @ 0x6ffdba20 (1.07 only) - unique symbol
- GetLastError @ 0x6ffdbfe0 (1.08) - unique symbol
- Ordinal_577 @ 0x6ffdb9a0 (both versions) - unique symbol

## Implications for Documentation Propagation
1. **Hash Matching Will Work Correctly**: Functions have different opcodes due to different calls, so hash-based matching will properly identify them as different in the hash index
2. **Offset-Based Globals Will Work**: Global references are captured by offset + operand, which works even when function addresses differ
3. **Called Function Propagation**: The propagation scripts should preserve correct function names since they reflect actual code differences
4. **No Symbol Conflict Fixing Needed**: The FixSymbolConflicts_ProjectFolder.java script is ready but not needed for this case

## Conclusion
The apparent difference (GetInstanceHandle vs GetLastError) is **not a symbol naming issue** but a **legitimate functional change** between Storm.dll 1.07 and 1.08. The documentation and function hash index should reflect these actual code changes.

---
**Investigation Date**: 2024
**Programs Analyzed**: Storm.dll 1.07, Storm.dll 1.08
**Status**: RESOLVED - Not a symbol conflict, legitimate code difference
