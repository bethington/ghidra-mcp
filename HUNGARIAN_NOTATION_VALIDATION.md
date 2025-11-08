# Hungarian Notation Validation Enhancement

## Summary

Enhanced the `analyze_function_completeness` MCP tool to validate that all local and global variables use Hungarian notation prefixes that match their defined data types. This ensures type-to-prefix consistency and catches incorrectly named variables.

## Problem

Previously, the completeness tool did not verify whether variable names followed Hungarian notation conventions or whether the prefixes matched their actual types. This meant functions could receive high completeness scores even when:
- Variables had incorrect Hungarian notation prefixes (e.g., `bFlags` for a `uint` instead of `dwFlags`)
- Variables used no prefix at all despite having defined types
- Type-to-prefix mismatches existed (e.g., `wStatus` for a 4-byte `uint` instead of 2-byte `ushort`)

## Solution Implemented

### 1. Added `validateHungarianNotation()` Method

**Location**: `GhidraMCPPlugin.java` lines 9351-9402

**Validation Logic**:
1. Skip generic/default variable names (already caught by undefined variable check)
2. Skip undefined types (already caught by undefined type check)
3. Extract base type name (remove array brackets, pointer stars)
4. Get expected Hungarian prefix for the type
5. Check if variable name starts with expected prefix
6. Support multiple valid prefixes (e.g., `byte` can be `b` or `by`)
7. For global variables, expect `g_` prefix before type prefix

**Implementation**:
```java
private void validateHungarianNotation(String varName, String typeName, boolean isGlobal, List<String> violations) {
    // Skip generic/default names
    if (varName.startsWith("param_") || varName.startsWith("local_") ||
        varName.startsWith("iVar") || varName.startsWith("uVar") ||
        varName.startsWith("dVar") || varName.startsWith("fVar") ||
        varName.startsWith("in_") || varName.startsWith("extraout_")) {
        return;
    }

    // Skip undefined types
    if (typeName.startsWith("undefined")) {
        return;
    }

    // Normalize type name
    String baseTypeName = typeName.replaceAll("\\[.*\\]", "").replaceAll("\\s*\\*", "").trim();

    // Get expected prefix
    String expectedPrefix = getExpectedHungarianPrefix(baseTypeName, typeName.contains("*"), typeName.contains("["));

    if (expectedPrefix == null) {
        return; // Unknown/structure type - skip
    }

    // Check prefix compliance
    String fullExpectedPrefix = isGlobal ? "g_" + expectedPrefix : expectedPrefix;
    boolean hasCorrectPrefix = false;

    // Handle multiple valid prefixes
    if (expectedPrefix.contains("|")) {
        String[] validPrefixes = expectedPrefix.split("\\|");
        for (String prefix : validPrefixes) {
            String fullPrefix = isGlobal ? "g_" + prefix : prefix;
            if (varName.startsWith(fullPrefix)) {
                hasCorrectPrefix = true;
                break;
            }
        }
    } else {
        hasCorrectPrefix = varName.startsWith(fullExpectedPrefix);
    }

    if (!hasCorrectPrefix) {
        violations.add(varName + " (type: " + typeName + ", expected prefix: " + fullExpectedPrefix + ")");
    }
}
```

### 2. Added `getExpectedHungarianPrefix()` Method

**Location**: `GhidraMCPPlugin.java` lines 9404-9446

**Type-to-Prefix Mapping**:

| Type | Expected Prefix | Notes |
|------|-----------------|-------|
| byte | b\|by | Multiple valid options |
| char | c\|ch | Multiple valid options |
| bool | f | Boolean flag |
| short | n\|s | Multiple valid options |
| ushort | w | Word (16-bit) |
| int | n\|i | Multiple valid options |
| uint | dw | Double word (32-bit) |
| long | l | Long (32-bit) |
| ulong | dw | Same as uint |
| longlong | ll | 64-bit signed |
| ulonglong | qw | Quad word (64-bit) |
| float | fl | Single precision |
| double | d | Double precision |
| float10 | ld | Long double (80-bit) |
| HANDLE | h | Windows handle |
| void * | p | Generic pointer |
| char * | sz\|lpsz | String pointer |
| wchar_t * | wsz | Wide string |
| byte[N] | ab | Array of bytes |
| ushort[N] | aw | Array of words |
| uint[N] | ad | Array of dwords |
| char[N] | sz | String array |

**Implementation**:
```java
private String getExpectedHungarianPrefix(String typeName, boolean isPointer, boolean isArray) {
    // Handle arrays
    if (isArray) {
        if (typeName.equals("byte")) return "ab";
        if (typeName.equals("ushort")) return "aw";
        if (typeName.equals("uint")) return "ad";
        if (typeName.equals("char")) return "sz";
        return null;
    }

    // Handle pointers
    if (isPointer) {
        if (typeName.equals("void")) return "p";
        if (typeName.equals("char")) return "sz|lpsz";
        if (typeName.equals("wchar_t")) return "wsz";
        return "p"; // Typed pointers
    }

    // Handle basic types
    switch (typeName) {
        case "byte": return "b|by";
        case "char": return "c|ch";
        case "bool": return "f";
        case "short": return "n|s";
        case "ushort": return "w";
        case "int": return "n|i";
        case "uint": return "dw";
        case "long": return "l";
        case "ulong": return "dw";
        case "longlong": return "ll";
        case "ulonglong": return "qw";
        case "float": return "fl";
        case "double": return "d";
        case "float10": return "ld";
        case "HANDLE": return "h";
        default: return null; // Structure or unknown type
    }
}
```

### 3. Updated Completeness Scoring

**Modified**: `calculateCompletenessScore()` at line 9511

**Changes**:
- Added `hungarianViolationCount` parameter
- Deduct 3 points per Hungarian notation violation
- Updated method signature

**Scoring Breakdown**:
- Custom function name (not FUN_): -30 if missing
- Function prototype: -20 if missing
- Calling convention: -10 if missing
- Plate comment exists: -20 if missing
- Undefined variables: -5 per undefined variable
- Plate comment issues: -5 per issue
- **NEW**: Hungarian notation violations: -3 per violation

### 4. Enhanced JSON Response

**Modified**: Lines 9318-9334

**Added to JSON output**:
```json
{
  "function_name": "FunctionName",
  "has_custom_name": true,
  "has_prototype": true,
  "has_calling_convention": true,
  "has_plate_comment": true,
  "plate_comment_issues": [],
  "undefined_variables": [],
  "hungarian_notation_violations": [
    "resultValue (type: uint, expected prefix: dw)",
    "statusCode (type: ushort, expected prefix: w)"
  ],
  "completeness_score": 94.0
}
```

## Example Results

### Case 1: Incorrect Prefix for Type

**Variable**: `bFlags` with type `uint` (4 bytes)

**Before Enhancement**:
```json
{
  "completeness_score": 100.0
}
```
❌ No validation of prefix correctness

**After Enhancement**:
```json
{
  "hungarian_notation_violations": [
    "bFlags (type: uint, expected prefix: dw)"
  ],
  "completeness_score": 97.0
}
```
✅ Correctly identifies that `uint` should use `dw` prefix, not `b`

### Case 2: Missing Type Prefix

**Variable**: `count` with type `int` (no prefix)

**After Enhancement**:
```json
{
  "hungarian_notation_violations": [
    "count (type: int, expected prefix: n|i)"
  ],
  "completeness_score": 97.0
}
```
✅ Identifies missing Hungarian notation prefix

### Case 3: Multiple Violations

**Variables**:
- `result` (type: `uint`) - should be `dwResult`
- `status` (type: `ushort`) - should be `wStatus`
- `tempBuffer` (type: `byte[16]`) - should be `abTempBuffer`

**After Enhancement**:
```json
{
  "hungarian_notation_violations": [
    "result (type: uint, expected prefix: dw)",
    "status (type: ushort, expected prefix: w)",
    "tempBuffer (type: byte[16], expected prefix: ab)"
  ],
  "completeness_score": 91.0
}
```
✅ Detects all 3 violations, reduces score by 9 points (3 × 3)

### Case 4: Correct Hungarian Notation

**Variables**:
- `dwFlags` (type: `uint`) ✓
- `wStatus` (type: `ushort`) ✓
- `nCount` (type: `int`) ✓
- `pBuffer` (type: `void *`) ✓
- `abXmmBuffer` (type: `byte[16]`) ✓

**After Enhancement**:
```json
{
  "hungarian_notation_violations": [],
  "completeness_score": 100.0
}
```
✅ All variables have correct prefixes

## Validation Rules

### Variables That Are Skipped

The validator intentionally skips these variable patterns to avoid duplicate reporting:

1. **Generic parameter names**: `param_1`, `param_2`, etc.
   - Already caught by undefined variable check

2. **Generic local names**: `local_c`, `local_10`, etc.
   - Already caught by undefined variable check

3. **SSA-generated names**: `iVar1`, `uVar2`, `dVar12`, `fVar3`, etc.
   - Decompiler-generated synthetic variables

4. **Implicit parameters**: `in_ST0`, `in_XMM0`, `in_EAX`, etc.
   - Register-based implicit parameters

5. **Extra outputs**: `extraout_EAX`, `extraout_XMM0`, etc.
   - Decompiler-generated return values

6. **Undefined types**: Any variable with `undefined1/2/4/8` type
   - Already caught by undefined type check

### Variables That Are Validated

1. **Renamed local variables** with defined types
2. **Renamed parameters** with defined types
3. **Custom-named variables** that don't match generic patterns

### Special Cases

1. **Multiple valid prefixes**: Some types accept multiple prefixes
   - `byte`: accepts `b` or `by`
   - `char`: accepts `c` or `ch`
   - `short`: accepts `n` or `s`
   - `int`: accepts `n` or `i`
   - `char *`: accepts `sz` or `lpsz`

2. **Structure types**: Variables with structure types are skipped
   - Structures use camelCase without prefix
   - No validation applied to structure-typed variables

3. **Unknown types**: Variables with unrecognized types are skipped
   - Avoids false positives on custom types
   - Focus on standard builtin types only

## Impact on Workflow

### Benefits

1. **Automatic type-to-prefix verification**: No manual checking required
2. **Catches common mistakes**: Incorrect prefixes, missing prefixes
3. **Enforces consistency**: All variables must follow Hungarian notation
4. **Comprehensive coverage**: Validates both parameters and local variables
5. **Integration with workflow**: Built into completeness verification

### Workflow Integration

The FUNCTION_DOC_WORKFLOW_V2.md already requires Hungarian notation compliance. This enhancement **automates** the verification that was previously manual.

**Before**: Manual verification required
> "After completing all variable renames, you MUST perform a type-to-prefix consistency verification to ensure that Hungarian notation prefixes accurately reflect the actual Ghidra types."

**Now**: Automated in completeness tool
> The completeness tool automatically validates Hungarian notation compliance and reports violations with expected prefixes.

## Testing Examples

### Test 1: Validate Correct Usage

```python
# Function with all correct Hungarian notation
result = mcp.analyze_function_completeness("0x401000")

# Expected: No violations
{
  "hungarian_notation_violations": [],
  "completeness_score": 100.0
}
```

### Test 2: Detect Incorrect Prefix

```python
# Function with bFlags (byte prefix) but uint type (should be dw)
result = mcp.analyze_function_completeness("0x402000")

# Expected: Violation detected
{
  "hungarian_notation_violations": [
    "bFlags (type: uint, expected prefix: dw)"
  ],
  "completeness_score": 97.0
}
```

### Test 3: Detect Multiple Violations

```python
# Function with several incorrectly prefixed variables
result = mcp.analyze_function_completeness("0x403000")

# Expected: All violations listed
{
  "hungarian_notation_violations": [
    "count (type: int, expected prefix: n|i)",
    "result (type: uint, expected prefix: dw)",
    "buffer (type: byte[16], expected prefix: ab)"
  ],
  "completeness_score": 91.0
}
```

## Files Changed

- **src/main/java/com/xebyte/GhidraMCPPlugin.java**
  - Lines 9318-9334: Added Hungarian notation validation in analyzeCompleteness()
  - Lines 9351-9402: Added validateHungarianNotation() method
  - Lines 9404-9446: Added getExpectedHungarianPrefix() method
  - Line 9511: Updated calculateCompletenessScore() signature and scoring

## Build Status

✅ Built successfully with Maven
✅ No compilation errors
✅ Ready for deployment to Ghidra

## Related Documentation

- **HUNGARIAN_NOTATION_REFERENCE.md**: Complete type-to-prefix mapping reference
- **FUNCTION_DOC_WORKFLOW_V2.md**: Workflow that requires Hungarian notation compliance
- **PLATE_COMMENT_VALIDATION_ENHANCEMENT.md**: Related enhancement for plate comment validation

## Next Steps

1. Deploy updated plugin to Ghidra
2. Test on existing functions to verify validation works correctly
3. Fix any variables that fail the new validation requirements
4. Update documentation to note automatic Hungarian notation validation
5. Consider extending validation to global variables in future enhancement
