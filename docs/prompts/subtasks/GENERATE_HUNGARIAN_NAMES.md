# GENERATE_HUNGARIAN_NAMES (Haiku Subtask)

Apply Hungarian notation prefixes to generate new variable names.
This is a lookup/rule-application task - no semantic analysis required.

## Input

JSON with variables and their resolved types:

```json
{
  "variables": [
    {"name": "param_1", "resolved_type": "UnitAny *"},
    {"name": "local_c", "resolved_type": "uint"},
    {"name": "iVar1", "resolved_type": "int"}
  ],
  "globals": [
    {"name": "DAT_6fbf42a0", "resolved_type": "uint", "purpose": "flags"},
    {"name": "s_Error_6fbe1234", "resolved_type": "char *", "purpose": "error message"}
  ]
}
```

## Prefix Rules

### Primitives
| Type | Prefix | Example |
|------|--------|---------|
| byte | b/by | byFlags |
| char | c/ch | chInput |
| bool | f | fEnabled |
| short | n/s | nIndex |
| ushort | w | wCount |
| int | n/i | nResult |
| uint | dw | dwFlags |
| long | l | lOffset |
| ulong | dw | dwSize |
| longlong | ll | llTimestamp |
| ulonglong | qw | qwAddress |
| float | fl | flRatio |
| double | d | dPrecision |
| float10 | ld | ldExtended |

### Pointers
| Type | Prefix | Example |
|------|--------|---------|
| void * | p | pData |
| byte * | pb | pbBuffer |
| ushort * | pw | pwLength |
| uint * | pdw | pdwFlags |
| int * | pn | pnCounter |
| char * | sz/lpsz | szBuffer (local), lpszName (param) |
| wchar_t * | wsz/lpwsz | wszPath (local), lpwszName (param) |
| struct * | p+Name | pUnitAny, pPlayerData |
| void ** | pp | ppData |
| struct ** | pp+Name | ppUnitAny |

### Arrays
| Type | Prefix | Example |
|------|--------|---------|
| byte[N] | ab | abBuffer |
| ushort[N] | aw | awTable |
| uint[N] | ad | adHashes |
| int[N] | an | anCoords |

### Globals
All globals get `g_` prefix:
- `g_dwFlags` (uint)
- `g_pConfig` (pointer)
- `g_szPath` (string)

### Strings
- `s_*` globals → `sz` + descriptive name (e.g., `szErrorMessage`)

## Task

For each variable/global:
1. Look up the prefix for its `resolved_type`
2. Generate a meaningful name using the prefix
3. For parameters: use descriptive names based on type (pUnit, dwFlags, nCount)
4. For locals: use context from `purpose` field if provided
5. For globals: always include `g_` prefix

## Name Generation Guidelines

When `purpose` is not provided, generate names from type:
- `UnitAny *` → `pUnit`
- `uint` (flags context) → `dwFlags`
- `int` (loop/index context) → `nIndex` or `nCount`
- `char *` → `szBuffer` or `lpszText`
- `void *` → `pData` or `pBuffer`

## Output Format

```json
{
  "variable_renames": [
    {"old": "param_1", "new": "pUnit", "type": "UnitAny *"},
    {"old": "local_c", "new": "dwFlags", "type": "uint"},
    {"old": "iVar1", "new": "nIndex", "type": "int"}
  ],
  "global_renames": [
    {"old": "DAT_6fbf42a0", "new": "g_dwFlags", "type": "uint"},
    {"old": "s_Error_6fbe1234", "new": "szErrorMessage", "type": "char *"}
  ]
}
```

## Rules

1. Every input variable MUST have an output rename
2. Prefix MUST match the type exactly
3. Use camelCase for the descriptive part
4. Globals always start with `g_`
5. Do NOT add semantic meaning not present in input
