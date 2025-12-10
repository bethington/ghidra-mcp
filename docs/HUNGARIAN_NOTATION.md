# Hungarian Notation Reference

Apply Hungarian notation prefixes matching the actual Ghidra data type. Normalize Windows SDK types to lowercase builtins first.

## Type Normalization

| Windows SDK | Ghidra Builtin |
|-------------|----------------|
| UINT, DWORD | uint |
| USHORT, WORD | ushort |
| BYTE | byte |
| BOOL | bool |
| LPVOID, PVOID | void * |
| LPCSTR | const char * |
| LPWSTR | wchar_t * |

## Primitive Types

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
| HANDLE | h | hProcess |

## Single Pointers

| Type | Prefix | Example |
|------|--------|---------|
| void * | p | pData |
| byte * | pb | pbBuffer |
| ushort * | pw | pwLength |
| uint * | pdw | pdwFlags |
| int * | pn | pnCounter |
| float * | pfl | pflValues |
| double * | pd | pdValues |
| char * (param) | lpsz | lpszFileName |
| char * (local) | sz | szBuffer |
| wchar_t * (param) | lpwsz | lpwszUserName |
| wchar_t * (local) | wsz | wszPath |
| struct * | p+Name | pUnitAny |

## Double Pointers

| Type | Prefix | Example |
|------|--------|---------|
| void ** | pp | ppData |
| byte ** | ppb | ppbBuffers |
| uint ** | ppdw | ppdwFlags |
| char ** (param) | pplpsz | pplpszArgv |
| char ** (local) | ppsz | ppszArgs |
| struct ** | pp+Name | ppPlayerNode |

## Const Pointers

| Type | Prefix | Example |
|------|--------|---------|
| const char * (param) | lpcsz | lpcszName |
| const char * (local) | csz | cszLabel |
| const void * | pc | pcData |
| const Type * | pc+prefix | pcdwFlags |

## Arrays (Stack)

| Type | Prefix | Example |
|------|--------|---------|
| byte[N] | ab | abEncryptionKey |
| ushort[N] | aw | awLookupTable |
| uint[N] | ad | adHashBuckets |
| int[N] | an | anCoordinates |

**Note**: Pointer parameters with array syntax use pointer prefix: `void foo(byte data[])` → `pbData`

## Globals

All globals require `g_` prefix:
- `g_dwProcessId` (uint)
- `g_szConfigPath` (string)
- `g_pMainWindow` (pointer)
- `g_ServiceStatus` (struct by value)

## Special Types

- Function pointers: `pfn` prefix for callbacks (`pfnCallback`), PascalCase for direct calls
- Structures (by value): camelCase without prefix (`unitAny`)

## Undefined Type Resolution

| Undefined | Resolve To |
|-----------|------------|
| undefined1 | byte |
| undefined2 | ushort/short |
| undefined4 | uint/int/float/pointer |
| undefined8 | double/ulonglong/longlong |
| undefined1[N] | byte[N] |
