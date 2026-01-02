# String Labeling Workflow

## Objective

Rename ALL defined strings in the current Ghidra program with descriptive labels based on their usage and purpose, using Hungarian notation with semantic category prefixes.

## Workflow Steps

### Phase 1: Retrieve All Defined Strings

```
1. Use list_strings(offset=0, limit=5000) to get all defined strings
2. Note the total count for progress tracking
3. If more than 5000 strings, paginate with offset
```

### Phase 2: Categorize and Label Strings

For each string, analyze its content and determine the appropriate category:

```
1. Read the string content
2. Identify its purpose/usage:
   - Is it an API function name? -> szApi_
   - Is it a DLL name? -> szDllName_
   - Is it a file path? -> szPath_, szFmtPath_, szUIPath_
   - Is it an error message? -> szErr_, szCRT_
   - Is it a format string with %d, %s? -> szFmt_, szDbg_
   - Is it a UI/menu label? -> szMenu_, szOpt_, szUI_
   - Is it a source file path? -> szSrcFile_
   - Is it a date/time string? -> szMonth_, szDay_, szDateFormat_

3. Construct the label: sz[Category]_[Description]
4. Apply using batch_create_labels for efficiency
```

### Phase 3: Batch Application

```
1. Group strings by category (process 20-30 at a time)
2. Use batch_create_labels with array of {address, name} pairs
3. Track success/skip/fail counts
4. Continue until all strings are labeled
```

### Phase 4: Verification

```
1. Re-run list_strings to confirm labels applied
2. Check for any remaining unlabeled strings (s_*, DAT_*)
3. Apply labels to any missed strings
```

---

## Naming Convention Reference

### Structure

```
sz[Category]_[Description][Suffix]
```

| Component | Purpose | Example |
|-----------|---------|---------|
| `sz` | Type prefix (null-terminated string) | `sz` |
| `Category` | Functional domain | `Api`, `Err`, `Path` |
| `_` | Separator | `_` |
| `Description` | CamelCase name | `GetTickCount` |
| `Suffix` | Optional disambiguation | `Fmt`, `2`, `Alt` |

---

## Category Reference

### System/Runtime

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Win32 API names (GetTickCount, CreateFileA) | `szApi_` | `szApi_GetTickCount` |
| DLL names (kernel32.dll, user32.dll) | `szDllName_` | `szDllName_Kernel32` |
| CRT errors (R6025, R6028, runtime error) | `szCRT_` | `szCRT_R6025_PureVirtualCall` |
| SEH/Exception tables | `szSeh_` | `szSeh_RegistrationTable` |
| RTTI type names (.?AV, type_info) | `szRTTI_` | `szRTTI_TypeInfo` |
| C++ mangled names (?strlen@) | `szMangled_` | `szMangled_Unicode_strlen` |

### Paths and Files

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Static paths (Data\Global\) | `szPath_` | `szPath_GlobalMonsters` |
| Format paths with %s (%s\UI\%s) | `szFmtPath_` | `szFmtPath_LoadingScreen` |
| UI resource paths (Panel\, Menu\) | `szUIPath_` | `szUIPath_PanelInvChar` |
| Source file paths (..\Source\) | `szSrcFile_` | `szSrcFile_GfxUtil` |
| Filename constants (.txt, .dat) | `szFile_` | `szFile_D2MemTxt` |

### UI and Display

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Menu labels (Options, Previous) | `szMenu_` | `szMenu_Options` |
| Option names (Gamma, Contrast) | `szOpt_` | `szOpt_LightQuality` |
| UI element names | `szUI_` | `szUI_MiniPanel` |
| Window/dialog titles | `szTitle_` | `szTitle_DiabloII` |
| Screen identifiers | `szScreen_` | `szScreen_Screen01` |

### Format and Debug Strings

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Printf format (%d, %s, %f) | `szFmt_` | `szFmt_IPAddress` |
| Debug output formats | `szDbg_` | `szDbg_FpsSkipFmt` |
| Memory debug formats | `szMem_` | `szMem_TotalBlocksFmt` |

### Error and Warning Messages

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Error messages | `szErr_` | `szErr_FileOpen` |
| Warning messages | `szWarn_` | `szWarn_InsufficientMemory` |
| Security messages | `szSec_` | `szSec_BufferOverrun` |

### Date and Time

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Month names (January, February) | `szMonth_` | `szMonth_January` |
| Day names (Monday, Tuesday) | `szDay_` | `szDay_Monday` |
| Date formats (MM/dd/yy) | `szDateFormat_` | `szDateFormat_ShortDate` |
| Time formats (HH:mm:ss) | `szTimeFormat_` | `szTimeFormat_HHmmss` |

### Network and Multiplayer

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Battle.net strings | `szBnet_` | `szBnet_ChatPrefix` |
| Server IPs/addresses | `szServer_` | `szServer_BnetIP1` |
| Chat commands (/whisper) | `szChat_` | `szChat_Whisper` |
| Command strings | `szCmd_` | `szCmd_NoPickup` |

### Audio and Video

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Sound parameters (EAX, Reverb) | `szSound_` | `szSound_EaxReverb` |
| Video mode names | `szVideo_` | `szVideo_Direct3D` |
| Bink video files (.bik) | `szBik_` | `szBik_D2Intro` |
| Resolution strings | `szRes_` | `szRes_640x292` |

### Game-Specific

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Game strings | `szGame_` | `szGame_Expansion` |
| Item strings | `szItem_` | `szItem_Ethereal` |
| State strings | `szState_` | `szState_GameOver` |
| Pool names | `szPool_` | `szPool_ClientPoolSystem` |
| Automap strings | `szAutomap_` | `szAutomap_PartyNames` |
| Environment effects | `szEnv_` | `szEnv_Bubbles` |

### Compression/Library

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| zlib/inflate strings | `szZlib_` | `szZlib_StreamError` |

### Input/Cursor

| Content Pattern | Category | Example Label |
|-----------------|----------|---------------|
| Cursor names | `szCursor_` | `szCursor_Buysell` |
| Input types | `szInput_` | `szInput_Alphanumeric` |
| Mouse strings | `szMouse_` | `szMouse_WheelSupportMsg` |

---

## Suffix Reference

### Duplicate Handling

When identical strings appear at multiple addresses:
```
szOpt_SmallOff      # First instance
szOpt_SmallOff2     # Second instance
szOpt_SmallOff3     # Third instance
```

### Descriptive Suffixes

| Suffix | When to Use | Example |
|--------|-------------|---------|
| `Fmt` | Format strings | `szDbg_TileCacheFmt` |
| `Msg` | Message body | `szSecurity_BufferOverrunMsg` |
| `Title` | Dialog title | `szSecurity_BufferOverrunTitle` |
| `Dir` | Directory path | `szPath_MonstersDir` |
| `Alt` | Alternative version | `szApi_MessageBoxA_Alt` |
| `Upper` | Uppercase variant | `szDllName_Kernel32Upper` |
| `Lower` | Lowercase variant | `szDll_D2GameLower` |
| `Local` | Local/embedded copy | `szDllName_D2ClientLocal` |

---

## Quick Decision Tree

```
String Content                          -> Category Prefix
─────────────────────────────────────────────────────────
Contains ".dll" or ".DLL"               -> szDllName_
Matches Win32 API name                  -> szApi_
Starts with "R60" or "runtime error"    -> szCRT_
Starts with "..\Source\" or "SOURCE\"   -> szSrcFile_
Contains "\" path separators            -> szPath_ or szUIPath_ or szFmtPath_
Contains %d, %s, %f format specifiers   -> szFmt_ or szDbg_
Is a month name (January-December)      -> szMonth_
Is a day name (Sunday-Saturday)         -> szDay_
Starts with "/" (command)               -> szCmd_ or szChat_
Contains "error" or "failed"            -> szErr_
Contains IP address pattern             -> szServer_
Starts with "?" (C++ mangled)           -> szMangled_
Starts with ".?AV" (RTTI)               -> szRTTI_
Is menu/option label                    -> szMenu_ or szOpt_
Is video mode (DirectDraw, OpenGL)      -> szVideo_
Is sound parameter                      -> szSound_
Default fallback                        -> szGame_ or szStr_
```

---

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `list_strings` | Retrieve all defined strings with addresses |
| `batch_create_labels` | Apply labels efficiently in batches |
| `create_label` | Apply single label |
| `get_xrefs_to` | Analyze string usage context |
| `decompile_function` | Understand how string is used |

---

## Example Batch Label Application

```python
# Example batch for CRT error strings
labels = [
    {"address": "0x6fb7f5c0", "name": "szCRT_TlossError"},
    {"address": "0x6fb7f5d0", "name": "szCRT_SingError"},
    {"address": "0x6fb7f5e0", "name": "szCRT_DomainError"},
    {"address": "0x6fb7f5f0", "name": "szCRT_R6029_NetRuntimeError"},
    {"address": "0x6fb7f694", "name": "szCRT_R6028_HeapInitError"}
]
# Use batch_create_labels(labels)
```

---

## Completion Criteria

The workflow is complete when:

1. All strings from `list_strings` have labels starting with `sz`
2. No strings remain with default names (s_*, DAT_*, etc.)
3. Labels follow the category conventions documented above
4. Duplicate strings have numeric suffixes (2, 3, etc.)
5. All labels are searchable by category prefix
