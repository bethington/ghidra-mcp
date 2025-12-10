# LOOKUP_ORDINALS (Haiku Subtask)

Look up ordinal function calls in the KNOWN_ORDINALS reference.
This is a table lookup task - no semantic analysis required.

## Input

List of ordinal calls found in function:

```json
{
  "ordinals": [
    {"call": "Ordinal_10342"},
    {"call": "Ordinal_10918"},
    {"call": "Ordinal_99999"}
  ]
}
```

## Reference Tables

### D2Common.dll
| Ordinal | API | Params |
|---------|-----|--------|
| 10000 | GetUnitData | (pUnit) |
| 10001 | GetUnitRoom | (pUnit) |
| 10005 | GetUnitX | (pUnit) |
| 10006 | GetUnitY | (pUnit) |
| 10007 | GetUnitState | (pUnit, dwState) |
| 10017 | GetUnitStat | (pUnit, nStatId, nLayer) |
| 10029 | GetLevel | (pRoom) |
| 10042 | GetItemData | (nItemCode) |
| 10043 | GetSkillData | (nSkillId) |
| 10072 | GetUnitInventory | (pUnit) |
| 10107 | GetPlayerData | (pUnit) |
| 10109 | GetMonsterData | (pUnit) |
| 10111 | GetObjectData | (pUnit) |
| 10130 | GetUnitMode | (pUnit) |
| 10342 | GetUnitStat | (pUnit, nStatId) |
| 10469 | GetUnitOwner | (pUnit) |
| 10539 | GetNextInventoryItem | (pUnit, pItem) |
| 10918 | RandSeed | (pSeed) |
| 10949 | GetAreaId | (dwDefault) |

### D2Win.dll
| Ordinal | API | Params |
|---------|-----|--------|
| 10018 | GetMouseX | () |
| 10019 | GetMouseY | () |
| 10021 | DrawText | (lpszText, x, y, dwColor, bCenter) |
| 10024 | GetTextWidth | (lpszText) |
| 10025 | GetTextHeight | (lpszText) |
| 10034 | LoadCellFile | (lpszPath) |
| 10047 | DrawSprite | (pSprite, x, y) |
| 10117 | GetSystemTime | () |
| 10127 | FlushDrawBuffer | () |

### D2Client.dll
| Ordinal | API | Params |
|---------|-----|--------|
| 10000 | GetPlayerUnit | () |
| 10004 | GetDifficulty | () |
| 10011 | GetMouseItem | () |
| 10014 | GetCursorItem | () |
| 10020 | GetUIState | (nUIType) |

### D2Gfx.dll
| Ordinal | API | Params |
|---------|-----|--------|
| 10000 | GetHwnd | () |
| 10001 | GetScreenWidth | () |
| 10002 | GetScreenHeight | () |
| 10003 | GetWindowMode | () |
| 10007 | DrawLine | (x1, y1, x2, y2, dwColor) |
| 10010 | DrawRect | (x1, y1, x2, y2, dwColor) |
| 10014 | FlipSurface | () |

### Fog.dll
| Ordinal | API | Params |
|---------|-----|--------|
| 10000 | MemAlloc | (nSize, lpszFile, nLine, dwFlags) |
| 10001 | MemFree | (pMem, lpszFile, nLine, dwFlags) |
| 10002 | MemRealloc | (pMem, nSize, lpszFile, nLine) |
| 10019 | GetSystemInfo | () |
| 10021 | ErrorMsg | (lpszMsg, ...) |
| 10024 | LogMessage | (lpszFormat, ...) |
| 10042 | GetInstallPath | () |
| 10101 | EnterCriticalSection | (pLock) |
| 10102 | LeaveCriticalSection | (pLock) |

### Storm.dll
| Ordinal | API | Params |
|---------|-----|--------|
| 401 | SMemAlloc | (nSize, lpszFile, nLine, dwFlags) |
| 403 | SMemFree | (pMem, lpszFile, nLine, dwFlags) |
| 421 | SStrCopy | (lpszDest, lpszSrc, nMaxLen) |
| 501 | SFileOpenArchive | (lpszPath, dwPriority, dwFlags, phArchive) |
| 502 | SFileCloseArchive | (hArchive) |
| 503 | SFileOpenFile | (lpszName, phFile) |
| 504 | SFileCloseFile | (hFile) |
| 505 | SFileGetFileSize | (hFile, pdwHigh) |
| 506 | SFileReadFile | (hFile, pBuffer, nSize, pdwRead, dwFlags) |

## Task

For each ordinal in input:
1. Extract the number from `Ordinal_NNNNN`
2. Look up in reference tables above
3. If found: return API name and DLL
4. If not found: add to "unknown" list

## Output Format

```json
{
  "mappings": [
    {
      "ordinal": "Ordinal_10342",
      "dll": "D2Common",
      "api": "GetUnitStat",
      "params": "(pUnit, nStatId)",
      "comment": "/* D2Common.GetUnitStat */"
    },
    {
      "ordinal": "Ordinal_10918", 
      "dll": "D2Common",
      "api": "RandSeed",
      "params": "(pSeed)",
      "comment": "/* D2Common.RandSeed */"
    }
  ],
  "unknown": [
    {"ordinal": "Ordinal_99999", "comment": "/* Unknown ordinal */"}
  ]
}
```

## Rules

1. Match ordinal numbers exactly
2. Generate comment in format `/* DLL.APIName */`
3. Unknown ordinals go in separate list
4. Do NOT guess API names for unknown ordinals
