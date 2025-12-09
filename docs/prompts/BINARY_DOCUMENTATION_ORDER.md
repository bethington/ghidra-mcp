# Binary Documentation Order

Recommended order for documenting Diablo II / PD2 binaries based on dependency analysis.

## Dependency Hierarchy

```
Tier 0 (Foundation - No Game Dependencies)
├── Storm.dll      - MPQ archives, memory, networking, encryption
└── Fog.dll        - Memory management, debugging, utilities

Tier 1 (Core Services)
├── D2Lang.dll     - Localization, string tables
└── D2CMP.dll      - Graphics data formats (DC6, DCC, DT1)

Tier 2 (Game Foundation)
└── D2Common.dll   - ALL game structures (Units, Items, Skills, Stats)

Tier 3 (Subsystems)
├── D2Sound.dll    - Audio (isolated, few dependencies)
├── D2Win.dll      - UI foundation, window management
├── D2Gfx.dll      - Graphics abstraction layer
└── D2Net.dll      - Network abstraction

Tier 4 (High-Level Systems)
├── D2Multi.dll    - Multiplayer, lobbies, game creation
├── D2Game.dll     - Server-side game logic
└── D2Client.dll   - Client-side rendering, input, UI

Tier 5 (Entry Points)
├── D2Launch.dll   - Launcher, initialization
└── Game.exe       - Main executable, WinMain entry

Tier 6 (PD2 Extensions)
├── PD2_EXT.dll    - PD2 mod extensions
└── SGD2FreeRes.dll - Resolution modifications
```

## Recommended Processing Order

| Priority | Binary | Reason |
|----------|--------|--------|
| 1 | **Storm.dll** | Foundation - MPQ file handling, memory allocation, all DLLs depend on it |
| 2 | **Fog.dll** | Foundation - Memory management, debugging utilities, error handling |
| 3 | **D2Lang.dll** | Small, focused - Localization strings, minimal dependencies |
| 4 | **D2CMP.dll** | Graphics data - DC6/DCC/DT1 formats, needed by rendering |
| 5 | **D2Common.dll** | **CRITICAL** - All game structures, types, and enums defined here |
| 6 | **D2Sound.dll** | Isolated subsystem - Audio playback, easy to document in isolation |
| 7 | **D2Win.dll** | UI foundation - Window management, controls |
| 8 | **D2Gfx.dll** | Graphics abstraction - Rendering backends (DDraw, D3D, Glide) |
| 9 | **D2Net.dll** | Network abstraction - Protocol handling |
| 10 | **D2Multi.dll** | Multiplayer - Battle.net, TCP/IP, lobbies |
| 11 | **D2Game.dll** | Server logic - Game simulation, AI, drops |
| 12 | **D2Client.dll** | Client logic - Rendering, input, UI interactions |
| 13 | **D2Launch.dll** | Launcher - Entry point, initialization |
| 14 | **Game.exe** | Main executable - WinMain, process entry, DLL loading |
| 15 | **PD2_EXT.dll** | PD2 extensions - Mod-specific functionality |
| 16 | **SGD2FreeRes.dll** | Resolution mod - Display modifications |

## Import Relationships

### Storm.dll Exports Used By All
- Memory: `SMemAlloc`, `SMemFree`, `SMemReAlloc`
- Files: `SFileOpenArchive`, `SFileReadFile`, `SFileCloseFile`
- Strings: `SStrCopy`, `SStrPack`, `SStrHash`
- Network: `SNet*` functions

### Fog.dll Exports
- Memory wrappers: `Fog_Alloc`, `Fog_Free`
- Debugging: `Fog_Assert`, `Fog_Trace`
- Utilities: `Fog_GetErrorString`

### D2Common.dll Structures (Define First)
- `UnitAny` - Base unit structure (players, monsters, items, missiles, tiles)
- `StatList` - Stats and modifiers
- `Inventory` - Item storage
- `Path` - Pathfinding data
- `Room` / `Level` / `Act` - World structure
- `Skill` / `SkillList` - Skill system
- `Quest` / `QuestRecord` - Quest state

## Processing Strategy

1. **Start with Storm/Fog** - These provide foundational understanding of memory patterns and utility functions used everywhere.

2. **Document D2Common structures early** - Even if D2Common functions aren't fully documented, defining the structures (UnitAny, StatList, etc.) enables proper typing in all other DLLs.

3. **Work bottom-up** - Lower-tier DLLs inform understanding of higher-tier DLLs.

4. **Cross-reference ordinals** - Use `docs/KNOWN_ORDINALS.md` to identify imported functions by ordinal.

## Notes

- **D2Common is the keystone** - Most reverse engineering value comes from documenting D2Common structures accurately
- **Storm ordinals** - Many Storm functions are imported by ordinal, not name
- **Game.exe** - Thin loader that initializes DLLs; most logic is in DLLs
- **PD2 extensions** - PD2_EXT.dll adds functionality but follows same patterns
