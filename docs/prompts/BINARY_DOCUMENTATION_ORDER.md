# Binary Documentation Order

Recommended order for documenting Diablo II / PD2 binaries based on dependency analysis.

## Dependency Hierarchy

```
Tier 0 (Foundation - No Game Dependencies)
â””â”€â”€ Storm.dll      [1175 funcs] - MPQ archives, memory, networking, encryption

Tier 0.5 (Foundation - Built on Storm)
â””â”€â”€ Fog.dll        [799 funcs]  - Memory management, debugging, utilities

Tier 1 (Core Services)
â”œâ”€â”€ D2Lang.dll     [314 funcs]  - Localization, string tables
â””â”€â”€ D2CMP.dll      [632 funcs]  - Graphics data formats (DC6, DCC, DT1)

Tier 2 (Game Foundation)
â””â”€â”€ D2Common.dll   [2259 funcs] - ALL game structures (Units, Items, Skills, Stats)

Tier 3 (Subsystems)
â”œâ”€â”€ D2Sound.dll    [375 funcs]  - Audio (isolated, few dependencies)
â”œâ”€â”€ D2Win.dll      [804 funcs]  - UI foundation, window management
â”œâ”€â”€ D2Gfx.dll      [388 funcs]  - Graphics abstraction layer
â”œâ”€â”€ D2Gdi.dll      [~200 funcs] - GDI helpers used by windowing/graphics paths
â””â”€â”€ D2Net.dll      [290 funcs]  - Network abstraction

Tier 3.5 (Render Backends + Support Libraries)
â”œâ”€â”€ D2DDraw.dll    [329 funcs]  - DirectDraw render backend (used by D2Gfx/D2Client)
â”œâ”€â”€ D2Direct3D.dll [~300 funcs] - Direct3D render backend (used by D2Gfx/D2Client)
â”œâ”€â”€ D2Glide.dll    [~250 funcs] - Glide render backend wrapper (used by D2Gfx/D2Client)
â”œâ”€â”€ ddraw.dll      [system]     - System DirectDraw (Windows) dependency
â”œâ”€â”€ glide3x.dll    [3rd-party]  - Glide runtime used by D2Glide
â”œâ”€â”€ ijl11.dll      [3rd-party]  - Intel JPEG library (image decode paths)
â”œâ”€â”€ binkw32.dll    [3rd-party]  - Bink video playback
â””â”€â”€ SmackW32.dll   [3rd-party]  - Smacker video playback

Tier 4 (High-Level Systems)
â”œâ”€â”€ D2Multi.dll    [650 funcs]  - Multiplayer, lobbies, game creation
â”œâ”€â”€ D2Game.dll     [5042 funcs] - Server-side game logic
â””â”€â”€ D2Client.dll   [5366 funcs] - Client-side rendering, input, UI

Tier 5 (Entry Points)
â”œâ”€â”€ D2Launch.dll   [744 funcs]  - Launcher, initialization
â””â”€â”€ Game.exe       [384 funcs]  - Main executable, WinMain entry

Tier 5.5 (Battle.net / Online Services)
â”œâ”€â”€ Bnclient.dll   [~150 funcs] - Battle.net client library (auth/session)
â”œâ”€â”€ D2MCPClient.dll [~100 funcs] - Battle.net MCP client for Diablo II
â””â”€â”€ BH.dll         [varies]     - Battle.net helper/hosting glue (varies by build)

Tier 6 (PD2 Extensions)
â”œâ”€â”€ PD2_EXT.dll    [varies]     - PD2 mod extensions
â”œâ”€â”€ SGD2FreeRes.dll [varies]    - Resolution modifications
â””â”€â”€ SGD2FreeDisplayFix.dll [varies] - Display/compatibility fixes

Tier 7 (Modern Dependencies - Present in some distributions)
â””â”€â”€ libcrypto-1_1.dll [3rd-party] - OpenSSL crypto (present in some bundled builds)
```

## Recommended Processing Order

| Priority | Binary | Functions | Reason |
|----------|--------|-----------|--------|
| 1 | **Storm.dll** | 1,175 | Foundation - MPQ file handling, memory allocation, all DLLs depend on it |
| 2 | **Fog.dll** | 799 | Foundation - Memory management, debugging utilities, error handling |
| 3 | **D2Lang.dll** | 314 | Small, focused - Localization strings, minimal dependencies |
| 4 | **D2CMP.dll** | 632 | Graphics data - DC6/DCC/DT1 formats, needed by rendering |
| 5 | **D2Common.dll** | 2,259 | **CRITICAL** - All game structures, types, and enums defined here |
| 6 | **D2Sound.dll** | 375 | Isolated subsystem - Audio playback, easy to document in isolation |
| 7 | **D2Win.dll** | 804 | UI foundation - Window management, controls |
| 8 | **D2Gfx.dll** | 388 | Graphics abstraction - Rendering backends (DDraw, D3D, Glide) |
| 9 | **D2Gdi.dll** | ~200 | GDI glue - Helps clarify UI/2D rendering call paths |
| 10 | **D2Net.dll** | 290 | Network abstraction - Protocol handling |
| 11 | **D2Multi.dll** | 650 | Multiplayer - Battle.net, TCP/IP, lobbies |
| 12 | **Bnclient.dll** | ~150 | Battle.net library - Authentication/session support |
| 13 | **D2MCPClient.dll** | ~100 | Diablo II MCP client - Imported by D2Client/D2Launch/Game.exe |
| 14 | **D2Game.dll** | 5,042 | Server logic - Game simulation, AI, drops |
| 15 | **D2Client.dll** | 5,366 | Client logic - Rendering, input, UI interactions |
| 16 | **D2DDraw.dll** | 329 | Render backend - DirectDraw path (used via D2Gfx) |
| 17 | **D2Direct3D.dll** | ~300 | Render backend - Direct3D path (used via D2Gfx) |
| 18 | **D2Glide.dll** | ~250 | Render backend - Glide path (used via D2Gfx) |
| 19 | **ddraw.dll** | — | System dependency - Only analyze if tracing deep DirectDraw behavior |
| 20 | **glide3x.dll** | — | Third-party dependency - Only analyze if you need Glide internals |
| 21 | **ijl11.dll** | — | Third-party dependency - Image decode paths |
| 22 | **binkw32.dll** | — | Third-party dependency - Video playback |
| 23 | **SmackW32.dll** | — | Third-party dependency - Video playback |
| 24 | **D2Launch.dll** | 744 | Launcher - Entry point, initialization |
| 25 | **Game.exe** | 384 | Main executable - WinMain, process entry, DLL loading |
| 26 | **BH.dll** | varies | Battle.net helper - Useful for online flows when present |
| 27 | **PD2_EXT.dll** | varies | PD2 extensions - Mod-specific functionality |
| 28 | **SGD2FreeRes.dll** | varies | Resolution mod - Display modifications |
| 29 | **SGD2FreeDisplayFix.dll** | varies | PD2 display fix - Compatibility/display tweaks |
| 30 | **libcrypto-1_1.dll** | — | External crypto - Only if present/used in your build |

## Import Relationships

### Observed Inter-Binary Dependencies (LoD 1.07)

These are derived from each moduleâ€™s external locations (imports/externals) and focus on non-system DLLs.

- Fog.dll â†' Storm.dll
- D2Lang.dll â†' Storm.dll
- D2CMP.dll â†' Storm.dll
- D2Common.dll â†' Fog.dll, D2Lang.dll, D2CMP.dll
- D2Gfx.dll â†' Fog.dll, Storm.dll
- D2Net.dll â†' Fog.dll, Storm.dll
- D2Win.dll â†' Storm.dll
- D2Multi.dll â†' Fog.dll, Storm.dll
- D2Game.dll â†' D2Common.dll
- D2Client.dll â†' D2Common.dll, D2CMP.dll, D2Gfx.dll, D2Win.dll, D2Lang.dll, D2Net.dll, D2Sound.dll, Fog.dll, Storm.dll
- D2Launch.dll â†' D2Gfx.dll, D2Win.dll, D2Lang.dll, D2Net.dll, D2Sound.dll, Fog.dll, Storm.dll, D2MCPClient.dll
- Game.exe â†' D2Gfx.dll, D2Win.dll, D2Lang.dll, D2Net.dll, D2Sound.dll, Fog.dll, Storm.dll, D2MCPClient.dll

### Storm.dll Exports Used By All
- Memory: `SMemAlloc`, `SMemFree`, `SMemReAlloc`
- Files: `SFileOpenArchive`, `SFileReadFile`, `SFileCloseFile`
- Strings: `SStrCopy`, `SStrPack`, `SStrHash`
- Network: `SNet*` functions

### Fog.dll Exports
- Memory wrappers: `FogMemAlloc`, `ReleasePoolAllocation`
- Debugging: `FogAssert`
- Utilities: `QueueLogMessage`

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
- **Backends/support DLLs** - D2DDraw/D2Direct3D/D2Glide and codec/libs are usually only worth deep work when youâ€™re chasing a rendering/media issue
