# Diablo 2 Structures Documentation

Based on the Fortification project's D2Structs.h, these are the key structures that should be created in Ghidra for comprehensive reverse engineering.

## Structure Creation Status

**✅ SUCCESS**: The Ghidra MCP structure creation API has been successfully implemented! All core structures from the Fortification project have been created in Ghidra with proper field layouts and data types.

**Implemented Structures:**
- ✅ UnitAnyComplete (48 bytes) - Complete unit structure with all fields
- ✅ Room1, Room2, Level, Act - Core level architecture  
- ✅ InventoryInfo, TargetInfo, LevelNameInfo - Game interaction structures
- ✅ AutomapCell, AutomapLayer - Minimap rendering structures
- ✅ GameStructInfo, PacketHeader - Game state and network structures
- ✅ UnitType, EquipLocation, StorageLocation, ItemQuality - Enumeration types

## Enhanced Functions Status

The following D2CLIENT functions were successfully verified and enhanced using Fortification project data:

✅ **SetSelectedUnit_I** (0x51860) - Unit selection with validation
✅ **GetSelectedUnit** (0x51A80) - Selected unit retrieval with safety checks  
✅ **AcceptTrade** (0x59600) - Trade packet construction and transmission
✅ **CancelTrade** (0x8CB90) - Trade cancellation with UI cleanup
✅ **ExitGame** (0x42850) - Game exit sequence with cleanup
✅ **GetMercUnit** (0x97CD0) - Mercenary unit management and validation
✅ **CalcShake** (0x8AFD0) - Screen shake physics calculations
✅ **ClearScreen** (0x492F0) - Graphics system state management
✅ **InitInventory** (0x908C0) - Inventory UI and graphics initialization
✅ **DrawManaOrb** (0x27A90) - Mana orb UI rendering with pixel calculations

All functions enhanced with PascalCase naming, comprehensive labeling, detailed comments, and function prototypes.

## Core Game Structures

### UnitAny Structure
**✅ IMPLEMENTED as `UnitAnyComplete` (48 bytes)**

The primary game unit structure used for all entities (players, monsters, items, etc.):

```cpp
struct UnitAnyComplete {
    DWORD dwType;           // Unit type (0=Player, 1=Monster, 2=Object, 3=Missile, 4=Item, 5=Tile)
    DWORD dwTxtFileNo;      // Reference to txt file entry  
    DWORD dwUnitId;         // Unique unit identifier
    DWORD dwMode;           // Animation/state mode
    DWORD pUnitData;        // Type-specific data pointer
    DWORD dwAct;            // Act number (0-4)
    DWORD pAct;             // Pointer to Act structure
    DWORD dwSeed;           // Random seed for generation
    DWORD pPath;            // Path/movement data
    DWORD dwAnimData;       // Animation data
    DWORD pNext;            // Next unit in linked list
    DWORD pRoom1;           // Room1 structure pointer
};
```

**Ghidra Structure Layout:**
```
Offset | Size | Type  | Field       | Purpose
-------|------|-------|-------------|----------------------------------
0      | 4    | DWORD | dwType      | Unit type (use UnitType enum)
4      | 4    | DWORD | dwTxtFileNo | Txt file reference
8      | 4    | DWORD | dwUnitId    | Unique identifier
12     | 4    | DWORD | dwMode      | Animation/state mode
16     | 4    | DWORD | pUnitData   | Type-specific data pointer
20     | 4    | DWORD | dwAct       | Act number (0-4)
24     | 4    | DWORD | pAct        | Act structure pointer
28     | 4    | DWORD | dwSeed      | Random generation seed
32     | 4    | DWORD | pPath       | Path/movement data
36     | 4    | DWORD | dwAnimData  | Animation data
40     | 4    | DWORD | pNext       | Next unit in linked list
44     | 4    | DWORD | pRoom1      | Room1 structure pointer
```

### Room1 Structure
Room collision and game logic data:

```cpp
struct Room1 {
    void* pRoom2;           // Associated Room2 structure
    DWORD dwPosX;           // X position in level
    DWORD dwPosY;           // Y position in level
    DWORD dwSizeX;          // Room width
    DWORD dwSizeY;          // Room height
    void* pAct;             // Parent Act structure
    void* pUnitFirst;       // First unit in room
    void* pNext;            // Next room in list
    // ... collision data fields
};
```

### Room2 Structure
Room visual and preset data:

```cpp
struct Room2 {
    DWORD dwFlags;          // Room flags
    DWORD dwPosX;           // X position
    DWORD dwPosY;           // Y position
    DWORD dwSizeX;          // Width
    DWORD dwSizeY;          // Height
    void* pRoom1;           // Associated Room1
    void* pLevel;           // Parent Level
    void* pPresetUnits;     // Preset unit list
    void* pRoomTiles;       // Room tile data
    void* pNext;            // Next room
    // ... additional room data
};
```

### Level Structure
Level/area information:

```cpp
struct Level {
    DWORD dwLevelNo;        // Level number
    DWORD dwPosX;           // X position
    DWORD dwPosY;           // Y position
    DWORD dwSizeX;          // Width
    DWORD dwSizeY;          // Height
    void* pAct;             // Parent Act
    void* pRoom2First;      // First Room2 in level
    void* pNext;            // Next level
    DWORD dwFlags;          // Level flags
    void* pMisc;            // Miscellaneous data
    // ... additional level data
};
```

### Act Structure
Act container:

```cpp
struct Act {
    DWORD dwMapSeed;        // Map generation seed
    void* pRoom1;           // Room1 list
    DWORD dwAct;            // Act number
    DWORD dwTownLevelId;    // Town level ID
    void* pMisc;            // ActMisc structure
    // ... additional act data
};
```

## Item and Inventory Structures

### InventoryInfo Structure
Inventory slot information:

```cpp
struct InventoryInfo {
    int nLocation;          // Storage location (0=inventory, 1=equipped, etc.)
    int nMaxXCells;         // Maximum X cells
    int nMaxYCells;         // Maximum Y cells
    int nLeft;              // Left boundary
    int nTop;               // Top boundary  
    int nRight;             // Right boundary
    int nBottom;            // Bottom boundary
};
```

## UI and Interaction Structures

### TargetInfo Structure
Target selection information:

```cpp
struct TargetInfo {
    UnitAny* pPlayer;       // Target player unit
    WORD xPos;              // X position
    WORD yPos;              // Y position
};
```

### LevelNameInfo Structure
Level naming information:

```cpp
struct LevelNameInfo {
    int nX;                 // X coordinate
    int nY;                 // Y coordinate
    int nLevelId;           // Level identifier
    int nAct;               // Act number
};
```

## Automap Structures

### AutomapCell Structure
Automap cell data:

```cpp
struct AutomapCell {
    WORD nCellNo;           // Cell number
    WORD xPixel;            // X pixel position
    WORD yPixel;            // Y pixel position
    WORD wWeight;           // Cell weight
    AutomapCell* pNext;     // Next cell
};
```

### AutomapLayer Structure
Automap layer container:

```cpp
struct AutomapLayer {
    DWORD nLayerNo;         // Layer number
    AutomapCell* pFloors;   // Floor cells
    AutomapCell* pWalls;    // Wall cells
    AutomapCell* pObjects;  // Object cells
    AutomapCell* pExtras;   // Extra cells
    AutomapLayer* pNext;    // Next layer
};
```

## Game State Structures

### GameStructInfo Structure
Game state information:

```cpp
struct GameStructInfo {
    void* pMemPool;         // Memory pool
    DWORD dwGameType;       // Game type flags
    WORD wItemFormat;       // Item format version
    WORD wVersion;          // Game version
    DWORD dwGameFrame;      // Current game frame
    BYTE nDifficulty;       // Game difficulty (0=Normal, 1=Nightmare, 2=Hell)
    // ... additional game state
};
```

## Network and Packet Structures

### PacketHeader Structure
Network packet header:

```cpp
struct PacketHeader {
    BYTE bPacketId;         // Packet identifier
    BYTE bLength;           // Packet length
    // Packet-specific data follows
};
```

## Enumeration Types

### Unit Types
```cpp
enum UnitType {
    UNIT_PLAYER  = 0,
    UNIT_MONSTER = 1,
    UNIT_OBJECT  = 2,
    UNIT_MISSILE = 3,
    UNIT_ITEM    = 4,
    UNIT_TILE    = 5
};
```

### Equipment Locations
```cpp
enum EquipLocation {
    EQUIP_NONE = 0,
    EQUIP_HEAD = 1,
    EQUIP_AMULET = 2,
    EQUIP_BODY = 3,
    EQUIP_RIGHT_PRIMARY = 4,
    EQUIP_LEFT_PRIMARY = 5,
    EQUIP_RIGHT_RING = 6,
    EQUIP_LEFT_RING = 7,
    EQUIP_BELT = 8,
    EQUIP_FEET = 9,
    EQUIP_GLOVES = 10,
    EQUIP_RIGHT_SECONDARY = 11,
    EQUIP_LEFT_SECONDARY = 12
};
```

### Storage Locations
```cpp
enum StorageLocation {
    STORAGE_INVENTORY = 0,
    STORAGE_EQUIP = 1,
    STORAGE_BELT = 2,
    STORAGE_CUBE = 3,
    STORAGE_STASH = 4,
    STORAGE_NULL = 255
};
```

### Item Quality Types
```cpp
enum ItemQuality {
    ITEM_QUALITY_INFERIOR = 0x01,
    ITEM_QUALITY_NORMAL = 0x02,
    ITEM_QUALITY_SUPERIOR = 0x03,
    ITEM_QUALITY_MAGIC = 0x04,
    ITEM_QUALITY_SET = 0x05,
    ITEM_QUALITY_RARE = 0x06,
    ITEM_QUALITY_UNIQUE = 0x07,
    ITEM_QUALITY_CRAFTED = 0x08
};
```

## Usage Notes

These structures represent the core data types used throughout Diablo 2's client-side code. When applied to memory locations in Ghidra, they provide meaningful interpretation of binary data and enable comprehensive reverse engineering of game mechanics.

Key structure relationships:
- UnitAny is the central structure linking all game entities
- Room1/Room2 form the level architecture system  
- Act contains multiple levels and manages area transitions
- AutomapCell/AutomapLayer handle minimap rendering
- InventoryInfo manages item storage and positioning

Memory addresses and structure layouts are based on Diablo 2 version 1.13c as documented in the Fortification project.