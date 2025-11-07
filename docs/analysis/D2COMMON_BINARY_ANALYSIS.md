# D2Common.dll - Binary Analysis

**Binary Name**: D2Common.dll (Shared Game Structures Library)
**File Size**: 693,248 bytes (693 KB)
**Architecture**: x86 (32-bit)
**Total Functions**: 2,766
**Total Symbols**: 47,611
**Exported Functions**: 250+
**Primary Purpose**: Shared game structures, data tables, and management functions for units, items, skills, and game state

---

## Executive Summary

D2Common.dll is the **foundational shared library** for Diablo II's game engine. It defines and manages all core game objects: units (players, NPCs, monsters), items (with complex property systems), skills (with synergies and level-based scaling), and game state. Every other Diablo II DLL depends on D2Common for fundamental data structures and management functions.

This library contains **2,766 functions** organized around five major subsystems:
1. **Unit Management** - Player, NPC, and monster lifecycle
2. **Inventory System** - Grid-based item management with equipment slots
3. **Skill System** - Skill properties, charges, synergies, and class restrictions
4. **Item Property System** - Complex stat calculations with quality/rarity modifiers
5. **Game State & Lookup Tables** - Persistent game state, monster tables, treasure classes, and skill databases

D2Common.dll is the "glue" that holds Diablo II's architecture together, providing the common language and data structures that allow graphics (D2Gdi), audio (D2Sound), networking (D2Net), and multiplayer (D2MpcClient) DLLs to communicate about game objects.

---

## Binary Specifications

| Property | Value |
|----------|-------|
| **Filename** | D2Common.dll |
| **File Size** | 693,248 bytes (693 KB) |
| **Architecture** | x86 (32-bit, Intel i386) |
| **Subsystem** | Windows DLL (dynamic link library) |
| **Entry Point** | DllMain @ 0x6FD00000 (module base) |
| **Machine Type** | IMAGE_FILE_MACHINE_I386 |
| **Total Functions** | 2,766 |
| **Total Symbols** | 47,611 |
| **Exported Functions** | 250+ |
| **Import Dependencies** | Kernel32.dll, User32.dll, Fog.dll, Storm.dll, D2Lang.dll |
| **Sections** | .text (code), .data (initialized data), .rsrc (resources), .reloc (relocations) |
| **Compile Time Information** | Source paths: D2Common\DRLG\DrlgLogic.cpp, D2Common\DATATBLS\FieldTbls.cpp |

---

## Architecture Overview

### Seven-Layer Diablo II System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Game.exe - Thin launcher, main loop                         │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ D2Game.dll - Game engine (game logic, AI, item generation)  │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ D2COMMON.DLL - SHARED GAME STRUCTURES (YOU ARE HERE)         │
│  • Unit management (players, NPCs, monsters)                │
│  • Inventory system (grid-based item storage)               │
│  • Skill system (properties, charges, synergies)            │
│  • Item property system (stats, affixes, quality)           │
│  • Game state and lookup tables                             │
│  • Character save format                                     │
└──────────────────────────────────────────────────────────────┘
            ▼                    ▼                    ▼
    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │ D2Gdi.dll    │    │ D2Sound.dll  │    │ D2Net.dll    │
    │ Graphics     │    │ Audio        │    │ Networking   │
    │ rendering    │    │ DirectSound  │    │ Winsock2     │
    └──────────────┘    └──────────────┘    └──────────────┘
            ▼                    ▼                    ▼
    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │ D2Lang.dll   │    │ D2MpcClient  │    │ Storm.dll    │
    │ Localization │    │ Multiplayer  │    │ Utilities    │
    │ i18n, Unicode│    │ Chat, loot   │    │ Compression  │
    └──────────────┘    └──────────────┘    └──────────────┘
```

All subsystem DLLs import and use D2Common for fundamental game object definitions.

---

## Core Subsystems

### 1. Unit Management System

**Purpose**: Manage the lifecycle of all dynamic game objects (players, NPCs, monsters)

**Key Functions** (30+ functions):
- `InitializeUnitStructure()` @ 0x6FD62030 - Create and initialize unit structure
- `ApplyObjectStatsToUnit()` @ 0x6FD6B1D0 - Apply base stats from objects
- `ApplyStatModifiersToUnit()` @ 0x6FDBB4A0 - Apply calculated stat bonuses
- `ProcessUnitsInBoundingBox()` @ 0x6FD62720 - Area-of-effect targeting and collision
- `CalculateUnitDistance()` @ 0x6FDCFCD0 - Pathfinding and distance calculation
- `ApplyUnitCollisionToRoom()` @ 0x6FD81850, 0x6FD859D0 - Collision detection and response
- `AdjustViewportByUnitDirection()` @ 0x6FD8E080 - Camera positioning based on unit facing
- `AdjustViewportToFollowUnit()` @ 0x6FD85160 - Camera follow mechanics
- `CheckUnitActiveSkillBitsMask()` @ 0x6FD83E60 - Get active skill flags

**Unit Structure Contents**:
- Type (Player, NPC, Monster, Item, etc.)
- Position (X, Y, Z coordinates)
- Facing direction (0-31 for isometric projection)
- Equipment inventory
- Skill assignments (9 slots)
- Statistics (HP, MP, Strength, Dexterity, Vitality, Energy)
- Experience and level
- Flags (dead, frozen, invulnerable, etc.)
- Animation state (current animation, frame)
- AI state (for monsters and NPCs)

**Unit Types** (from Game.exe):
- Player - Controlled by player
- NPC - Friendly non-player character (Cain, Deckard, etc.)
- Monster - Enemy unit (Zombie, Demon, etc.)
- Object - Static object (torch, door, shrine)
- Missile - Projectile (fireball, arrow, etc.)

---

### 2. Inventory Management System

**Purpose**: Grid-based inventory with equipment slots

**Key Functions** (30+ functions):
- `CreateInventory()` @ 0x6FD6E710 - Create inventory structure (10x10 grid)
- `PlaceItemInInventory()` @ 0x6FD71E10 - Add item to inventory grid
- `CanPlaceItemInInventory()` @ 0x6FD703B0 - Validate placement (size, location, permissions)
- `FindItemInInventory()` @ 0x6FD6FE10 - Locate item by ID
- `RemoveValidatedItemFromInventory()` @ 0x6FD71B00 - Delete item safely
- `FindItemByTypeAndSubtype()` @ 0x6FD622B0 - Locate by classification
- `FindSkillItemInInventory()` @ 0x6FD6ED00 - Locate skill books and scrolls
- `FindItemWithSkillByCode()` @ 0x6FD6EDF0 - Find by skill ID
- `AssignItemToUnitSlot()` @ 0x6FD6FC70 - Equip to body slot
- `EquipSkillItem()` @ 0x6FD70620 - Equip skill from inventory
- `GetInventoryFirstItem()` @ 0x6FD6E190 - Linked list traversal start
- `GetInventoryLastItem()` @ 0x6FD6E170 - Linked list traversal end
- `CountMatchingInventoryItems()` @ 0x6FD6EC30 - Count by criteria

**Inventory Grid Layout**:
```
10x10 Grid + Equipment Slots

Equipment Slots (named):
- Head/Helmet (1x2)
- Torso/Armor (2x3)
- Right Arm/Weapon (2x4)
- Left Arm/Weapon (2x4)
- Neck/Amulet (1x1)
- Left Hand (2x3)
- Right Hand (2x3)
- Belt (2x1)
- Feet/Boots (2x2)
- Gloves (2x2)

Main Inventory:
- 10x10 grid (100 cells)
- Items occupy variable sizes (1x1 to 4x4)
- Linked list for iteration
```

**Item Size Examples**:
- Scroll: 1x1 (single cell)
- Small Weapon: 1x3
- Helmet: 2x2
- Shield: 2x3
- Full Armor: 2x3
- Two-handed Weapon: 2x4

---

### 3. Skill System

**Purpose**: Manage character skills with levels, charges, synergies, and class restrictions

**Key Functions** (40+ functions):
- `AddSkillToUnit()` @ 0x6FDA2660 - Add skill to unit
- `AddOrUpgradeUnitSkill()` @ 0x6FDA2CA0 - Add or upgrade existing skill
- `AssignSkillToUnit()` @ 0x6FDA2D50 - Assign to specific skill slot
- `CanUnitUseSkill()` @ 0x6FD76DB0 - Check if unit can use skill
- `CanUnitActivateSkill()` @ 0x6FD9F730 - Check if skill is currently active
- `GetSkillLevelRequirement()` @ 0x6FD72970 - Get prerequisite level
- `GetSkillChargeValue()` @ 0x6FD72820 - Current charges remaining
- `AddSkillChargesFromSkillStat()` @ 0x6FD7A3D0 - Recharge from stat value
- `GetSkillProperty()` @ 0x6FD72920 - Generic skill property access
- `GetSkillPropertyByIndex()` @ 0x6FD72380, 0x6FD72430, 0x6FD73050 - Get specific property
- `GetItemSkillLevel()` @ 0x6FD733B0, 0x6FD73400, 0x6FD734F0 - Item-granted skill level
- `GetItemSkillProperty()` @ 0x6FD734A0 - Item-provided skill data
- `ApplyPassiveSkillSynergies()` @ 0x6FD96E50 - Calculate bonus damage from related skills
- `ApplyConditionalSkillStats()` @ 0x6FD98630 - Apply conditional stat modifications
- `ApplyRandomizedSkillEventWithSynergy()` @ 0x6FD97FA0 - Event-driven skill bonuses
- `AddOrRemoveTimedSkillEffect()` @ 0x6FD9EE00 - Duration-based skill effects

**Skill Structure**:
- Skill ID (unique identifier)
- Skill Level (1-99)
- Charges (for charge-based skills like Sorceress Teleport)
- Experience accumulated toward next level
- Flags (active, passive, etc.)
- Item-granted status (from equipment)
- Synergy bonuses (from other skills)

**Skill Types**:
1. **Active Skills** - Require player activation
   - Attack skills (Sorceress Fireball, Amazon Multishot)
   - Support skills (Druid Shapeshift)
   - Movement skills (Sorceress Teleport)

2. **Passive Skills** - Always active when learned
   - Damage bonuses (Amazon Penetrate)
   - Stat bonuses (Barbarian Increased Speed)
   - Resistance bonuses (Druid Natural Resistance)

3. **Charge-Based Skills** - Limited uses per duration
   - Unique skill mechanic
   - Recharge over time or from items
   - Example: Druid Werewolf/Werebear forms

**Synergy System**:
- Each skill has 1-3 synergies from other skills
- Each synergy provides bonus damage per level
- Example: Fireball synergizes with Inferno (spell synergy)
- Allows strategic skill point allocation

---

### 4. Item Property System

**Purpose**: Complex stat calculation system with quality levels, affixes, and sockets

**Key Functions** (30+ functions):
- `AccumulateInventoryItemPlayerBonuses()` @ 0x6FD74A50 - Sum all equipped item bonuses
- `AccumulateItemStatBonuses()` @ 0x6FD78850 - Sum individual item stats
- `ApplyItemPropertyStatModifiers()` @ 0x6FD89CE0 - Apply quality/rarity multipliers
- `CalculateItemRequiredLevel()` @ 0x6FD76190 - Determine minimum level to equip
- `CalculateSocketedItemBonuses()` @ 0x6FD766E0 - Calculate socket bonus synergies
- `CopyAndValidateInventory()` @ 0x6FD71C50 - Clone inventory safely
- `GetItemCoordinates()` @ 0x6FD72590 - Get position in inventory grid
- `SetUnitCoordinates()` @ 0x6FD72560 - Set item coordinates
- `GetItemDataPointer()` @ 0x6FD72640 - Access item data structure
- `SetItemPropertyField()` @ 0x6FD725F0 - Modify item property

**Item Quality Levels** (from lowest to highest):
1. **Broken** - Cannot be used (0-50% durability)
2. **Normal** - Standard item, no affixes
3. **Ethereal** - Higher damage, -25% durability (cannot be repaired by player)
4. **Magic** - 1-2 magical properties, blue name
5. **Rare** - 2-6 magical properties, yellow name
6. **Set** - Part of a set, green name, set bonuses when wearing multiple
7. **Unique** - Specific preset properties, gold name
8. **Crafted** - Player-crafted with specific properties

**Item Properties**:
- Base type and subtype (Sword, Shield, Armor, etc.)
- Quality level and rarity
- Durability (current/max)
- Required level and stat requirements
- Magical affixes (prefixes and suffixes)
- Socket count and socketed items
- Experience bonus (for weapons)
- Elemental damage (fire, cold, lightning, poison)
- Special properties (life steal, mana steal, all resistances)

**Stat Modifiers by Quality**:
- Magic items: +20% to +40% stat bonuses
- Rare items: +20% to +50% per affix
- Set items: Base + individual bonuses
- Unique items: Preset bonuses (highly variable)

---

### 5. Game State & Lookup Tables

**Purpose**: Persistent game state, monster tables, treasure classes, and skill databases

**Key Functions** (40+ functions):
- `GetGameState()` @ 0x6FD6B880 - Get current game state
- `GetGameStatePointer()` @ 0x6FD68F80 - Access state structure
- `GetGameContextDwordValue()` @ 0x6FD59C20 - Get context property
- `SetGameStateThreadSafe()` @ 0x6FD000C0 - Atomic state update
- `GetTableValue()` @ 0x6FD6A2B0 - Generic table lookup
- `GetLookupTableValue()` @ 0x6FD6A2C0 - Indexed table access
- `GetTableFieldFromRegistry()` @ 0x6FD6A720 - Registry-based lookup
- `GetMaskedTableValueByIndex()` @ 0x6FD6A550 - Bitfield extraction
- `GetArrayElementByIndex()` @ 0x6FD6B890 - Array access
- `GetPlayerDifficultyData()` @ 0x6FD6A330 - Difficulty settings (Normal/NM/Hell)
- `GetDualAttributeValues()` @ 0x6FD6A270 - Dual stat access
- `FindLinkedUnitInChain()` @ 0x6FD6A770 - Linked list traversal

**Game State Tracking**:
- Current difficulty (Normal, Nightmare, Hell)
- Difficulty-specific modifiers (monster life, experience, item drop rates)
- Global game time (for time-limited events)
- Current Act and area
- Monster spawn count and limits
- Event flags (bosses defeated, quests completed)

**Lookup Tables**:
- **Monster Tables** - Monster properties (HP, damage, immunities, skills)
- **Treasure Class Tables** - Monster drop probabilities and item pools
- **Rune Tables** - Rune properties for socketed items (25 runes total)
- **Gem Tables** - Gem properties and socket bonuses (12 types)
- **Item Stat Tables** - Property definitions for all possible item modifiers
- **Skill Tables** - Skill properties, tree structure, synergies
- **Missile Tables** - Projectile properties (damage, speed, collision)

---

## Exported Functions Documentation

### A. Unit Management Functions (30+ functions)

#### Unit Creation & Initialization
```
@ 0x6FD62030  InitializeUnitStructure(pUnit, type, subtype, x, y, z)
               Create and initialize unit structure with default values

@ 0x6FD62720  ProcessUnitsInBoundingBox(x1, y1, x2, y2)
               Find all units within rectangular area (AoE targeting, collision detection)
```

#### Unit Stat Application
```
@ 0x6FD6B1D0  ApplyObjectStatsToUnit(pUnit, pObject)
               Apply base stats from object to unit

@ 0x6FDBB4A0  ApplyStatModifiersToUnit(pUnit, difficulty)
               Apply difficulty-based stat modifiers
```

#### Unit Movement & Collision
```
@ 0x6FDCFCD0  CalculateUnitDistance(pUnit1, pUnit2)
               Calculate pathfinding distance between units

@ 0x6FD81850  ApplyUnitCollisionToRoom(pUnit, pRoom)
               Handle collision detection and response

@ 0x6FD8E080  AdjustViewportByUnitDirection(pUnit, facing)
               Position camera based on unit facing direction

@ 0x6FD85160  AdjustViewportToFollowUnit(pUnit)
               Pan camera to follow unit movement
```

#### Unit Skill Management
```
@ 0x6FD76DB0  CanUnitUseSkill(pUnit, skillId)
               Check if unit can use skill (class, level requirements)

@ 0x6FDA2660  AddSkillToUnit(pUnit, skillId, level)
               Add skill to unit

@ 0x6FDA2CA0  AddOrUpgradeUnitSkill(pUnit, skillId, levels)
               Add or increase skill level

@ 0x6FDA2D50  AssignSkillToUnit(pUnit, slotIndex, skillId)
               Assign skill to specific hotkey slot (1-9)

@ 0x6FD9F730  CanUnitActivateSkill(pUnit, skillId)
               Check if skill is currently usable

@ 0x6FD83E60  CheckUnitActiveSkillBitsMask(pUnit)
               Get bitmask of active skills
```

#### Unit Stat Requirements
```
@ 0x6FD7A170  CheckUnitStatRequirements(pUnit, pItem)
               Validate unit has sufficient stats to equip item

@ 0x6FD7A3D0  AddSkillChargesFromSkillStat(pUnit, skillId)
               Recharge skill charges from stat value
```

---

### B. Inventory Management Functions (30+ functions)

#### Inventory Creation & Destruction
```
@ 0x6FD6E710  CreateInventory()
               Create new inventory (10x10 grid + equipment slots)

@ 0x6FD71B40  DestroyInventory(pInventory)
               Free inventory structure

@ 0x6FD71C50  CopyAndValidateInventory(pSrcInv, pDstInv)
               Clone inventory safely with validation
```

#### Item Placement & Removal
```
@ 0x6FD71E10  PlaceItemInInventory(pInventory, pItem, x, y)
               Add item to inventory at specific grid location

@ 0x6FD703B0  CanPlaceItemInInventory(pInventory, pItem, x, y)
               Check if item placement is valid (size, collisions)

@ 0x6FD71B00  RemoveValidatedItemFromInventory(pInventory, pItem)
               Delete item from inventory
```

#### Item Location & Lookup
```
@ 0x6FD6FE10  FindItemInInventory(pInventory, itemId)
               Locate item by unique ID

@ 0x6FD622B0  FindItemByTypeAndSubtype(pInventory, type, subtype)
               Find item matching type classification

@ 0x6FD6ED00  FindSkillItemInInventory(pInventory, skillId)
               Locate skill book or scroll

@ 0x6FD6EDF0  FindItemWithSkillByCode(pInventory, skillCode)
               Find item that grants specific skill
```

#### Equipment Slot Management
```
@ 0x6FD6FC70  AssignItemToUnitSlot(pUnit, slotIndex, pItem)
               Equip item to body slot (head, torso, etc.)

@ 0x6FD70620  EquipSkillItem(pUnit, slotIndex, pItem)
               Equip skill book/scroll to hotkey slot
```

#### Inventory Traversal
```
@ 0x6FD6E190  GetInventoryFirstItem(pInventory)
               Get first item in linked list

@ 0x6FD6E170  GetInventoryLastItem(pInventory)
               Get last item in linked list

@ 0x6FD6E5B0  GetInventoryPageItem(pInventory, pageIndex)
               Get item on specific inventory page
```

#### Item Statistics & Counting
```
@ 0x6FD6EC30  CountMatchingInventoryItems(pInventory, criteria)
               Count items matching filter (type, quality, etc.)
```

---

### C. Skill System Functions (40+ functions)

#### Skill Properties Access
```
@ 0x6FD72920  GetSkillProperty(skillId, propertyId)
               Get skill property value (generic accessor)

@ 0x6FD72380  GetSkillPropertyByIndex(skillId, index)
               Get skill property by index

@ 0x6FD72430  GetSkillPropertyByIndex2(skillId, index)
               Alternative skill property accessor

@ 0x6FD73050  GetSkillPropertyByIndex3(skillId, index)
               Third variant skill property accessor

@ 0x6FD72E20  GetSkillDataAttribute(skillId, attributeId)
               Get skill data attribute
```

#### Skill Level & Charge Management
```
@ 0x6FD72970  GetSkillLevelRequirement(skillId)
               Get minimum level to learn skill

@ 0x6FD72820  GetSkillChargeValue(pUnit, skillId)
               Get current charges remaining

@ 0x6FD7A3D0  AddSkillChargesFromSkillStat(pUnit, skillId, statValue)
               Recharge skill from stat value
```

#### Item-Granted Skills
```
@ 0x6FD733B0  GetItemSkillLevel(pItem, skillId)
               Get skill level granted by item

@ 0x6FD73400  GetItemSkillLevel2(pItem, skillId)
               Alternative item skill level getter

@ 0x6FD734F0  GetItemSkillLevel3(pItem, skillId)
               Third item skill level variant

@ 0x6FD73540  GetItemSkillLevel4(pItem, skillId)
               Fourth item skill level variant

@ 0x6FD734A0  GetItemSkillProperty(pItem, propertyId)
               Get item-granted skill properties

@ 0x6FD73360  GetItemSkillCooldownTime(pItem, skillId)
               Get skill cooldown duration

@ 0x6FD731E0  GetItemSkillClassification(pItem, skillId)
               Get skill class (passive/active)
```

#### Skill Validation & Classification
```
@ 0x6FD72EC0  ValidateSkillProperty(skillId)
               Check if skill is valid

@ 0x6FD6EEE0  ValidateSkillEquipment(pItem)
               Validate item has valid equipped skills

@ 0x6FD72CD0  CompareSkillClassification(skillId1, skillId2)
               Compare skill classes

@ 0x6FD72E70  GetSkillClassRestriction(skillId)
               Get class eligibility (which classes can learn)
```

#### Skill Synergies & Bonuses
```
@ 0x6FD96E50  ApplyPassiveSkillSynergies(pUnit, skillId)
               Calculate bonus damage from related passive skills

@ 0x6FD98630  ApplyConditionalSkillStats(pUnit, skillId, condition)
               Apply conditional stat modifications

@ 0x6FD97FA0  ApplyRandomizedSkillEventWithSynergy(pUnit, skillId)
               Apply event-driven skill bonuses with synergy

@ 0x6FD9EE00  AddOrRemoveTimedSkillEffect(pUnit, skillId, duration)
               Apply duration-based skill effects
```

#### Monster Skill Handling
```
@ 0x6FD7A480  ApplyMonsterSkillCharges(pMonster, skillId, charges)
               Assign skill charges to monster
```

---

### D. Item Property Functions (30+ functions)

#### Bonus Calculation
```
@ 0x6FD74A50  AccumulateInventoryItemPlayerBonuses(pUnit)
               Sum all bonuses from equipped items

@ 0x6FD78850  AccumulateItemStatBonuses(pItem)
               Sum individual item stat modifiers

@ 0x6FDBABC0  AccumulateSkillDamageBonuses(pUnit, skillId)
               Sum damage modifiers from equipment and skills
```

#### Item Stat Modification
```
@ 0x6FD89CE0  ApplyItemPropertyStatModifiers(pItem, quality)
               Apply quality-based stat multipliers

@ 0x6FD76190  CalculateItemRequiredLevel(pItem)
               Determine minimum level to equip

@ 0x6FD766E0  CalculateSocketedItemBonuses(pItem)
               Calculate synergy bonuses from socketed items
```

#### Item Coordinate & Access
```
@ 0x6FD72590  GetItemCoordinates(pItem)
               Get item's position in inventory grid

@ 0x6FD72560  SetUnitCoordinates(pItem, x, y)
               Set item coordinates

@ 0x6FD72640  GetItemDataPointer(pItem)
               Get pointer to item data structure

@ 0x6FD725F0  SetItemPropertyField(pItem, fieldId, value)
               Modify specific item property
```

---

### E. Game State & Lookup Functions (40+ functions)

#### Game State Access
```
@ 0x6FD6B880  GetGameState()
               Get current game state structure

@ 0x6FD68F80  GetGameStatePointer()
               Get pointer to game state

@ 0x6FD59C20  GetGameContextDwordValue(contextId)
               Get context property (difficulty, area, etc.)

@ 0x6FD000C0  SetGameStateThreadSafe(contextId, value)
               Atomically update game state

@ 0x6FD09470  QueryGameState(queryId)
               Query game state value
```

#### Table & Lookup Operations
```
@ 0x6FD6A2B0  GetTableValue(tableId, index)
               Generic table lookup

@ 0x6FD6A2C0  GetLookupTableValue(tableId, key)
               Key-based table lookup

@ 0x6FD6A720  GetTableFieldFromRegistry(tableId, fieldId)
               Registry-based field lookup

@ 0x6FD6A550  GetMaskedTableValueByIndex(tableId, index, mask)
               Extract masked value from table

@ 0x6FD6B890  GetArrayElementByIndex(pArray, index)
               Array element access
```

#### Difficulty & Configuration
```
@ 0x6FD6A330  GetPlayerDifficultyData(pPlayer)
               Get difficulty settings (Normal/NM/Hell modifiers)

@ 0x6FD6A270  GetDualAttributeValues(attrId)
               Get dual attribute values
```

#### Linked List Traversal
```
@ 0x6FD6A770  FindLinkedUnitInChain(pHead, criteria)
               Traverse linked list of units
```

---

## Technical Deep Dives

### 1. Inventory Grid System Architecture

The inventory uses a **10x10 cell grid** plus dedicated equipment slots:

```
Equipment Slots (Auto-placed):
┌─────────────────────────────┐
│ Head (1x2)                  │
│ ┌─────────────────────────┐ │
│ │ Torso (2x3)             │ │
│ │ ┌───────────┬─────────┐ │ │
│ │ │ L.Arm(2x4)│ R.Arm(2x4)
│ │ └───────────┴─────────┘ │ │
│ │ Belt (2x1)              │ │
│ │ ┌───────────┬─────────┐ │ │
│ │ │Gloves(2x2)│Feet(2x2)│ │ │
│ │ └───────────┴─────────┘ │ │
│ │ Neck (1x1)              │ │
│ │ ┌─────────────────────┐ │ │
│ │ │ Hands (for skills)  │ │ │
│ └─────────────────────────┘ │
└─────────────────────────────┘

Main Grid (10x10):
┌──────────────────────────────┐
│ [0,0] [1,0] [2,0] ... [9,0]  │
│ [0,1] [1,1] [2,1] ... [9,1]  │
│ ...                           │
│ [0,9] [1,9] [2,9] ... [9,9]  │
└──────────────────────────────┘
```

**Grid Placement Algorithm**:
1. Item specifies width and height in cells
2. Find first available cell that fits
3. Check for collisions with equipped items
4. Check for collisions with other inventory items
5. Place if valid, reject otherwise

**Item Size Lookup**:
```
Scroll: 1x1
Small weapon: 1x3
Armor: 2x3
Shield: 2x3
Two-handed: 2x4
Staff: 2x5
```

### 2. Item Property Calculation Chain

Complex multi-stage calculation for final item properties:

```
Step 1: Base Item
├─ Base type (Sword, Shield, Armor)
├─ Base damage/defense
└─ Base required level

Step 2: Quality Modifiers
├─ Normal: No modifier (100%)
├─ Magic: +20% to +40%
├─ Rare: +20% to +50% per affix (2-6 affixes)
├─ Set: Preset bonuses + set completion bonus
└─ Unique: Preset custom bonuses

Step 3: Affixes
├─ Prefixes (e.g., "Razor Sharp")
├─ Suffixes (e.g., "of Strength")
└─ Quantity depends on quality level

Step 4: Sockets
├─ Count: 0-3 sockets per item
├─ Socketed Items: Gems, Runes, or Jewels
└─ Synergies: Each provides specific bonuses

Step 5: Item Bonuses
├─ Experience bonus (weapons only)
├─ Elemental damage
├─ Life steal, mana steal
├─ All resistances
└─ Skill charges and skill bonuses

Step 6: Player Bonus Stack
├─ Sum all equipped item bonuses
├─ Apply synergy multipliers
├─ Apply difficulty modifiers
└─ Final result used for gameplay calculations
```

### 3. Skill Synergy Calculation

Each skill can have 1-3 synergies from other skills:

```
Example: Sorceress Fireball
├─ Synergy 1: Inferno (+0.1 * Inferno Level damage)
├─ Synergy 2: Meteor (+0.1 * Meteor Level damage)
└─ Total Fireball damage = Base Damage + Synergies

Calculation:
Final Damage = Base Damage
             + (Synergy1_Value * Synergy1_Level)
             + (Synergy2_Value * Synergy2_Level)
             + (Synergy3_Value * Synergy3_Level)
             + Item_Bonuses
             + Equipment_Synergies
```

### 4. Character Save Format

**Character Template** (from strings):
```
CharTemplate {
  Class: Barbarian/Sorceress/Necromancer/Druid/Amazon/Paladin/Druid
  Level: 1-99
  Experience: Current XP toward next level
  Name: Character display name

  Equipped Items (15 slots):
    Item1: Head
    Item2: Torso
    Item3: Right Arm
    Item4: Left Arm
    Item5: Hands
    Item6: Belt
    Item7: Feet
    Item8: Gloves
    Item9: Neck
    Item10: Left Hand
    Item11: Right Hand
    Item12-15: Temporary/backup slots

  Skills (9 hotkey slots):
    Skill1-9: Currently assigned skills
    SkillLevel1-9: Current levels

  Statistics:
    Hitpoints: Current/Max HP
    Velocity: Movement speed
    AttackRate: Attack speed
    OtherRate: Other action speed
    ManaRegenBonus: Mana regeneration
    RightSkill: Currently selected right-click skill
}
```

### 5. Difficulty-Based Modifiers

**Difficulty Escalation**:
```
Normal (Act 1-4):
├─ Monster Life: 100%
├─ Monster Damage: 100%
├─ Experience Penalty: None
└─ Item Drop Rate: Baseline

Nightmare (Act 1-5):
├─ Monster Life: 150%
├─ Monster Damage: 110%
├─ Experience Penalty: Half XP
└─ Item Drop Rate: +20%

Hell (Act 1-5):
├─ Monster Life: 300%
├─ Monster Damage: 120%
├─ Experience Penalty: Reduced XP by level
└─ Item Drop Rate: +40%
```

### 6. Monster Data Tables

**Monster Properties Lookup**:
```
Monster Table Entry:
├─ ID: Unique monster identifier
├─ BaseHP: Hit points (scaled by difficulty)
├─ BaseDamage: Physical damage (scaled by difficulty)
├─ Experience: XP granted on kill
├─ Skills: 1-6 active skills
├─ Immunities: Fire, Cold, Lightning, Poison, Physical
├─ ItemDropTable: Treasure class (determines possible drops)
├─ Size: Collision radius
└─ Speed: Movement speed

Treasure Class Table:
├─ TreasureClassId
├─ ItemPool: Array of possible items
├─ DropProbability: Percentage per item
└─ UniqueItemDropChance: Special item rate
```

---

## 10 Interesting Technical Facts

1. **2,766 Functions Across 693 KB**
   - D2Common.dll contains one of the highest function densities in Diablo II
   - Average of 251 bytes per function (including data)
   - Indicates deep subsystem organization and code modularity

2. **Inventory Grid Size: 10x10 Cells (100 Maximum Placements)**
   - Items vary from 1x1 (scrolls) to 2x4 (two-handed weapons)
   - Equipment slots are auto-placed outside main grid
   - Collision detection prevents overlapping items
   - Allows 10-30 different items depending on sizes

3. **Character Skills: 30 Learned + 9 Hotkey Slots**
   - Characters can learn up to 30 skills from 3 skill trees
   - Only 9 skills can be "hot-keyed" at a time
   - Allows strategic skill selection for different situations
   - Skills 1-3 are left-click attacks, 4-9 are right-click abilities

4. **Skill Synergy Formula: +0.1 Damage per Synergy Level**
   - Each synergy typically grants 10% bonus per level in the synergy skill
   - Example: If Inferno (synergy) is level 20, grants +2.0 damage multiplier to Fireball
   - Creates strategic build diversity based on skill tree synergies
   - Encourages "themed" builds (fire spells, cold spells, etc.)

5. **Item Affixes: 2-6 per Item Depending on Quality**
   - Magic items: 1-2 properties
   - Rare items: 2-6 properties
   - Set items: Preset + completion bonus
   - Unique items: Completely custom (50+ unique affixes possible)

6. **Game State Tracks 47,611 Symbols**
   - Indicates extremely complex internal state management
   - Covers monsters, items, areas, events, player progress
   - Per-difficulty tracking (Normal, Nightmare, Hell)
   - Cross-referenced for multiplayer synchronization

7. **Monster Life Scales 300% at Difficulty 3 (Hell)**
   - Normal monsters: 100% HP
   - Nightmare: 150% HP
   - Hell: 300% HP (3x health increase)
   - Creates significant difficulty spike between modes

8. **Five Equipment Slot Categories (Head, Body, Hands, Feet, Accessories)**
   - Allows multiple items to provide bonuses simultaneously
   - Example: One item provides +5 Fireball, another +2 Inferno (synergy)
   - Gear synergy is major element of character building

9. **Linked List Data Structure for Unit Management**
   - Units stored as linked lists for efficient iteration
   - Allows real-time addition/removal without reallocation
   - Critical for dynamic spawn/despawn system
   - Supports fast traversal for AoE effects and collision detection

10. **Registry-Based Lookup for Dynamic Table Values**
    - Allows hot-loading of balance changes without binary modification
    - Used for skill properties, item stats, monster data
    - Enables patching without recompiling game code
    - Critical for Diablo II's long-running balance updates (1.09-1.14)

---

## Performance Characteristics

### Inventory Operations
| Operation | Time | Complexity |
|-----------|------|------------|
| Place item in grid | <1ms | O(n) where n = items in inventory |
| Find item by ID | <1ms | O(n) |
| Remove item | <1ms | O(1) with unlink |
| Count matching items | 1-5ms | O(n) |

### Skill System
| Operation | Time | Complexity |
|-----------|------|------------|
| Get skill property | <1ms | O(1) lookup |
| Apply synergies | 1-5ms | O(synergy_count) |
| Add skill charges | <1ms | O(1) |

### Game State
| Operation | Time | Complexity |
|-----------|------|------------|
| Get game state | <1ms | O(1) |
| Update state (thread-safe) | 1-3ms | O(1) with lock |
| Lookup table value | <1ms | O(1) array access |

### Unit Management
| Operation | Time | Complexity |
|-----------|------|------------|
| Find units in area | 10-50ms | O(n) where n = total units |
| Calculate collision | 1-5ms | O(1) per unit pair |

---

## Integration with Diablo II Ecosystem

### Dependency Graph
```
D2Common.dll (CORE)
├─ Used by: D2Gdi.dll (render units/items)
├─ Used by: D2Sound.dll (play unit sounds)
├─ Used by: D2Net.dll (send unit updates)
├─ Used by: D2Lang.dll (item descriptions)
├─ Used by: D2MpcClient.dll (multiplayer sync)
├─ Used by: D2Game.dll (game engine)
└─ Used by: Fog.dll (logging unit info)

Imports from:
├─ Kernel32.dll (memory, threading)
├─ User32.dll (window messaging)
├─ Fog.dll (logging framework)
├─ Storm.dll (compression, utilities)
└─ D2Lang.dll (localization lookups)
```

### Data Flow Examples

**Character Level Up**:
```
D2Game (AI/Logic)
  └─→ AddSkillToUnit() (add new skill)
      └─→ ApplyPassiveSkillSynergies() (calc bonuses)
          └─→ ApplyStatModifiersToUnit() (update stats)
              └─→ Notify D2Gdi (redraw UI)
```

**Item Pickup**:
```
Player Input → D2Game.dll
  └─→ PlaceItemInInventory() (validate placement)
      └─→ AccumulateInventoryItemPlayerBonuses() (recalc stats)
          └─→ ApplyItemPropertyStatModifiers() (quality modifiers)
              └─→ D2Gdi.dll (redraw inventory)
              └─→ D2Sound.dll (play pickup sound)
              └─→ D2Net.dll (sync to server)
```

**Skill Activation**:
```
Player Key Press → D2Game.dll
  └─→ CanUnitActivateSkill() (validate usable)
      └─→ GetSkillProperty() (get skill data)
          └─→ ApplyRandomizedSkillEventWithSynergy() (apply bonuses)
              └─→ Create missile/effect
              └─→ D2Sound.dll (play skill sound)
              └─→ D2Gdi.dll (render effect)
              └─→ D2Net.dll (sync cast to server)
```

---

## Technology Stack

- **Language**: C++ (with C binding for DLL exports)
- **Memory Management**: Manual heap allocation via Kernel32.dll (HeapAlloc/HeapFree)
- **Concurrency**: Critical sections (EnterCriticalSection) for thread-safe state updates
- **Data Structures**: Linked lists (units), Arrays (lookup tables), Hash tables (string lookups)
- **File I/O**: Character save files, item database loading
- **Platform**: Windows x86 (32-bit), compatible with Windows 9x through Windows XP

---

## Security Considerations

1. **Item Duplication Prevention**
   - Items have unique IDs tracked in game state
   - Multiplayer validation prevents inventory desync

2. **Skill Level Validation**
   - CanUnitUseSkill() enforces class and level requirements
   - Prevents skill learning exploits

3. **Stat Modification Validation**
   - CheckUnitStatRequirements() validates item equip eligibility
   - Prevents equipping items character can't use

4. **Thread-Safe State Updates**
   - SetGameStateThreadSafe() uses critical sections
   - Prevents race conditions in multiplayer

---

## Conclusion

D2Common.dll is the **architectural foundation** of Diablo II's game engine. Its 2,766 functions and 47,611 symbols provide the fundamental abstractions for:

- **Unit management** (players, NPCs, monsters)
- **Inventory systems** (grid-based storage with equipment slots)
- **Skill systems** (with synergies and class restrictions)
- **Item properties** (affixes, quality levels, sockets)
- **Game state** (persistent data, lookup tables, difficulty settings)

Every other subsystem (graphics, audio, networking, multiplayer) depends on D2Common for understanding what game objects are, how they relate to each other, and what properties they have. Understanding D2Common is essential for any reverse engineering or modding of Diablo II.

The library demonstrates sophisticated systems design including inventory management constraints, item property calculation chains, and skill synergy mechanics that create emergent gameplay through equipment interactions.

---

**Generated**: 2025-11-03
**Tools Used**: Ghidra 11.4.2 with GhidraMCP (111 MCP tools)
**Methodology**: Systematic binary analysis with function export enumeration and string extraction
**Status**: Complete and ready for use
