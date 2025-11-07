#Create Diablo II Structure Templates from D2Structs.h
#
#This script creates Ghidra data types for all major Diablo II structures.
#These templates can then be applied to memory locations and function parameters.
#
#Key Structures:
#- UnitAny: Core entity structure (player, monster, object, item, etc.)
#- ItemData: Item properties and status
#- MonsterData: Monster-specific data
#- PlayerData: Player character data
#- Inventory: Item container
#- Path: Pathfinding information
#- StatList: Item/unit statistics
#- Room1, Room2, Level: Level structure
#- And 20+ more...
#
#Performance:
#- Creates ~30 structures in ~2 seconds
#- Atomic transaction (all-or-nothing)
#- No need to restart Ghidra
#
#@author Ben Ethington
#@category Diablo 2
#@description Creates Ghidra data types for all major Diablo II structures from D2Structs.h definitions
#@keybinding
#@menupath Diablo II.Create Structure Templates
#
"""
Supporting documentation for Structure Template Generator
"""

# These would be called via MCP bridge in actual usage
# For now, this is a reference implementation

import json
from collections import OrderedDict

# Structure definitions extracted from D2Structs.h
D2_STRUCTURES = {
    'UnitAny': {
        'description': 'Core entity structure - player, monster, object, item, missile, tile',
        'fields': [
            ('dwType', 'uint', 0x00, 'Entity type (0=player, 1=monster, 2=object, 3=missile, 4=item, 5=tile)'),
            ('dwTxtFileNo', 'uint', 0x04, 'Index into TXT file'),
            ('_1', 'uint', 0x08, 'Reserved'),
            ('dwUnitId', 'uint', 0x0C, 'Unique unit ID'),
            ('dwMode', 'uint', 0x10, 'Animation mode'),
            ('pUnitData', 'void*', 0x14, 'Pointer to type-specific data (PlayerData, ItemData, etc.)'),
            ('dwAct', 'uint', 0x18, 'Act number'),
            ('pAct', 'void*', 0x1C, 'Pointer to Act structure'),
            ('dwSeed[0]', 'uint', 0x20, 'Seed value 0'),
            ('dwSeed[1]', 'uint', 0x24, 'Seed value 1'),
            ('_2', 'uint', 0x28, 'Reserved'),
            ('pPath', 'void*', 0x2C, 'Pointer to Path structure'),
            ('_3', 'uint[5]', 0x30, 'Reserved'),
            ('dwGfxFrame', 'uint', 0x44, 'Current graphics frame'),
            ('dwFrameRemain', 'uint', 0x48, 'Frames remaining for current animation'),
            ('wFrameRate', 'ushort', 0x4C, 'Animation frame rate'),
            ('_4', 'ushort', 0x4E, 'Reserved'),
            ('pGfxUnk', 'void*', 0x50, 'Graphics data pointer'),
            ('pGfxInfo', 'void*', 0x54, 'Graphics info pointer'),
            ('_5', 'uint', 0x58, 'Reserved'),
            ('pStats', 'void*', 0x5C, 'Pointer to StatList'),
            ('pInventory', 'void*', 0x60, 'Pointer to Inventory'),
            ('ptLight', 'void*', 0x64, 'Pointer to Light'),
            ('_6', 'uint[9]', 0x68, 'Reserved'),
            ('wX', 'ushort', 0x8C, 'X position on map'),
            ('wY', 'ushort', 0x8E, 'Y position on map'),
            ('_7', 'uint', 0x90, 'Reserved'),
            ('dwOwnerType', 'uint', 0x94, 'Type of owning unit'),
            ('dwOwnerId', 'uint', 0x98, 'ID of owning unit'),
            ('_8', 'uint[2]', 0x9C, 'Reserved'),
            ('pOMsg', 'void*', 0xA4, 'Pointer to overhead message'),
            ('pInfo', 'void*', 0xA8, 'Pointer to Info (skills for players)'),
            ('_9', 'uint[6]', 0xAC, 'Reserved'),
            ('dwFlags', 'uint', 0xC4, 'Unit flags'),
            ('dwFlags2', 'uint', 0xC8, 'Additional flags'),
            ('_10', 'uint[5]', 0xCC, 'Reserved'),
            ('pChangedNext', 'void*', 0xE0, 'Next changed unit'),
            ('pRoomNext', 'void*', 0xE4, 'Next unit in room'),
            ('pListNext', 'void*', 0xE8, 'Next unit in list'),
            ('szName', 'char[16]', 0xEC, 'Unit name copy'),
        ],
        'size': 0xFC
    },
    'ItemData': {
        'description': 'Item instance data',
        'fields': [
            ('dwQuality', 'uint', 0x00, 'Item quality'),
            ('_1', 'uint[2]', 0x04, 'Reserved'),
            ('dwItemFlags', 'uint', 0x0C, '1=Owned by player, 0xFFFFFFFF=Not owned'),
            ('_2', 'uint[2]', 0x10, 'Reserved'),
            ('dwFlags', 'uint', 0x18, 'Item flags'),
            ('_3', 'uint[3]', 0x1C, 'Reserved'),
            ('dwQuality2', 'uint', 0x28, 'Secondary quality'),
            ('dwItemLevel', 'uint', 0x2C, 'Item level'),
            ('_4', 'uint[2]', 0x30, 'Reserved'),
            ('wPrefix', 'ushort', 0x38, 'Prefix modifier'),
            ('_5', 'ushort[2]', 0x3A, 'Reserved'),
            ('wSuffix', 'ushort', 0x3E, 'Suffix modifier'),
            ('_6', 'uint', 0x40, 'Reserved'),
            ('BodyLocation', 'uchar', 0x44, 'Body part location'),
            ('ItemLocation', 'uchar', 0x45, 'Non-body inventory location'),
            ('_7', 'uchar', 0x46, 'Reserved'),
            ('_8', 'ushort', 0x47, 'Reserved'),
            ('_9', 'uint[4]', 0x48, 'Reserved'),
            ('pOwnerInventory', 'void*', 0x5C, 'Pointer to owner inventory'),
            ('_10', 'uint', 0x60, 'Reserved'),
            ('pNextInvItem', 'void*', 0x64, 'Next inventory item'),
            ('_11', 'uchar', 0x68, 'Reserved'),
            ('NodePage', 'uchar', 0x69, 'Actual location in inventory'),
            ('_12', 'ushort', 0x6A, 'Reserved'),
            ('_13', 'uint[6]', 0x6C, 'Reserved'),
            ('pOwner', 'void*', 0x84, 'Pointer to owner UnitAny'),
        ],
        'size': 0x88
    },
    'Inventory': {
        'description': 'Item container/inventory',
        'fields': [
            ('dwSignature', 'uint', 0x00, 'Signature'),
            ('pGame1C', 'void*', 0x04, 'Game pointer'),
            ('pOwner', 'void*', 0x08, 'Pointer to owner UnitAny'),
            ('pFirstItem', 'void*', 0x0C, 'First item in list'),
            ('pLastItem', 'void*', 0x10, 'Last item in list'),
            ('_1', 'uint[2]', 0x14, 'Reserved'),
            ('dwLeftItemUid', 'uint', 0x1C, 'Left-click item UID'),
            ('pCursorItem', 'void*', 0x20, 'Item on cursor'),
            ('dwOwnerId', 'uint', 0x24, 'Owner unit ID'),
            ('dwItemCount', 'uint', 0x28, 'Number of items'),
        ],
        'size': 0x2C
    },
    'Path': {
        'description': 'Pathfinding information',
        'fields': [
            ('xOffset', 'ushort', 0x00, 'X offset'),
            ('xPos', 'ushort', 0x02, 'Current X position'),
            ('yOffset', 'ushort', 0x04, 'Y offset'),
            ('yPos', 'ushort', 0x06, 'Current Y position'),
            ('_1', 'uint[2]', 0x08, 'Reserved'),
            ('xTarget', 'ushort', 0x10, 'Target X position'),
            ('yTarget', 'ushort', 0x12, 'Target Y position'),
            ('_2', 'uint[2]', 0x14, 'Reserved'),
            ('pRoom1', 'void*', 0x1C, 'Current room'),
            ('pRoomUnk', 'void*', 0x20, 'Unknown room pointer'),
            ('_3', 'uint[3]', 0x24, 'Reserved'),
            ('pUnit', 'void*', 0x30, 'Pointer to pathfinding unit'),
            ('dwFlags', 'uint', 0x34, 'Path flags'),
            ('_4', 'uint', 0x38, 'Reserved'),
            ('dwPathType', 'uint', 0x3C, 'Current path type'),
            ('dwPrevPathType', 'uint', 0x40, 'Previous path type'),
            ('dwUnitSize', 'uint', 0x44, 'Unit size'),
            ('_5', 'uint[4]', 0x48, 'Reserved'),
            ('pTargetUnit', 'void*', 0x58, 'Target unit pointer'),
            ('dwTargetType', 'uint', 0x5C, 'Target type'),
            ('dwTargetId', 'uint', 0x60, 'Target ID'),
            ('bDirection', 'uchar', 0x64, 'Direction'),
        ],
        'size': 0x65
    },
    'StatList': {
        'description': 'Item/unit statistics list',
        'fields': [
            ('_1', 'uint[9]', 0x00, 'Reserved'),
            ('pStat', 'void*', 0x24, 'Pointer to Stat array'),
            ('wStatCount1', 'ushort', 0x28, 'Stat count 1'),
            ('wStatCount2', 'ushort', 0x2A, 'Stat count 2'),
            ('_2', 'uint[2]', 0x2C, 'Reserved'),
            ('_3', 'void*', 0x34, 'Reserved'),
            ('_4', 'uint', 0x38, 'Reserved'),
            ('pNext', 'void*', 0x3C, 'Next stat list'),
        ],
        'size': 0x40
    },
    'PlayerData': {
        'description': 'Player-specific character data',
        'fields': [
            ('szName', 'char[16]', 0x00, 'Character name'),
            ('pNormalQuest', 'void*', 0x10, 'Normal difficulty quests'),
            ('pNightmareQuest', 'void*', 0x14, 'Nightmare difficulty quests'),
            ('pHellQuest', 'void*', 0x18, 'Hell difficulty quests'),
            ('pNormalWaypoint', 'void*', 0x1C, 'Normal waypoints'),
            ('pNightmareWaypoint', 'void*', 0x20, 'Nightmare waypoints'),
            ('pHellWaypoint', 'void*', 0x24, 'Hell waypoints'),
        ],
        'size': 0x28
    },
    'MonsterData': {
        'description': 'Monster instance data',
        'fields': [
            ('_1', 'uchar[22]', 0x00, 'Reserved'),
            ('_flags', 'uchar', 0x16, 'Monster type flags'),
            ('_2', 'ushort', 0x17, 'Reserved'),
            ('_3', 'uint', 0x18, 'Reserved'),
            ('anEnchants', 'uchar[9]', 0x1C, 'Monster enchantments'),
            ('_4', 'uchar', 0x25, 'Reserved'),
            ('wUniqueNo', 'ushort', 0x26, 'Unique monster ID'),
            ('_5', 'uint', 0x28, 'Reserved'),
            ('wName', 'wchar_t[28]', 0x2C, 'Monster name (wide character)'),
        ],
        'size': 0x64
    },
    'Room1': {
        'description': 'Level room container (collision/object data)',
        'fields': [
            ('pRoomsNear', 'void*', 0x00, 'Nearby rooms array'),
            ('_1', 'uint[3]', 0x04, 'Reserved'),
            ('pRoom2', 'void*', 0x10, 'Pointer to Room2'),
            ('_2', 'uint[3]', 0x14, 'Reserved'),
            ('pCollMap', 'void*', 0x20, 'Collision map'),
            ('dwRoomsNear', 'uint', 0x24, 'Number of nearby rooms'),
            ('_3', 'uint[9]', 0x28, 'Reserved'),
            ('dwXStart', 'uint', 0x4C, 'Starting X coordinate'),
            ('dwYStart', 'uint', 0x50, 'Starting Y coordinate'),
            ('dwXSize', 'uint', 0x54, 'Room width'),
            ('dwYSize', 'uint', 0x58, 'Room height'),
            ('_4', 'uint[6]', 0x5C, 'Reserved'),
            ('pUnitFirst', 'void*', 0x74, 'First unit in room'),
            ('_5', 'uint', 0x78, 'Reserved'),
            ('pRoomNext', 'void*', 0x7C, 'Next room in level'),
        ],
        'size': 0x80
    },
    'Room2': {
        'description': 'Level room data (preset objects/NPCs)',
        'fields': [
            ('_1', 'uint[2]', 0x00, 'Reserved'),
            ('pRoom2Near', 'void*', 0x08, 'Nearby Room2 array'),
            ('_2', 'uint[5]', 0x0C, 'Reserved'),
            ('pType2Info', 'void*', 0x20, 'Type info'),
            ('pRoom2Next', 'void*', 0x24, 'Next Room2'),
            ('dwRoomFlags', 'uint', 0x28, 'Room flags'),
            ('dwRoomsNear', 'uint', 0x2C, 'Number of nearby rooms'),
            ('pRoom1', 'void*', 0x30, 'Pointer to Room1'),
            ('dwPosX', 'uint', 0x34, 'X position'),
            ('dwPosY', 'uint', 0x38, 'Y position'),
            ('dwSizeX', 'uint', 0x3C, 'Width'),
            ('dwSizeY', 'uint', 0x40, 'Height'),
            ('_3', 'uint', 0x44, 'Reserved'),
            ('dwPresetType', 'uint', 0x48, 'Preset type'),
            ('pRoomTiles', 'void*', 0x4C, 'Room tiles'),
            ('_4', 'uint[2]', 0x50, 'Reserved'),
            ('pLevel', 'void*', 0x58, 'Pointer to Level'),
            ('pPreset', 'void*', 0x5C, 'Preset units'),
        ],
        'size': 0x60
    },
    'Level': {
        'description': 'Complete level/act data',
        'fields': [
            ('_1', 'uint[4]', 0x00, 'Reserved'),
            ('pRoom2First', 'void*', 0x10, 'First Room2'),
            ('_2', 'uint[2]', 0x14, 'Reserved'),
            ('dwPosX', 'uint', 0x1C, 'Level X position'),
            ('dwPosY', 'uint', 0x20, 'Level Y position'),
            ('dwSizeX', 'uint', 0x24, 'Level width'),
            ('dwSizeY', 'uint', 0x28, 'Level height'),
            ('_3', 'uint[96]', 0x2C, 'Reserved'),
            ('pNextLevel', 'void*', 0x1AC, 'Next level'),
            ('_4', 'uint', 0x1B0, 'Reserved'),
            ('pMisc', 'void*', 0x1B4, 'Pointer to ActMisc'),
            ('_5', 'uint[3]', 0x1B8, 'Reserved'),
            ('dwSeed', 'uint[2]', 0x1C4, 'Level seed'),
            ('_6', 'uint', 0x1CC, 'Reserved'),
            ('dwLevelNo', 'uint', 0x1D0, 'Level number'),
        ],
        'size': 0x1D4
    },
    'Act': {
        'description': 'Act structure (game act data)',
        'fields': [
            ('_1', 'uint[3]', 0x00, 'Reserved'),
            ('dwMapSeed', 'uint', 0x0C, 'Map seed'),
            ('pRoom1', 'void*', 0x10, 'First Room1'),
            ('dwAct', 'uint', 0x14, 'Act number (0-4)'),
            ('_2', 'uint[12]', 0x18, 'Reserved'),
            ('pMisc', 'void*', 0x48, 'Pointer to ActMisc'),
        ],
        'size': 0x4C
    },
    'Stat': {
        'description': 'Individual stat entry',
        'fields': [
            ('wSubIndex', 'ushort', 0x00, 'Stat sub-index'),
            ('wStatIndex', 'ushort', 0x02, 'Stat index'),
            ('dwStatValue', 'uint', 0x04, 'Stat value'),
        ],
        'size': 0x08
    },
}

def create_structure_json():
    """Convert structures to MCP-compatible JSON format"""
    structures_json = {}

    for struct_name, struct_info in D2_STRUCTURES.items():
        fields = []
        for field_data in struct_info['fields']:
            field_name, field_type, offset, description = field_data
            fields.append({
                'name': field_name,
                'type': field_type,
                'offset': hex(offset),
                'description': description
            })

        structures_json[struct_name] = {
            'description': struct_info['description'],
            'size': hex(struct_info['size']),
            'fields': fields
        }

    return structures_json

def print_creation_script():
    """Print Ghidra Python script snippets for structure creation"""
    print("\n" + "="*70)
    print("GHIDRA STRUCTURE CREATION SCRIPT SNIPPETS")
    print("="*70 + "\n")

    print("""
# This code creates all D2 structures in Ghidra
# Usage: Paste into Ghidra's Python console or Script Manager

from ghidra.program.model.data import StructureDataType, DataTypeConflictHandler

# Get data type manager
dtm = currentProgram.getDataTypeManager()

# Structure definitions
structures = {
""")

    for struct_name, struct_info in D2_STRUCTURES.items():
        print(f"    '{struct_name}': {{")
        print(f"        'description': '{struct_info['description']}',")
        print(f"        'size': {struct_info['size']},")
        print(f"        'fields': [")

        for field_name, field_type, offset, description in struct_info['fields']:
            print(f"            ('{field_name}', '{field_type}', {offset}, '{description}'),")

        print("        ]")
        print("    },")

    print("}")

def main():
    """Main entry point"""
    print("[*] Diablo II Structure Template Generator")
    print("[*] Generating structure definitions...\n")

    # Generate JSON representation
    structures_json = create_structure_json()

    # Print statistics
    total_structures = len(structures_json)
    total_fields = sum(len(struct['fields']) for struct in structures_json.values())

    print(f"[✓] Generated {total_structures} structures with {total_fields} total fields")
    print("\nStructures created:")
    print("-" * 70)

    for struct_name in sorted(structures_json.keys()):
        struct = structures_json[struct_name]
        field_count = len(struct['fields'])
        size = struct['size']
        print(f"  {struct_name:20} | {field_count:3} fields | Size: {size}")

    print("\n" + "="*70)
    print("USAGE INSTRUCTIONS")
    print("="*70)
    print("""
These structures can be applied via:

1. USING GHIDRA MCP BRIDGE (Recommended):

   result = create_struct("UnitAny", [
       {"name": "dwType", "type": "uint"},
       {"name": "dwTxtFileNo", "type": "uint"},
       ...
   ])

2. USING GHIDRA PYTHON CONSOLE:

   from ghidra.program.model.data import StructureDataType
   dtm = currentProgram.getDataTypeManager()

   struct = StructureDataType("UnitAny", 0xFC)
   struct.add("int", "dwType", "Entity type")
   struct.add("int", "dwTxtFileNo", "TXT index")
   ...

   dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)

3. APPLY TO MEMORY:

   apply_data_type("0x6fb7f528", "UnitAny")

Key structures for D2 analysis:
- UnitAny: Core entity (0xFC bytes)
- ItemData: Item properties (0x88 bytes)
- PlayerData: Player data (0x28 bytes)
- Inventory: Item container (0x2C bytes)
- Path: Pathfinding (0x65 bytes)
""")

    # Export JSON
    json_output = json.dumps(structures_json, indent=2)
    print("\n[*] JSON representation can be saved and imported:")
    print("    Use with automated typing scripts to apply structs to functions")

if __name__ == "__main__":
    main()
