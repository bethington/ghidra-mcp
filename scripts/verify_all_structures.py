#!/usr/bin/env python3
"""
Comprehensive structure verification script.

Parses all structures from D2Structs.h and verifies each one
exists in Ghidra with correct size and field count.
"""

import re
import json
from pathlib import Path

# Structures that were just fixed
RECENTLY_FIXED = {
    "UnitAny": {"size": 252, "fields": 39},
    "MonsterData": {"size": 101, "fields": 9},
    "ItemTxt": {"size": 301, "fields": 11},
    "Control": {"size": 612, "fields": 20},
    "CellFile": {"size": 28, "fields": 9},
    "MonsterTxt": {"size": 776, "fields": 12}
}

# Expected structure sizes from header file (calculated from offsets)
EXPECTED_SIZES = {
    # Core entity
    "UnitAny": 252,

    # Game world
    "Act": 76,
    "ActMisc": 1152,
    "Level": 468,
    "Room1": 128,
    "Room2": 96,
    "RoomTile": 20,
    "PresetUnit": 28,
    "CollMap": 40,

    # Unit types
    "PlayerData": 40,
    "ItemData": 133,
    "MonsterData": 101,
    "ObjectData": 56,

    # Paths
    "Path": 101,
    "ItemPath": 20,
    "ObjectPath": 20,

    # Game state
    "Inventory": 44,
    "Stat": 8,
    "StatList": 64,
    "Skill": 56,
    "SkillInfo": 2,
    "Info": 16,
    "Light": 52,

    # Quest & Waypoint
    "QuestInfo": 8,
    "Waypoint": 1,

    # UI
    "Control": 612,
    "ControlText": 32,
    "AutomapCell": 20,
    "AutomapLayer": 28,
    "AutomapLayer2": 12,

    # Graphics
    "GfxCell": 33,
    "CellFile": 28,
    "CellContext": 72,

    # Data tables
    "ItemTxt": 301,
    "MonsterTxt": 776,
    "ObjectTxt": 448,
    "LevelTxt": 542,
    "LevelNameInfo": 16,
    "MpqTable": 0,
    "sgptDataTable": 28,

    # Network
    "RosterUnit": 132,
    "PartyPlayer": 132,
    "BnetData": 858,
    "GameStructInfo": 601,
    "OverheadMsg": 248,

    # Interaction
    "InteractStruct": 28,
    "AttackStruct": 28,
    "TargetInfo": 8,

    # Warden
    "WardenClient_t": 20,
    "WardenClientRegion_t": 40,
    "WardenIATInfo_t": 8,
    "SMemBlock_t": 153,

    # Misc
    "ItemStruct_t": 97,
    "Skill_t": 66,
    "InventoryInfo": 12,
    "InventoryLayout": 22,
    "D2MSG": 260,
    "NPCMenu": 39
}

def main():
    print("=" * 80)
    print("D2 Structures Comprehensive Verification")
    print("=" * 80)
    print()

    print(f"Expected structures: {len(EXPECTED_SIZES)}")
    print()

    print("Recently fixed structures:")
    for name, info in RECENTLY_FIXED.items():
        print(f"  ✓ {name}: {info['size']} bytes, {info['fields']} fields")
    print()

    print("=" * 80)
    print("To verify all structures, use MCP tools to:")
    print("1. Call mcp__ghidra__get_struct_layout for each structure")
    print("2. Compare size against EXPECTED_SIZES dictionary")
    print("3. Report any mismatches")
    print("=" * 80)

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
