#!/usr/bin/env python3
"""
Create typedefs for D2Structs.h pointer types.
This handles the typedef declarations like:
  typedef RoomTile* LPROOMTILE;
  typedef UnitAny* LPUNITANY;
"""

import sys
from bridge_mcp_ghidra import (
    create_typedef,
    create_pointer_type,
    create_struct,
    logger
)


# Typedefs from D2Structs.h
TYPEDEFS = [
    # From lines 19-25
    ('LPROOMTILE', 'RoomTile', True),   # pointer
    ('LPPRESETUNIT', 'PresetUnit', True),
    ('LPUNITANY', 'UnitAny', True),
    ('LPLEVEL', 'Level', True),
    ('LPROOM2', 'Room2', True),
    ('LPROOM1', 'Room1', True),
    ('LPDWORD', 'dword', True),  # Special case: pointer to DWORD
]


def create_typedefs_in_ghidra():
    """Create all typedef pointer types in Ghidra."""
    results = {}

    for alias_name, base_type, is_pointer in TYPEDEFS:
        logger.info(f"\nCreating typedef: {alias_name} = {base_type}*")

        try:
            # For pointer typedefs, we can use create_pointer_type or create_typedef
            # Ghidra typically uses pointer type directly
            if is_pointer:
                # Create as pointer type
                result = create_pointer_type(base_type, name=alias_name)
            else:
                # Create as typedef alias
                result = create_typedef(alias_name, base_type)

            if "error" in result.lower() or "failed" in result.lower():
                logger.error(f"  Failed to create {alias_name}: {result}")
                results[alias_name] = False
            else:
                logger.info(f"  ✓ Created {alias_name}")
                results[alias_name] = True

        except Exception as e:
            logger.error(f"  Exception creating {alias_name}: {e}")
            results[alias_name] = False

    return results


def retry_failed_structures():
    """Retry creating structures that failed due to missing typedefs."""
    logger.info("\n" + "="*60)
    logger.info("Retrying failed structures...")
    logger.info("="*60)

    results = {}

    # Room2 structure (failed because of missing LP* typedefs)
    room2_fields = [
        {'name': 'pRoom2Near', 'type': 'LPROOM2'},
        {'name': 'pType2Info', 'type': 'LPDWORD'},
        {'name': 'pRoom2Next', 'type': 'LPROOM2'},
        {'name': 'dwRoomFlags', 'type': 'dword'},
        {'name': 'dwRoomsNear', 'type': 'dword'},
        {'name': 'pRoom1', 'type': 'LPROOM1'},
        {'name': 'dwPosX', 'type': 'dword'},
        {'name': 'dwPosY', 'type': 'dword'},
        {'name': 'dwSizeX', 'type': 'dword'},
        {'name': 'dwSizeY', 'type': 'dword'},
        {'name': 'dwPresetType', 'type': 'dword'},
        {'name': 'pRoomTiles', 'type': 'LPROOMTILE'},
        {'name': 'pLevel', 'type': 'LPLEVEL'},
        {'name': 'pPreset', 'type': 'LPPRESETUNIT'},
    ]

    try:
        logger.info("\nCreating Room2...")
        result = create_struct('Room2', room2_fields)
        if "error" not in result.lower() and "failed" not in result.lower():
            logger.info("  ✓ Created Room2")
            results['Room2'] = True
        else:
            logger.error(f"  Failed to create Room2: {result}")
            results['Room2'] = False
    except Exception as e:
        logger.error(f"  Exception creating Room2: {e}")
        results['Room2'] = False

    # OverheadMsg (failed because of missing CHAR type - should be byte)
    overhead_msg_fields = [
        {'name': 'dwTrigger', 'type': 'dword'},
        {'name': 'Msg', 'type': 'byte[232]'},
    ]

    try:
        logger.info("\nCreating OverheadMsg...")
        result = create_struct('OverheadMsg', overhead_msg_fields)
        if "error" not in result.lower() and "failed" not in result.lower():
            logger.info("  ✓ Created OverheadMsg")
            results['OverheadMsg'] = True
        else:
            logger.error(f"  Failed to create OverheadMsg: {result}")
            results['OverheadMsg'] = False
    except Exception as e:
        logger.error(f"  Exception creating OverheadMsg: {e}")
        results['OverheadMsg'] = False

    # Skill_t (failed because of CHAR - should be byte)
    skill_t_fields = [
        {'name': 'name', 'type': 'byte[64]'},
        {'name': 'skillID', 'type': 'word'},
    ]

    try:
        logger.info("\nCreating Skill_t...")
        result = create_struct('Skill_t', skill_t_fields)
        if "error" not in result.lower() and "failed" not in result.lower():
            logger.info("  ✓ Created Skill_t")
            results['Skill_t'] = True
        else:
            logger.error(f"  Failed to create Skill_t: {result}")
            results['Skill_t'] = False
    except Exception as e:
        logger.error(f"  Exception creating Skill_t: {e}")
        results['Skill_t'] = False

    return results


def main():
    logger.info("Creating typedefs...")
    typedef_results = create_typedefs_in_ghidra()

    logger.info("\n" + "="*60)
    logger.info("Retrying failed structures...")
    logger.info("="*60)
    struct_results = retry_failed_structures()

    # Print summary
    typedef_success = sum(1 for v in typedef_results.values() if v)
    struct_success = sum(1 for v in struct_results.values() if v)

    logger.info("\n" + "="*60)
    logger.info("SUMMARY")
    logger.info("="*60)
    logger.info(f"Typedefs created: {typedef_success}/{len(typedef_results)}")
    logger.info(f"Structures created: {struct_success}/{len(struct_results)}")

    total_failed = (len(typedef_results) - typedef_success) + (len(struct_results) - struct_success)
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
