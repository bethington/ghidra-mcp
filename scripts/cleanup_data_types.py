#!/usr/bin/env python3
"""
Data Type Cleanup and Management Script
Cleans up existing data types and organizes them according to D2Structs.h
"""
import requests
import json
import time
import re

# List of structures that should be kept (from D2Structs.h)
D2_STRUCTURES = {
    'Act', 'ActMisc', 'AttackStruct', 'AutomapCell', 'AutomapLayer', 'AutomapLayer2',
    'BnetData', 'CellContext', 'CellFile', 'CollMap', 'Control', 'ControlText',
    'D2MSG', 'GameStructInfo', 'GfxCell', 'Info', 'InteractStruct', 'Inventory',
    'InventoryInfo', 'InventoryLayout', 'ItemData', 'ItemPath', 'ItemTxt',
    'Level', 'LevelNameInfo', 'LevelTxt', 'Light', 'MonsterData', 'MonsterTxt',
    'MpqTable', 'NPCMenu', 'ObjectData', 'ObjectPath', 'ObjectTxt', 'OverheadMsg',
    'PartyPlayer', 'Path', 'PlayerData', 'PresetUnit', 'QuestInfo', 'Room1',
    'Room2', 'RoomTile', 'RosterUnit', 'SMemBlock_t', 'Skill', 'SkillInfo', 'Skill_t',
    'Stat', 'StatList', 'TargetInfo', 'UnitAny', 'WardenClientRegion_t',
    'WardenClient_t', 'WardenIATInfo_t', 'Waypoint', 'sgptDataTable'
}

# Pointer typedefs that should be kept
D2_TYPEDEFS = {
    'LPROOMTILE', 'LPPRESETUNIT', 'LPUNITANY', 'LPLEVEL', 'LPROOM2', 'LPROOM1'
}

# System types that should be preserved (Windows/system headers)
SYSTEM_TYPE_PATTERNS = [
    r'.*\.h/', r'win.*', r'DOS', r'PE', r'Demangler', r'mtdll', r'crt', r'excpt', r'flt', r'vad', r'base'
]

def is_system_type(type_name):
    """Check if a type is a system/Windows type that should be preserved"""
    for pattern in SYSTEM_TYPE_PATTERNS:
        if re.search(pattern, type_name, re.IGNORECASE):
            return True
    return False

def get_current_data_types():
    """Get all current data types from Ghidra"""
    try:
        response = requests.get('http://127.0.0.1:8089/list_data_types', 
                              params={'offset': 0, 'limit': 1000})
        if response.status_code == 200:
            types = []
            for line in response.text.strip().split('\n'):
                if line.strip():
                    # Parse the format: "TypeName | category | size | path"
                    parts = line.split(' | ')
                    if len(parts) >= 1:
                        type_name = parts[0].strip()
                        types.append({
                            'name': type_name,
                            'full_line': line.strip()
                        })
            return types
        else:
            print(f"Error getting data types: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error getting data types: {e}")
        return []

def delete_data_type(type_name):
    """Delete a data type"""
    try:
        response = requests.post('http://127.0.0.1:8089/delete_data_type', 
                               json={'type_name': type_name})
        return response.status_code == 200, response.text
    except Exception as e:
        return False, str(e)

def create_d2_category():
    """Create a category for D2 structures"""
    try:
        response = requests.post('http://127.0.0.1:8089/create_data_type_category', 
                               json={'category_path': 'D2Structs'})
        return response.status_code == 200, response.text
    except Exception as e:
        return False, str(e)

def move_type_to_category(type_name, category):
    """Move a data type to a specific category"""
    try:
        response = requests.post('http://127.0.0.1:8089/move_data_type_to_category', 
                               json={'type_name': type_name, 'category_path': category})
        return response.status_code == 200, response.text
    except Exception as e:
        return False, str(e)

def analyze_and_cleanup():
    """Main cleanup function"""
    print("🧹 DATA TYPE CLEANUP AND MANAGEMENT")
    print("=" * 60)
    
    # Get current data types
    print("📊 Analyzing current data types...")
    current_types = get_current_data_types()
    print(f"Found {len(current_types)} data types")
    
    # Categorize types
    d2_types = []
    test_types = []
    system_types = []
    other_types = []
    
    for dtype in current_types:
        name = dtype['name']
        
        if is_system_type(dtype['full_line']):
            system_types.append(dtype)
        elif name in D2_STRUCTURES or name in D2_TYPEDEFS:
            d2_types.append(dtype)
        elif any(keyword in name.lower() for keyword in ['test', 'debug', 'temp', 'concurrent', 'mcp', 'demo', 'comprehensive']):
            test_types.append(dtype)
        else:
            other_types.append(dtype)
    
    print(f"📈 Type Analysis:")
    print(f"  🎯 D2 Structures: {len(d2_types)}")
    print(f"  🧪 Test/Debug Types: {len(test_types)}")
    print(f"  🖥️  System Types: {len(system_types)}")
    print(f"  ❓ Other Types: {len(other_types)}")
    
    # Create D2 category
    print("\n📁 Creating D2Structs category...")
    success, message = create_d2_category()
    if success:
        print(f"   ✅ Category created: {message}")
    else:
        print(f"   ⚠️  Category creation: {message}")
    
    # Clean up test types
    print(f"\n🗑️  Cleaning up {len(test_types)} test/debug types...")
    deleted_count = 0
    failed_deletes = []
    
    for dtype in test_types:
        print(f"   Deleting: {dtype['name']}")
        success, message = delete_data_type(dtype['name'])
        if success:
            deleted_count += 1
            print(f"     ✅ Deleted")
        else:
            failed_deletes.append((dtype['name'], message))
            print(f"     ❌ Failed: {message}")
    
    print(f"\n✅ Deleted {deleted_count} test types")
    if failed_deletes:
        print(f"❌ Failed to delete {len(failed_deletes)} types:")
        for name, error in failed_deletes:
            print(f"   - {name}: {error}")
    
    # Move D2 types to D2 category
    print(f"\n📦 Moving {len(d2_types)} D2 types to D2Structs category...")
    moved_count = 0
    failed_moves = []
    
    for dtype in d2_types:
        print(f"   Moving: {dtype['name']} to D2Structs")
        success, message = move_type_to_category(dtype['name'], 'D2Structs')
        if success:
            moved_count += 1
            print(f"     ✅ Moved")
        else:
            failed_moves.append((dtype['name'], message))
            print(f"     ⚠️  Move result: {message}")
    
    print(f"\n✅ Moved {moved_count} D2 types to D2Structs category")
    if failed_moves:
        print(f"⚠️  Move issues for {len(failed_moves)} types (may be expected):")
        for name, error in failed_moves[:5]:  # Show first 5
            print(f"   - {name}: {error}")
    
    # Report on other types
    if other_types:
        print(f"\n❓ Found {len(other_types)} other user-defined types:")
        for dtype in other_types[:10]:  # Show first 10
            print(f"   - {dtype['name']}")
        if len(other_types) > 10:
            print(f"   ... and {len(other_types) - 10} more")
        print("   These may need manual review to determine if they should be kept or moved.")
    
    # Create summary report
    summary = {
        'timestamp': int(time.time()),
        'cleanup_stats': {
            'total_types_found': len(current_types),
            'd2_types': len(d2_types),
            'test_types_deleted': deleted_count,
            'system_types_preserved': len(system_types),
            'other_types_remaining': len(other_types),
            'd2_types_moved': moved_count
        },
        'failed_deletes': failed_deletes,
        'failed_moves': failed_moves,
        'other_types': [t['name'] for t in other_types]
    }
    
    # Save summary
    timestamp = int(time.time())
    report_file = f"logs/data_type_cleanup_{timestamp}.json"
    try:
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\n📝 Cleanup report saved to: {report_file}")
    except Exception as e:
        print(f"⚠️  Could not save report: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 DATA TYPE CLEANUP COMPLETED")
    print("=" * 60)
    print(f"✅ Deleted {deleted_count} test/debug types")
    print(f"📦 Organized {moved_count} D2 types into D2Structs category")
    print(f"🖥️  Preserved {len(system_types)} system types")
    print(f"❓ {len(other_types)} other types need manual review")
    
    if other_types:
        print("\n⚠️  MANUAL REVIEW NEEDED:")
        print("The following types were not automatically categorized:")
        for dtype in other_types:
            print(f"  - {dtype['name']}")
        print("\nPlease review these types and either:")
        print("  1. Delete them if they're not needed")
        print("  2. Move them to appropriate categories")
        print("  3. Keep them if they're legitimate D2 structures not in the header")

if __name__ == "__main__":
    analyze_and_cleanup()