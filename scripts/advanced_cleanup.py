#!/usr/bin/env python3
"""
Advanced Data Type Cleanup - Replace user types with system equivalents and create D2 structures
"""
import requests
import json
import time

# Mapping of user types to system equivalents
TYPE_REPLACEMENTS = {
    'byte': 'BYTE',
    'word': 'WORD', 
    'dword': 'DWORD',
    'char': 'CHAR',
    'uint': 'UINT',
    # Keep basic built-in types that don't have direct Windows equivalents
    # 'int', 'short', 'long', 'float', etc. should remain as they are standard C types
}

def delete_redundant_basic_types():
    """Delete user-defined basic types that have system equivalents"""
    print("🧹 CLEANING UP REDUNDANT BASIC TYPES")
    print("=" * 50)
    
    types_to_delete = []
    
    # Get current types
    response = requests.get('http://127.0.0.1:8089/list_data_types', params={'offset': 0, 'limit': 1000})
    if response.status_code != 200:
        print("❌ Failed to get data types")
        return
    
    types = response.text.strip().split('\n')
    
    for dtype in types:
        if dtype.strip():
            type_name = dtype.split(' | ')[0].strip()
            
            # Check if this is a redundant basic type
            if type_name in TYPE_REPLACEMENTS:
                types_to_delete.append(type_name)
            # Also delete array versions of redundant types
            elif any(type_name.startswith(f'{redundant}[') for redundant in TYPE_REPLACEMENTS):
                types_to_delete.append(type_name)
    
    deleted_count = 0
    for type_name in types_to_delete:
        try:
            response = requests.post('http://127.0.0.1:8089/delete_data_type', 
                                   json={'type_name': type_name})
            if response.status_code == 200:
                print(f"   ✅ Deleted: {type_name}")
                deleted_count += 1
            else:
                print(f"   ⚠️  Could not delete {type_name}: {response.text}")
        except Exception as e:
            print(f"   ❌ Error deleting {type_name}: {e}")
    
    print(f"\n✅ Deleted {deleted_count} redundant basic types")
    return deleted_count

def create_d2_structures():
    """Create the D2 structures from D2Structs.h"""
    print("\n🏗️  CREATING D2 STRUCTURES")
    print("=" * 50)
    
    # Define key D2 structures with their fields
    d2_structures = {
        'Room1': [
            {'name': 'pRoomsNear', 'type': 'Room1**'},
            {'name': '_1', 'type': 'DWORD[3]'},
            {'name': 'pRoom2', 'type': 'Room2*'},
            {'name': '_2', 'type': 'DWORD[3]'},
            {'name': 'Coll', 'type': 'CollMap*'},
            {'name': 'dwRoomsNear', 'type': 'DWORD'},
            {'name': '_3', 'type': 'DWORD[9]'},
            {'name': 'dwXStart', 'type': 'DWORD'},
            {'name': 'dwYStart', 'type': 'DWORD'},
            {'name': 'dwXSize', 'type': 'DWORD'},
            {'name': 'dwYSize', 'type': 'DWORD'},
            {'name': '_4', 'type': 'DWORD[6]'},
            {'name': 'pUnitFirst', 'type': 'UnitAny*'},
            {'name': '_5', 'type': 'DWORD'},
            {'name': 'pRoomNext', 'type': 'Room1*'}
        ],
        
        'Room2': [
            {'name': '_1', 'type': 'DWORD[2]'},
            {'name': 'pRoom2Next', 'type': 'Room2*'},
            {'name': 'dwRoomFlags', 'type': 'DWORD'},
            {'name': 'dwRoomsNear', 'type': 'DWORD'},
            {'name': 'pRoom1', 'type': 'Room1*'},
            {'name': 'dwPosX', 'type': 'DWORD'},
            {'name': 'dwPosY', 'type': 'DWORD'},
            {'name': 'dwSizeX', 'type': 'DWORD'},
            {'name': 'dwSizeY', 'type': 'DWORD'},
            {'name': '_3', 'type': 'DWORD'},
            {'name': 'dwPresetType', 'type': 'DWORD'},
            {'name': 'pRoomTiles', 'type': 'RoomTile*'},
            {'name': '_4', 'type': 'DWORD[2]'},
            {'name': 'pLevel', 'type': 'Level*'},
            {'name': 'pPreset', 'type': 'PresetUnit*'}
        ],
        
        'UnitAny': [
            {'name': 'dwType', 'type': 'DWORD'},
            {'name': 'dwTxtFileNo', 'type': 'DWORD'},
            {'name': '_1', 'type': 'DWORD'},
            {'name': 'dwUnitId', 'type': 'DWORD'},
            {'name': 'dwMode', 'type': 'DWORD'},
            {'name': 'pPlayerData', 'type': 'void*'},  # Union - using void* for now
            {'name': 'dwAct', 'type': 'DWORD'},
            {'name': 'pAct', 'type': 'Act*'},
            {'name': 'dwSeed', 'type': 'DWORD[2]'},
            {'name': '_2', 'type': 'DWORD'},
            {'name': 'pPath', 'type': 'Path*'},
            {'name': '_3', 'type': 'DWORD[5]'},
            {'name': 'dwGfxFrame', 'type': 'DWORD'},
            {'name': 'dwFrameRemain', 'type': 'DWORD'},
            {'name': 'wFrameRate', 'type': 'WORD'},
            {'name': '_4', 'type': 'WORD'},
            {'name': 'pGfxUnk', 'type': 'BYTE*'},
            {'name': 'pGfxInfo', 'type': 'DWORD*'},
            {'name': '_5', 'type': 'DWORD'},
            {'name': 'pStats', 'type': 'StatList*'},
            {'name': 'pInventory', 'type': 'Inventory*'},
            {'name': 'ptLight', 'type': 'Light*'},
            {'name': '_6', 'type': 'DWORD[9]'},
            {'name': 'wX', 'type': 'WORD'},
            {'name': 'wY', 'type': 'WORD'},
            {'name': '_7', 'type': 'DWORD'},
            {'name': 'dwOwnerType', 'type': 'DWORD'},
            {'name': 'dwOwnerId', 'type': 'DWORD'},
            {'name': '_8', 'type': 'DWORD[2]'},
            {'name': 'pOMsg', 'type': 'OverheadMsg*'},
            {'name': 'pInfo', 'type': 'Info*'},
            {'name': '_9', 'type': 'DWORD[6]'},
            {'name': 'dwFlags', 'type': 'DWORD'},
            {'name': 'dwFlags2', 'type': 'DWORD'},
            {'name': '_10', 'type': 'DWORD[5]'},
            {'name': 'pChangedNext', 'type': 'UnitAny*'},
            {'name': 'pRoomNext', 'type': 'UnitAny*'},
            {'name': 'pListNext', 'type': 'UnitAny*'},
            {'name': 'szNameCopy', 'type': 'CHAR[16]'}
        ],
        
        'Level': [
            {'name': 'dwLevelNo', 'type': 'DWORD'},
            {'name': 'dwPosX', 'type': 'DWORD'},
            {'name': 'dwPosY', 'type': 'DWORD'},
            {'name': 'dwSizeX', 'type': 'DWORD'},
            {'name': 'dwSizeY', 'type': 'DWORD'},
            {'name': '_1', 'type': 'DWORD[96]'},  # Large padding
            {'name': 'pRoom2First', 'type': 'Room2*'},
            {'name': 'pActMisc', 'type': 'ActMisc*'},
            {'name': 'dwLevelFlags', 'type': 'DWORD'},
            {'name': 'pLevelNext', 'type': 'Level*'}
        ],
        
        'Act': [
            {'name': '_1', 'type': 'DWORD[3]'},
            {'name': 'dwMapSeed', 'type': 'DWORD'},
            {'name': 'pRoom1', 'type': 'Room1*'},
            {'name': 'dwAct', 'type': 'DWORD'},
            {'name': '_2', 'type': 'DWORD[12]'},
            {'name': 'pMisc', 'type': 'ActMisc*'}
        ],
        
        'Path': [
            {'name': 'xOffset', 'type': 'WORD'},
            {'name': 'xPos', 'type': 'WORD'},
            {'name': 'yOffset', 'type': 'WORD'},
            {'name': 'yPos', 'type': 'WORD'},
            {'name': '_1', 'type': 'DWORD[2]'},
            {'name': 'xTarget', 'type': 'WORD'},
            {'name': 'yTarget', 'type': 'WORD'},
            {'name': '_2', 'type': 'DWORD[2]'},
            {'name': 'pRoom1', 'type': 'Room1*'},
            {'name': 'pRoomUnk', 'type': 'Room1*'},
            {'name': '_3', 'type': 'DWORD[3]'},
            {'name': 'pUnit', 'type': 'UnitAny*'},
            {'name': 'dwFlags', 'type': 'DWORD'},
            {'name': '_4', 'type': 'DWORD'},
            {'name': 'dwPathType', 'type': 'DWORD'},
            {'name': 'dwPrevPathType', 'type': 'DWORD'},
            {'name': 'dwUnitSize', 'type': 'DWORD'},
            {'name': '_5', 'type': 'DWORD[4]'},
            {'name': 'pTargetUnit', 'type': 'UnitAny*'},
            {'name': 'dwTargetType', 'type': 'DWORD'},
            {'name': 'dwTargetId', 'type': 'DWORD'},
            {'name': 'bDirection', 'type': 'BYTE'}
        ]
    }
    
    created_count = 0
    skipped_count = 0
    
    for struct_name, fields in d2_structures.items():
        try:
            response = requests.post('http://127.0.0.1:8089/create_struct', 
                                   json={'name': struct_name, 'fields': fields})
            if response.status_code == 200:
                print(f"   ✅ Created: {struct_name}")
                created_count += 1
                
                # Move to D2Structs category
                try:
                    cat_response = requests.post('http://127.0.0.1:8089/move_data_type_to_category',
                                               json={'type_name': struct_name, 'category_path': 'D2Structs'})
                    if cat_response.status_code == 200:
                        print(f"      📦 Moved to D2Structs category")
                    else:
                        print(f"      ⚠️  Category move: {cat_response.text}")
                except Exception as e:
                    print(f"      ⚠️  Category move error: {e}")
                    
            else:
                if "already exists" in response.text:
                    print(f"   ⚠️  Skipped: {struct_name} (already exists)")
                    skipped_count += 1
                else:
                    print(f"   ❌ Failed to create {struct_name}: {response.text}")
        except Exception as e:
            print(f"   ❌ Error creating {struct_name}: {e}")
    
    print(f"\n✅ Created {created_count} D2 structures")
    if skipped_count > 0:
        print(f"⚠️  Skipped {skipped_count} existing structures")
    
    return created_count

def create_pointer_typedefs():
    """Create the pointer typedefs from D2Structs.h"""
    print("\n👉 CREATING POINTER TYPEDEFS")
    print("=" * 50)
    
    pointer_typedefs = {
        'LPUNITANY': 'UnitAny*',
        'LPROOM1': 'Room1*', 
        'LPROOM2': 'Room2*',
        'LPLEVEL': 'Level*',
        'LPROOMTILE': 'RoomTile*',
        'LPPRESETUNIT': 'PresetUnit*'
    }
    
    created_count = 0
    
    for typedef_name, base_type in pointer_typedefs.items():
        try:
            # Create using create_pointer_type
            response = requests.post('http://127.0.0.1:8089/create_pointer_type',
                                   json={'base_type': base_type.replace('*', ''), 'name': typedef_name})
            if response.status_code == 200:
                print(f"   ✅ Created: {typedef_name} -> {base_type}")
                created_count += 1
            else:
                print(f"   ⚠️  {typedef_name}: {response.text}")
        except Exception as e:
            print(f"   ❌ Error creating {typedef_name}: {e}")
    
    print(f"\n✅ Created {created_count} pointer typedefs")
    return created_count

def main():
    """Main cleanup and setup function"""
    print("🚀 ADVANCED DATA TYPE MANAGEMENT")
    print("=" * 60)
    print("This will:")
    print("1. Delete redundant basic types that have system equivalents")
    print("2. Create core D2 structures from D2Structs.h")
    print("3. Create pointer typedefs")
    print("4. Organize everything into D2Structs category")
    print("=" * 60)
    
    # Step 1: Clean up redundant basic types
    deleted_basic = delete_redundant_basic_types()
    
    # Step 2: Create D2 structures
    created_structs = create_d2_structures()
    
    # Step 3: Create pointer typedefs
    created_typedefs = create_pointer_typedefs()
    
    # Final summary
    print("\n" + "=" * 60)
    print("🎉 ADVANCED CLEANUP COMPLETED")
    print("=" * 60)
    print(f"✅ Deleted {deleted_basic} redundant basic types")
    print(f"🏗️  Created {created_structs} D2 structures")
    print(f"👉 Created {created_typedefs} pointer typedefs")
    print("\n📋 RECOMMENDATIONS:")
    print("1. Review remaining undefined arrays - they may be legitimate structure members")
    print("2. Check if any custom structures (GameUnit, UnitGroup, etc.) are still needed")
    print("3. Verify that all D2 structures are correctly defined and match the binary")
    
    # Save summary
    summary = {
        'timestamp': int(time.time()),
        'advanced_cleanup': {
            'deleted_basic_types': deleted_basic,
            'created_d2_structures': created_structs,
            'created_pointer_typedefs': created_typedefs
        }
    }
    
    try:
        with open(f"logs/advanced_cleanup_{int(time.time())}.json", 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"💾 Results saved to logs/advanced_cleanup_{int(time.time())}.json")
    except Exception as e:
        print(f"⚠️  Could not save results: {e}")

if __name__ == "__main__":
    main()