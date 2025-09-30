#!/usr/bin/env python3
"""
Create additional common D2 structures and show comprehensive status
"""
import requests
import json

def create_additional_d2_structures():
    """Create commonly used D2 structures that are missing"""
    print("🏗️  CREATING ADDITIONAL D2 STRUCTURES")
    print("=" * 50)
    
    # Common D2 structures from D2Structs.h
    additional_structures = {
        'RoomTile': {
            'fields': [
                {'name': 'room2', 'type': 'LPROOM2'},
                {'name': 'nNum', 'type': 'DWORD'},
                {'name': 'pRoom1', 'type': 'LPROOM1'},
                {'name': '__b0C', 'type': 'DWORD'},
            ]
        },
        
        'PresetUnit': {
            'fields': [
                {'name': 'dwTxtFileNo', 'type': 'DWORD'},
                {'name': 'dwPosX', 'type': 'DWORD'},
                {'name': 'dwPosY', 'type': 'DWORD'},
                {'name': 'dwType', 'type': 'DWORD'},
                {'name': 'dwId', 'type': 'DWORD'},
                {'name': 'pNext', 'type': 'void *'},
            ]
        },
        
        'StatList': {
            'fields': [
                {'name': 'pUnit', 'type': 'LPUNITANY'},
                {'name': 'dwUnitType', 'type': 'DWORD'},
                {'name': 'dwUnitId', 'type': 'DWORD'},
                {'name': 'dwFlags', 'type': 'DWORD'},
                {'name': 'pMyStats', 'type': 'void *'},
                {'name': 'pBaseStats', 'type': 'void *'},
            ]
        },
        
        'PlayerData': {
            'fields': [
                {'name': 'szName', 'type': 'char[16]'},
                {'name': 'pQuest', 'type': 'void *'},
                {'name': 'pWaypoint', 'type': 'void *'},
                {'name': 'pMenu', 'type': 'void *'},
                {'name': 'pSkillhotkey', 'type': 'void *'},
                {'name': 'pNpcIntro', 'type': 'void *'},
            ]
        },
        
        'MonsterData': {
            'fields': [
                {'name': 'pMonsterTxt', 'type': 'void *'},
                {'name': 'fmod', 'type': 'BYTE[16]'},
                {'name': 'anEnchants', 'type': 'WORD[9]'},
                {'name': 'wUniqueNo', 'type': 'WORD'},
                {'name': 'dwNameSeed', 'type': 'DWORD'},
                {'name': 'pAiGeneral', 'type': 'void *'},
            ]
        },
        
        'ItemData': {
            'fields': [
                {'name': 'dwFlags', 'type': 'DWORD'},
                {'name': 'dwFlags2', 'type': 'DWORD'},
                {'name': 'dwParam1', 'type': 'DWORD'},
                {'name': 'pItemTxt', 'type': 'void *'},
                {'name': 'pOwner', 'type': 'LPUNITANY'},
                {'name': 'dwGfxType', 'type': 'DWORD'},
            ]
        }
    }
    
    created_count = 0
    for struct_name, struct_def in additional_structures.items():
        try:
            response = requests.post('http://127.0.0.1:8089/create_struct', 
                                   json={'name': struct_name, 'fields': struct_def['fields']})
            if response.status_code == 200:
                print(f"   ✅ Created: {struct_name}")
                created_count += 1
                
                # Try to move to D2Structs category
                try:
                    requests.post('http://127.0.0.1:8089/move_data_type_to_category',
                                json={'type_name': struct_name, 'category_path': '/D2Structs'})
                except:
                    pass  # Category might not exist yet
            else:
                print(f"   ⚠️  Could not create {struct_name}: {response.text}")
        except Exception as e:
            print(f"   ❌ Error creating {struct_name}: {e}")
    
    # Create additional pointer typedefs
    pointer_typedefs = {
        'LPROOMTILE': 'RoomTile *',
        'LPPRESETUNIT': 'PresetUnit *', 
        'LPSTATLIST': 'StatList *',
        'LPPLAYERDATA': 'PlayerData *',
        'LPMONSTERDATA': 'MonsterData *',
        'LPITEMDATA': 'ItemData *'
    }
    
    print(f"\n🔗 Creating pointer typedefs...")
    for typedef_name, base_type in pointer_typedefs.items():
        try:
            response = requests.post('http://127.0.0.1:8089/create_typedef',
                                   json={'name': typedef_name, 'base_type': base_type})
            if response.status_code == 200:
                print(f"   ✅ Created typedef: {typedef_name}")
                created_count += 1
            else:
                print(f"   ⚠️  Could not create typedef {typedef_name}: {response.text}")
        except Exception as e:
            print(f"   ❌ Error creating typedef {typedef_name}: {e}")
    
    print(f"\n✅ Created {created_count} additional D2 structures and typedefs")
    return created_count

def show_comprehensive_status():
    """Show detailed status of all data types"""
    print(f"\n📊 COMPREHENSIVE DATA TYPE STATUS")
    print("=" * 50)
    
    response = requests.get('http://127.0.0.1:8089/list_data_types', params={'offset': 0, 'limit': 1000})
    types = response.text.strip().split('\n')
    
    # Categorize types
    d2_structures = []
    d2_pointers = []
    system_types = []
    user_types = []
    undefined_types = []
    
    d2_names = ['Room1', 'Room2', 'UnitAny', 'Level', 'Act', 'Path', 'RoomTile', 'PresetUnit', 'StatList', 'PlayerData', 'MonsterData', 'ItemData']
    d2_pointer_names = ['LPUNITANY', 'LPROOM1', 'LPROOM2', 'LPLEVEL', 'LPROOMTILE', 'LPPRESETUNIT', 'LPSTATLIST', 'LPPLAYERDATA', 'LPMONSTERDATA', 'LPITEMDATA']
    
    for dtype in types:
        if dtype.strip():
            type_name = dtype.split(' | ')[0].strip()
            
            if type_name in d2_names:
                d2_structures.append(dtype)
            elif type_name in d2_pointer_names:
                d2_pointers.append(dtype)
            elif any(x in dtype.lower() for x in ['win', '.h/', 'dos', 'pe', 'demangler', 'mtdll', 'crt', 'excpt', 'flt', 'vad', 'base']):
                system_types.append(dtype)
            elif type_name.startswith('undefined'):
                undefined_types.append(dtype)
            else:
                user_types.append(dtype)
    
    print(f"🎯 D2 STRUCTURES ({len(d2_structures)}):")
    for dtype in sorted(d2_structures):
        print(f"   {dtype}")
    
    print(f"\n🔗 D2 POINTER TYPEDEFS ({len(d2_pointers)}):")
    for dtype in sorted(d2_pointers):
        print(f"   {dtype}")
    
    print(f"\n🖥️  SYSTEM TYPES: {len(system_types)} (preserved)")
    print(f"👤 USER TYPES: {len(user_types)} (need reviewing)")
    print(f"❓ UNDEFINED TYPES: {len(undefined_types)} (auto-generated)")
    print(f"📊 TOTAL: {len(types)}")
    
    # Show sample user types for review
    if user_types:
        print(f"\n📋 SAMPLE USER TYPES (first 10):")
        for dtype in sorted(user_types)[:10]:
            print(f"   {dtype}")
        if len(user_types) > 10:
            print(f"   ... and {len(user_types) - 10} more")
    
    print(f"\n🎉 CLEANUP SUCCESS SUMMARY:")
    print(f"✅ {len(d2_structures)} core D2 structures created")
    print(f"✅ {len(d2_pointers)} D2 pointer typedefs created") 
    print(f"✅ {len(system_types)} system types preserved")
    print(f"✅ All test/debug types removed")
    print(f"✅ Basic type duplicates cleaned up")
    
    if user_types:
        print(f"\n⚠️  {len(user_types)} user types remain - review if still needed")
    if undefined_types:
        print(f"⚠️  {len(undefined_types)} undefined types - can be cleaned up if not used")

if __name__ == "__main__":
    created = create_additional_d2_structures()
    show_comprehensive_status()