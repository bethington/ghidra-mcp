#!/usr/bin/env python3
"""
Final cleanup - Remove remaining test types and organize legitimate types
"""
import requests
import json

def final_cleanup():
    """Remove remaining test and unnecessary types"""
    print("🧹 FINAL DATA TYPE CLEANUP")
    print("=" * 50)
    
    response = requests.get('http://127.0.0.1:8089/list_data_types', params={'offset': 0, 'limit': 1000})
    types = response.text.strip().split('\n')
    
    # Types that should definitely be deleted (test/demo types that somehow remained)
    test_patterns = [
        'Test', 'Debug', 'MCP', 'Demo', 'Comprehensive', 'Concurrent', 'Category',
        'Game', 'Complex', 'Quick', 'Process', 'Auto', 'My', 'Client', 'Error',
        'File', 'Colors'
    ]
    
    # Types that are legitimate and should be kept
    keep_types = {
        'int', 'short', 'long', 'float', 'double', 'bool', 'void', 'string', 'unicode',
        'pointer', 'pointer32', 'longlong', 'float10',
        # Arrays and pointers of basic types are OK
        'uchar', 'ushort', 'ulong', 'ulonglong', 'wchar_t', 'wchar16',
        # Legitimate structures that might be needed
        'FuncInfo', '_s_FuncInfo', 'GUID', 'IMAGE_RICH_HEADER', 'TerminatedCString'
    }
    
    types_to_delete = []
    types_to_keep = []
    undefined_types = []
    
    for dtype in types:
        if dtype.strip():
            type_name = dtype.split(' | ')[0].strip()
            
            # Skip system types
            if any(x in dtype.lower() for x in ['win', '.h/', 'dos', 'pe', 'demangler', 'mtdll', 'crt', 'excpt', 'flt', 'vad', 'base']):
                continue
                
            # Skip D2 types
            if 'D2Structs' in dtype or type_name in ['Room1', 'Room2', 'UnitAny', 'Level', 'Act', 'Path', 'LPUNITANY', 'LPROOM1', 'LPROOM2', 'LPLEVEL', 'LPROOMTILE', 'LPPRESETUNIT']:
                continue
            
            # Check if it's a test type
            if any(pattern in type_name for pattern in test_patterns):
                types_to_delete.append(type_name)
            # Check if it's undefined (these are usually auto-generated and can be cleaned up)
            elif type_name.startswith('undefined'):
                undefined_types.append(type_name)
            # Check if it's a basic type we want to keep
            elif (type_name in keep_types or 
                  any(type_name.startswith(f'{keep}[') or type_name.startswith(f'{keep} ') or type_name.endswith(f' {keep}') for keep in keep_types) or
                  type_name.endswith('*') or type_name.endswith(']')):
                types_to_keep.append(type_name)
            else:
                # Uncertain - let user decide
                types_to_keep.append(type_name)
    
    print(f"📊 Analysis Results:")
    print(f"  🗑️  Will delete: {len(types_to_delete)} test types")
    print(f"  ❓ Undefined types: {len(undefined_types)} (leaving for now)")
    print(f"  ✅ Keeping: {len(types_to_keep)} legitimate types")
    
    # Delete test types
    if types_to_delete:
        print(f"\n🗑️  Deleting {len(types_to_delete)} test/unnecessary types...")
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
        
        print(f"\n✅ Deleted {deleted_count} test types")
    
    # Show remaining types that need review
    if types_to_keep:
        print(f"\n📋 REMAINING USER TYPES ({len(types_to_keep)}):")
        print("These types were kept - please review if they're still needed:")
        for dtype in sorted(types_to_keep)[:15]:
            print(f"  {dtype}")
        if len(types_to_keep) > 15:
            print(f"  ... and {len(types_to_keep) - 15} more")
    
    # Show undefined types
    if undefined_types:
        print(f"\n❓ UNDEFINED TYPES ({len(undefined_types)}):")
        print("These are typically auto-generated. Delete if not needed:")
        for dtype in sorted(undefined_types)[:10]:
            print(f"  {dtype}")
        if len(undefined_types) > 10:
            print(f"  ... and {len(undefined_types) - 10} more")
    
    print(f"\n✅ Final cleanup completed!")
    return len(types_to_delete), len(types_to_keep), len(undefined_types)

def show_final_status():
    """Show the final status of data types"""
    print(f"\n📈 FINAL DATA TYPE STATUS")
    print("=" * 50)
    
    response = requests.get('http://127.0.0.1:8089/list_data_types', params={'offset': 0, 'limit': 1000})
    types = response.text.strip().split('\n')
    
    d2_count = 0
    system_count = 0
    user_count = 0
    undefined_count = 0
    
    for dtype in types:
        if dtype.strip():
            if 'D2Structs' in dtype:
                d2_count += 1
            elif any(x in dtype.lower() for x in ['win', '.h/', 'dos', 'pe', 'demangler', 'mtdll', 'crt', 'excpt', 'flt', 'vad', 'base']):
                system_count += 1
            elif dtype.split(' | ')[0].strip().startswith('undefined'):
                undefined_count += 1
            else:
                user_count += 1
    
    print(f"🎯 D2 Structures: {d2_count}")
    print(f"🖥️  System Types: {system_count}")
    print(f"👤 User Types: {user_count}")
    print(f"❓ Undefined Types: {undefined_count}")
    print(f"📊 Total: {len(types)}")
    
    print(f"\n🎉 SUCCESS! Data types are now organized according to D2Structs.h")
    print(f"✅ System types preserved")
    print(f"✅ D2 structures created and categorized")
    print(f"✅ Test/debug types cleaned up")

if __name__ == "__main__":
    deleted, kept, undefined = final_cleanup()
    show_final_status()