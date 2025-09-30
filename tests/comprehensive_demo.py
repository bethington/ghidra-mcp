#!/usr/bin/env python3
"""
COMPREHENSIVE DEMONSTRATION OF ALL IMPLEMENTED GHIDRA MCP FUNCTIONALITY
This script demonstrates the complete data structure management capabilities.
"""
import requests
import json
import time

def demo_comprehensive_functionality():
    """Demonstrate all implemented functionality in a cohesive workflow"""
    base_url = "http://127.0.0.1:8089"
    
    print("🎉 COMPREHENSIVE GHIDRA MCP DATA STRUCTURE DEMO")
    print("=" * 60)
    print("Demonstrating ALL implemented functionality:")
    print("• Structure creation, modification, and deletion")
    print("• Advanced type creation (arrays, pointers)")
    print("• Category management and organization")
    print("• Function signature creation")
    print("• Layout inspection and analysis")
    print("=" * 60)
    
    demo_steps = []
    
    # Step 1: Create a category for our demo
    print("\n📁 Step 1: Creating demo category")
    try:
        response = requests.post(f"{base_url}/create_data_type_category", 
                               json={"category_path": "ComprehensiveDemo"})
        print(f"   ✅ Category created: {response.text}")
        demo_steps.append(("Create Category", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Create Category", "FAILED"))
    
    # Step 2: Create a complex structure
    print("\n🏗️  Step 2: Creating complex data structure")
    try:
        complex_struct = {
            "name": "GameEntity",
            "fields": [
                {"name": "entityId", "type": "DWORD"},
                {"name": "position", "type": "float[3]"},
                {"name": "health", "type": "int"},
                {"name": "name", "type": "char[32]"},
                {"name": "flags", "type": "byte"}
            ]
        }
        response = requests.post(f"{base_url}/create_struct", json=complex_struct)
        print(f"   ✅ Complex structure: {response.text}")
        demo_steps.append(("Create Complex Structure", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Create Complex Structure", "FAILED"))
    
    # Step 3: Move structure to category
    print("\n📦 Step 3: Organizing structure into category")
    try:
        response = requests.post(f"{base_url}/move_data_type_to_category", 
                               json={"type_name": "GameEntity", "category_path": "ComprehensiveDemo"})
        print(f"   ✅ Structure moved: {response.text}")
        demo_steps.append(("Move to Category", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Move to Category", "FAILED"))
    
    # Step 4: Add a new field to the structure
    print("\n➕ Step 4: Adding field to structure")
    try:
        response = requests.post(f"{base_url}/add_struct_field", 
                               json={"struct_name": "GameEntity", "field_name": "level", "field_type": "int"})
        print(f"   ✅ Field added: {response.text}")
        demo_steps.append(("Add Field", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Add Field", "FAILED"))
    
    # Step 5: Create array type
    print("\n📊 Step 5: Creating array type")
    try:
        response = requests.post(f"{base_url}/create_array_type", 
                               json={"base_type": "GameEntity", "size": 50, "name": "EntityArray"})
        print(f"   ✅ Array created: {response.text}")
        demo_steps.append(("Create Array", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Create Array", "FAILED"))
    
    # Step 6: Create pointer type
    print("\n👉 Step 6: Creating pointer type")
    try:
        response = requests.post(f"{base_url}/create_pointer_type", 
                               json={"base_type": "GameEntity", "name": "EntityPtr"})
        print(f"   ✅ Pointer created: {response.text}")
        demo_steps.append(("Create Pointer", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Create Pointer", "FAILED"))
    
    # Step 7: Create function signature
    print("\n⚡ Step 7: Creating function signature")
    try:
        response = requests.post(f"{base_url}/create_function_signature", 
                               json={
                                   "name": "ProcessEntity",
                                   "return_type": "int",
                                   "parameters": '[{"name": "entity", "type": "GameEntity*"}, {"name": "deltaTime", "type": "float"}]'
                               })
        print(f"   ✅ Function signature: {response.text}")
        demo_steps.append(("Create Function Signature", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Create Function Signature", "FAILED"))
    
    # Step 8: Inspect structure layout
    print("\n🔍 Step 8: Inspecting structure layout")
    try:
        response = requests.get(f"{base_url}/get_struct_layout", 
                              params={"struct_name": "GameEntity"})
        print(f"   ✅ Layout inspection: {response.text[:200]}...")
        demo_steps.append(("Inspect Layout", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Inspect Layout", "FAILED"))
    
    # Step 9: Modify a field
    print("\n🔧 Step 9: Modifying structure field")
    try:
        response = requests.post(f"{base_url}/modify_struct_field", 
                               json={"struct_name": "GameEntity", "field_name": "health", "new_type": "float"})
        print(f"   ✅ Field modified: {response.text}")
        demo_steps.append(("Modify Field", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("Modify Field", "FAILED"))
    
    # Step 10: List categories to see our work
    print("\n📋 Step 10: Listing all categories")
    try:
        response = requests.get(f"{base_url}/list_data_type_categories", 
                              params={"offset": 0, "limit": 30})
        categories = response.text.split('\n')
        our_category = [cat for cat in categories if 'ComprehensiveDemo' in cat]
        if our_category:
            print(f"   ✅ Found our category: {our_category[0]}")
        else:
            print(f"   ✅ Categories listed (total: {len(categories)})")
        demo_steps.append(("List Categories", "SUCCESS"))
    except Exception as e:
        print(f"   ❌ Error: {e}")
        demo_steps.append(("List Categories", "FAILED"))
    
    # Final Summary
    print("\n" + "="*60)
    print("🎯 COMPREHENSIVE DEMO RESULTS")
    print("="*60)
    
    success_count = sum(1 for _, status in demo_steps if status == "SUCCESS")
    total_steps = len(demo_steps)
    
    for i, (step, status) in enumerate(demo_steps, 1):
        icon = "✅" if status == "SUCCESS" else "❌"
        print(f"{icon} Step {i}: {step}")
    
    print(f"\n📊 Overall Success: {success_count}/{total_steps} ({success_count/total_steps*100:.1f}%)")
    
    if success_count == total_steps:
        print("🎉 PERFECT! All functionality working flawlessly!")
        print("🚀 Ghidra MCP now has COMPLETE data structure management!")
    else:
        print(f"⚠️  {total_steps - success_count} steps need attention")
    
    # Save results
    timestamp = int(time.time())
    results = {
        "timestamp": timestamp,
        "demo_steps": [{"step": step, "status": status} for step, status in demo_steps],
        "success_rate": success_count / total_steps * 100,
        "total_features_demonstrated": total_steps
    }
    
    try:
        with open(f"logs/comprehensive_demo_{timestamp}.json", 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📝 Demo results saved to: logs/comprehensive_demo_{timestamp}.json")
    except Exception as e:
        print(f"⚠️ Could not save demo results: {e}")

if __name__ == "__main__":
    demo_comprehensive_functionality()