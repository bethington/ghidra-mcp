#!/usr/bin/env python3
"""
Test script for comprehensive category management and advanced data type functionality
"""
import json
import requests
import time

def test_category_management():
    """Test category management functionality"""
    base_url = "http://127.0.0.1:8089"
    
    print("🧪 Testing Category Management & Advanced Functionality")
    print("=" * 60)
    
    test_results = []
    
    # Test 1: Create data type category
    print("\n📁 Test 1: Create data type category")
    try:
        response = requests.post(f"{base_url}/create_data_type_category", 
                               json={"category_path": "MyCustomTypes"}, 
                               timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   {status}: {response.text[:100]}")
        test_results.append(("create_data_type_category", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("create_data_type_category", "ERROR", str(e)))
    
    # Test 2: List data type categories
    print("\n📋 Test 2: List data type categories")
    try:
        response = requests.get(f"{base_url}/list_data_type_categories", 
                              params={"offset": 0, "limit": 50}, 
                              timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   {status}: {response.text[:200]}")
        test_results.append(("list_data_type_categories", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("list_data_type_categories", "ERROR", str(e)))
    
    # Test 3: Create test structure first
    print("\n🏗️  Test 3: Create test structure for category testing")
    try:
        test_struct = {
            "name": "CategoryTestStruct",
            "fields": [
                {"name": "id", "type": "int"},
                {"name": "value", "type": "float"}
            ]
        }
        response = requests.post(f"{base_url}/create_struct", 
                               json=test_struct, 
                               timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   {status}: {response.text[:100]}")
        test_results.append(("create_struct_for_category", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("create_struct_for_category", "ERROR", str(e)))
    
    # Test 4: Move data type to category
    print("\n📦 Test 4: Move data type to category")
    try:
        response = requests.post(f"{base_url}/move_data_type_to_category", 
                               json={"type_name": "CategoryTestStruct", "category_path": "MyCustomTypes"}, 
                               timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   {status}: {response.text[:100]}")
        test_results.append(("move_data_type_to_category", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("move_data_type_to_category", "ERROR", str(e)))
    
    # Test 5: Create function signature
    print("\n⚡ Test 5: Create function signature")
    try:
        response = requests.post(f"{base_url}/create_function_signature", 
                               json={
                                   "name": "TestFunction",
                                   "return_type": "int",
                                   "parameters": '[{"name": "param1", "type": "int"}, {"name": "param2", "type": "char*"}]'
                               }, 
                               timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   {status}: {response.text[:100]}")
        test_results.append(("create_function_signature", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("create_function_signature", "ERROR", str(e)))
    
    # Test 6: Test enhanced structure operations
    print("\n🔧 Test 6: Enhanced structure operations")
    try:
        # Create a more complex structure
        complex_struct = {
            "name": "ComplexStruct",
            "fields": [
                {"name": "header", "type": "DWORD"},
                {"name": "flags", "type": "byte"},
                {"name": "data", "type": "char[32]"},
                {"name": "pointer", "type": "void*"}
            ]
        }
        response = requests.post(f"{base_url}/create_struct", 
                               json=complex_struct, 
                               timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   Complex struct creation: {status}: {response.text[:100]}")
        test_results.append(("create_complex_struct", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("create_complex_struct", "ERROR", str(e)))
    
    # Test 7: Multi-dimensional arrays
    print("\n📊 Test 7: Multi-dimensional array creation")
    try:
        response = requests.post(f"{base_url}/create_array_type", 
                               json={"base_type": "int", "size": 100, "name": "LargeIntArray"}, 
                               timeout=10)
        status = "✅ PASS" if response.status_code == 200 else f"❌ FAIL ({response.status_code})"
        print(f"   {status}: {response.text[:100]}")
        test_results.append(("create_large_array", response.status_code, response.text))
    except Exception as e:
        print(f"   ❌ EXCEPTION: {e}")
        test_results.append(("create_large_array", "ERROR", str(e)))
    
    # Generate comprehensive report
    print("\n" + "="*60)
    print("📊 COMPREHENSIVE TEST RESULTS")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for test_name, status_code, response_text in test_results:
        if isinstance(status_code, int) and status_code == 200:
            print(f"✅ {test_name}: PASS")
            passed += 1
        else:
            print(f"❌ {test_name}: FAIL ({status_code})")
            failed += 1
    
    print(f"\n📈 Summary: {passed} passed, {failed} failed")
    print(f"🎯 Success Rate: {(passed/(passed+failed)*100):.1f}%")
    
    # Save detailed results
    timestamp = int(time.time())
    results_file = f"logs/category_management_test_{timestamp}.json"
    
    detailed_results = {
        "timestamp": timestamp,
        "summary": {
            "passed": passed,
            "failed": failed,
            "success_rate": passed/(passed+failed)*100 if (passed+failed) > 0 else 0
        },
        "test_results": [
            {
                "test_name": name,
                "status_code": status,
                "response": response[:500] if isinstance(response, str) else str(response)[:500]
            }
            for name, status, response in test_results
        ]
    }
    
    try:
        with open(results_file, 'w') as f:
            json.dump(detailed_results, f, indent=2)
        print(f"📝 Detailed results saved to: {results_file}")
    except Exception as e:
        print(f"⚠️ Could not save results file: {e}")
    
    return passed, failed

if __name__ == "__main__":
    test_category_management()