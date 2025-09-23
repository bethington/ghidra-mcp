#!/usr/bin/env python3

import requests
import json
import time

def test_data_type_summary():
    """Comprehensive summary test of all data type creation."""
    
    print("🧪 FINAL DATA TYPE CREATION TEST SUMMARY")
    print("=" * 60)
    
    results = {
        "structs": [],
        "enums": [],
        "unions": [],
        "validation": []
    }
    
    # Test Struct Creation
    print("\n🏗️ STRUCT CREATION TESTS")
    print("-" * 30)
    
    struct_tests = [
        {
            "name": "Basic Types",
            "data": {
                "name": f"BasicStruct_{int(time.time())}",
                "fields": [
                    {"name": "id", "type": "int"},
                    {"name": "flag", "type": "char"}
                ]
            }
        },
        {
            "name": "Advanced Types",
            "data": {
                "name": f"AdvancedStruct_{int(time.time())}",
                "fields": [
                    {"name": "buffer", "type": "char[64]"},
                    {"name": "pointer", "type": "void*"},
                    {"name": "double_val", "type": "double"}
                ]
            }
        }
    ]
    
    for test in struct_tests:
        try:
            response = requests.post(
                "http://localhost:8089/create_struct",
                json=test["data"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            success = response.status_code == 200 and "Successfully created" in response.text
            results["structs"].append((test["name"], success, response.text))
            status = "✅" if success else "❌"
            print(f"{status} {test['name']}: {response.text[:50]}...")
        except Exception as e:
            results["structs"].append((test["name"], False, str(e)))
            print(f"❌ {test['name']}: {e}")
    
    # Test Enum Creation
    print("\n🔢 ENUM CREATION TESTS")
    print("-" * 30)
    
    enum_tests = [
        {
            "name": "Sequential Values",
            "data": {
                "name": f"SeqEnum_{int(time.time())}",
                "values": {"FIRST": 0, "SECOND": 1, "THIRD": 2}
            }
        },
        {
            "name": "Custom Values",
            "data": {
                "name": f"CustomEnum_{int(time.time())}",
                "values": {"LOW": 10, "MEDIUM": 50, "HIGH": 100}
            }
        }
    ]
    
    for test in enum_tests:
        try:
            response = requests.post(
                "http://localhost:8089/create_enum",
                json=test["data"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            success = response.status_code == 200 and "Successfully created" in response.text
            results["enums"].append((test["name"], success, response.text))
            status = "✅" if success else "❌"
            print(f"{status} {test['name']}: {response.text[:50]}...")
        except Exception as e:
            results["enums"].append((test["name"], False, str(e)))
            print(f"❌ {test['name']}: {e}")
    
    # Test Union Creation
    print("\n🔄 UNION CREATION TESTS")
    print("-" * 30)
    
    union_test = {
        "name": "Basic Union",
        "data": {
            "name": f"BasicUnion_{int(time.time())}",
            "fields": [
                {"name": "as_int", "type": "int"},
                {"name": "as_float", "type": "float"}
            ]
        }
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_union",
            json=union_test["data"],
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        success = response.status_code == 200 and "successfully" in response.text.lower()
        results["unions"].append((union_test["name"], success, response.text))
        status = "✅" if success else "❌"
        print(f"{status} {union_test['name']}: {response.text[:50]}...")
    except Exception as e:
        results["unions"].append((union_test["name"], False, str(e)))
        print(f"❌ {union_test['name']}: {e}")
    
    # Test Validation
    print("\n⚠️ VALIDATION TESTS")
    print("-" * 30)
    
    validation_tests = [
        {
            "name": "Struct No Name",
            "url": "http://localhost:8089/create_struct",
            "data": {"fields": [{"name": "test", "type": "int"}]},
            "expected": "name is required"
        },
        {
            "name": "Enum No Name",
            "url": "http://localhost:8089/create_enum", 
            "data": {"values": {"A": 1}},
            "expected": "name is required"
        }
    ]
    
    for test in validation_tests:
        try:
            response = requests.post(
                test["url"],
                json=test["data"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            success = test["expected"].lower() in response.text.lower()
            results["validation"].append((test["name"], success, response.text))
            status = "✅" if success else "❌"
            print(f"{status} {test['name']}: {response.text}")
        except Exception as e:
            results["validation"].append((test["name"], False, str(e)))
            print(f"❌ {test['name']}: {e}")
    
    # Final Summary
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS SUMMARY")
    print("=" * 60)
    
    for category, tests in results.items():
        working = sum(1 for _, success, _ in tests if success)
        total = len(tests)
        percentage = (working / total * 100) if total > 0 else 0
        
        print(f"\n{category.upper()}:")
        print(f"   Working: {working}/{total} ({percentage:.1f}%)")
        
        for name, success, response in tests:
            status = "✅" if success else "❌"
            print(f"   {status} {name}")
    
    # Overall Summary
    all_tests = sum(len(tests) for tests in results.values())
    all_working = sum(sum(1 for _, success, _ in tests if success) for tests in results.values())
    overall_percentage = (all_working / all_tests * 100) if all_tests > 0 else 0
    
    print(f"\n🎯 OVERALL: {all_working}/{all_tests} ({overall_percentage:.1f}%) WORKING")
    
    if overall_percentage >= 80:
        print("🎉 EXCELLENT! Data type creation is working well!")
    elif overall_percentage >= 60:
        print("👍 GOOD! Most data type creation is working!")
    else:
        print("⚠️  NEEDS ATTENTION: Several data type issues found!")

if __name__ == "__main__":
    test_data_type_summary()