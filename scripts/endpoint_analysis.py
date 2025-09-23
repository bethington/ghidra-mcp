#!/usr/bin/env python3
"""
Comprehensive REST Endpoint Analysis

This script analyzes which endpoints are implemented vs. which ones are failing.
"""

import json
import requests

def extract_implemented_endpoints():
    """Extract endpoints from the source code pattern"""
    implemented = [
        "/methods", "/classes", "/decompile", "/renameFunction", "/renameData", 
        "/renameVariable", "/segments", "/imports", "/exports", "/namespaces", 
        "/data", "/searchFunctions", "/get_function_by_address", "/get_current_address", 
        "/get_current_function", "/list_functions", "/decompile_function", 
        "/disassemble_function", "/set_decompiler_comment", "/set_disassembly_comment", 
        "/rename_function_by_address", "/set_function_prototype", "/set_local_variable_type", 
        "/xrefs_to", "/xrefs_from", "/function_xrefs", "/function_labels", 
        "/rename_label", "/function_jump_targets", "/create_label", "/function_callees", 
        "/function_callers", "/function_call_graph", "/full_call_graph", 
        "/list_data_types", "/create_struct", "/create_enum", "/apply_data_type", 
        "/strings", "/check_connection", "/get_metadata", "/convert_number", 
        "/list_globals", "/rename_global_variable", "/get_entry_points", 
        "/analyze_data_types", "/create_union", "/get_type_size", "/get_struct_layout", 
        "/search_data_types", "/auto_create_struct", "/get_enum_values", 
        "/create_typedef", "/clone_data_type", "/validate_data_type", 
        "/export_data_types", "/import_data_types"
    ]
    return sorted(implemented)

def analyze_endpoint_discrepancies():
    print("🔍 REST ENDPOINT ANALYSIS")
    print("=" * 60)
    
    # Load test results
    try:
        with open('mcp_tools_test_report.json', 'r') as f:
            test_data = json.load(f)
    except FileNotFoundError:
        print("❌ Test report not found!")
        return
    
    # Get implemented endpoints from source
    implemented_endpoints = extract_implemented_endpoints()
    print(f"📝 Implemented in Plugin: {len(implemented_endpoints)} endpoints")
    
    # Analyze test results
    tested_endpoints = {}
    for test in test_data['test_results']:
        endpoint = "/" + test['endpoint']
        tested_endpoints[endpoint] = {
            'tool_name': test['tool_name'],
            'success': test['success'],
            'status_code': test['status_code'],
            'method': test['method']
        }
    
    print(f"🧪 Tested by Suite: {len(tested_endpoints)} endpoints")
    
    # Compare sets
    implemented_set = set(implemented_endpoints)
    tested_set = set(tested_endpoints.keys())
    
    print(f"\n📊 ENDPOINT COMPARISON:")
    print(f"   Common endpoints: {len(implemented_set & tested_set)}")
    print(f"   Only implemented: {len(implemented_set - tested_set)}")
    print(f"   Only tested: {len(tested_set - implemented_set)}")
    
    # Show discrepancies
    print(f"\n❌ FAILING ENDPOINTS ANALYSIS:")
    
    # Group failures by reason
    http_404_failures = []
    working_but_wrong_path = []
    actually_working = []
    
    for endpoint, data in tested_endpoints.items():
        if not data['success']:
            if data['status_code'] == 404:
                # Check if it's a path mismatch
                if endpoint in implemented_set:
                    working_but_wrong_path.append((endpoint, data))
                else:
                    # Check for similar paths
                    similar = None
                    endpoint_clean = endpoint.strip('/')
                    for impl in implemented_endpoints:
                        impl_clean = impl.strip('/')
                        if endpoint_clean.replace('_', '') == impl_clean.replace('_', ''):
                            similar = impl
                            break
                    http_404_failures.append((endpoint, data, similar))
            else:
                working_but_wrong_path.append((endpoint, data))
        else:
            actually_working.append((endpoint, data))
    
    print(f"\n🚫 TRUE 404 FAILURES ({len(http_404_failures)}):")
    print("   These endpoints are genuinely missing from the plugin:")
    for endpoint, data, similar in http_404_failures:
        if similar:
            print(f"   • {endpoint} ({data['tool_name']}) - Similar: {similar}")
        else:
            print(f"   • {endpoint} ({data['tool_name']}) - NOT IMPLEMENTED")
    
    if working_but_wrong_path:
        print(f"\n⚠️  PATH/METHOD MISMATCHES ({len(working_but_wrong_path)}):")
        print("   These may be working but have wrong URL or method:")
        for endpoint, data in working_but_wrong_path[:10]:  # Show first 10
            print(f"   • {data['method']} {endpoint} ({data['tool_name']}) - HTTP {data['status_code']}")
    
    print(f"\n✅ ACTUALLY WORKING ({len(actually_working)}):")
    print("   These endpoints are working correctly:")
    for endpoint, data in actually_working[:15]:  # Show first 15
        print(f"   • {data['method']} {endpoint} ({data['tool_name']}) ✓")
    if len(actually_working) > 15:
        print(f"   ... and {len(actually_working) - 15} more")
    
    # Show clearly unimplemented endpoints
    print(f"\n🔴 DEFINITELY NOT IMPLEMENTED:")
    unimplemented = []
    for endpoint, data, similar in http_404_failures:
        if not similar and endpoint not in implemented_set:
            unimplemented.append((endpoint, data['tool_name']))
    
    for endpoint, tool_name in sorted(unimplemented):
        print(f"   • {endpoint} - {tool_name}")
    
    print(f"\n📈 SUMMARY:")
    print(f"   ✅ Working: {len(actually_working)}")
    print(f"   ⚠️  Path issues: {len(working_but_wrong_path)}")
    print(f"   🚫 Not implemented: {len(unimplemented)}")
    print(f"   📊 Success rate: {len(actually_working)/(len(actually_working)+len(http_404_failures)+len(working_but_wrong_path))*100:.1f}%")

if __name__ == "__main__":
    analyze_endpoint_discrepancies()