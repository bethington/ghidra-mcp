#!/usr/bin/env python3
"""
Analyze failing REST endpoints from test report
"""
import json

def analyze_failing_endpoints():
    try:
        with open('mcp_tools_test_report.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Test report not found. Running a quick check instead...")
        return
    
    print('❌ FAILING REST ENDPOINTS ANALYSIS')
    print('=' * 60)
    
    failed_tests = [test for test in data['test_results'] if not test['success']]
    total_tests = data['total_tests']
    
    print(f'Total failed: {len(failed_tests)}/{total_tests} ({len(failed_tests)/total_tests*100:.1f}%)')
    print(f'Success rate: {data["success_rate"]:.1f}%\n')
    
    # Group by status code
    by_status = {}
    for test in failed_tests:
        status = test['status_code']
        if status not in by_status:
            by_status[status] = []
        by_status[status].append(test)
    
    # Show failures by HTTP status code
    for status_code, tests in sorted(by_status.items()):
        print(f'🚫 HTTP {status_code} Errors ({len(tests)} endpoints):')
        for test in tests:
            method = test['method']
            endpoint = test['endpoint']  
            tool_name = test['tool_name']
            print(f'   • {method} /{endpoint} - {tool_name}')
        print()
    
    # Show most common failure reasons
    print('📊 FAILURE ANALYSIS:')
    print('-' * 30)
    
    missing_endpoints = [t for t in failed_tests if t['status_code'] == 404]
    unexpected_success = [t for t in failed_tests if 'Unexpected success' in str(t.get('response_preview', ''))]
    
    if missing_endpoints:
        print(f'• Missing Endpoints (404): {len(missing_endpoints)}')
        print('  These endpoints are not implemented in the plugin')
        
    if unexpected_success:
        print(f'• Unexpected Success Response: {len(unexpected_success)}')
        print('  These endpoints work but return unexpected success messages')
    
    print(f'\n✅ WORKING ENDPOINTS: {total_tests - len(failed_tests)}/{total_tests}')
    
    working_tests = [test for test in data['test_results'] if test['success']]
    print('Key working endpoints:')
    for test in working_tests[:10]:  # Show first 10 working ones
        print(f'   • {test["method"]} /{test["endpoint"]} - {test["tool_name"]}')
    if len(working_tests) > 10:
        print(f'   ... and {len(working_tests) - 10} more')

if __name__ == "__main__":
    analyze_failing_endpoints()