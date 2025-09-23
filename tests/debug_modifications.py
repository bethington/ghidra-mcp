"""
Debug modification operations to identify specific failures
"""
import requests
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('debug_modifications.log', encoding='utf-8')
    ]
)

class ModificationDebugger:
    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip('/')
        
    def test_endpoint(self, endpoint, method='GET', data=None):
        """Test a single endpoint and return detailed results"""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.request(method, url, json=data, timeout=10)
            
            result = {
                'endpoint': endpoint,
                'method': method,
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response_size': len(response.text),
                'has_content': len(response.text.strip()) > 0
            }
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    result['response_type'] = type(json_data).__name__
                    if isinstance(json_data, list):
                        result['item_count'] = len(json_data)
                    elif isinstance(json_data, dict):
                        result['keys'] = list(json_data.keys())
                except:
                    result['response_type'] = 'text'
            else:
                result['error'] = response.text[:200] if response.text else 'No error message'
                
            return result
            
        except Exception as e:
            return {
                'endpoint': endpoint,
                'method': method,
                'success': False,
                'error': str(e),
                'exception_type': type(e).__name__
            }
    
    def debug_modification_operations(self):
        """Debug all modification operations"""
        
        # First, get some data to work with
        logging.info("🔍 Getting available data for modification tests...")
        
        # Get functions to rename
        functions_result = self.test_endpoint('/functions')
        functions = []
        if functions_result['success']:
            try:
                response = requests.get(f"{self.base_url}/functions")
                functions = response.json()
                logging.info(f"Found {len(functions)} functions for testing")
            except:
                logging.warning("Could not get functions list")
        
        # Get some addresses for labeling/commenting
        segments_result = self.test_endpoint('/segments')
        test_address = "0x100000"  # Default test address
        if segments_result['success']:
            try:
                response = requests.get(f"{self.base_url}/segments")
                segments = response.json()
                if segments:
                    # Use the start of the first segment
                    test_address = segments[0].get('start', test_address)
                logging.info(f"Using test address: {test_address}")
            except:
                logging.warning("Could not get segments for test address")
        
        # Test modification endpoints
        modification_endpoints = [
            # Function renaming
            {'endpoint': '/rename-function', 'method': 'POST', 'data': {'old_name': 'NonExistentFunction', 'new_name': 'TestRename'}},
            {'endpoint': '/rename-function-by-address', 'method': 'POST', 'data': {'function_address': test_address, 'new_name': 'TestRenameByAddr'}},
            
            # Variable renaming  
            {'endpoint': '/rename-variable', 'method': 'POST', 'data': {'function_name': 'main', 'old_name': 'var1', 'new_name': 'testVar'}},
            {'endpoint': '/set-local-variable-type', 'method': 'POST', 'data': {'function_address': test_address, 'variable_name': 'testVar', 'new_type': 'int'}},
            
            # Global variable renaming
            {'endpoint': '/rename-global-variable', 'method': 'POST', 'data': {'old_name': 'NonExistentGlobal', 'new_name': 'TestGlobal'}},
            
            # Data and label operations
            {'endpoint': '/rename-data', 'method': 'POST', 'data': {'address': test_address, 'new_name': 'TestDataName'}},
            {'endpoint': '/create-label', 'method': 'POST', 'data': {'address': test_address, 'name': 'TestLabel'}},
            {'endpoint': '/rename-label', 'method': 'POST', 'data': {'address': test_address, 'old_name': 'TestLabel', 'new_name': 'RenamedLabel'}},
            
            # Comment operations
            {'endpoint': '/set-disassembly-comment', 'method': 'POST', 'data': {'address': test_address, 'comment': 'Test disassembly comment'}},
            {'endpoint': '/set-decompiler-comment', 'method': 'POST', 'data': {'address': test_address, 'comment': 'Test decompiler comment'}},
            
            # Data type application
            {'endpoint': '/apply-data-type', 'method': 'POST', 'data': {'address': test_address, 'type_name': 'int', 'clear_existing': True}},
            
            # Function prototype
            {'endpoint': '/set-function-prototype', 'method': 'POST', 'data': {'function_address': test_address, 'prototype': 'int test_function(void)'}},
        ]
        
        logging.info("🧪 Testing modification endpoints...")
        results = []
        
        for test_case in modification_endpoints:
            endpoint = test_case['endpoint']
            method = test_case.get('method', 'GET')
            data = test_case.get('data')
            
            logging.info(f"Testing {method} {endpoint}")
            result = self.test_endpoint(endpoint, method, data)
            results.append(result)
            
            if result['success']:
                logging.info(f"  ✅ Success: {endpoint}")
            else:
                logging.warning(f"  ❌ Failed: {endpoint} - {result.get('error', 'Unknown error')}")
        
        # Summary
        successful = sum(1 for r in results if r['success'])
        total = len(results)
        success_rate = (successful / total) * 100 if total > 0 else 0
        
        logging.info(f"\n📊 MODIFICATION OPERATIONS SUMMARY")
        logging.info(f"✅ Successful: {successful}/{total}")
        logging.info(f"📈 Success Rate: {success_rate:.1f}%")
        
        # Detailed failures
        failures = [r for r in results if not r['success']]
        if failures:
            logging.info(f"\n❌ FAILED ENDPOINTS:")
            for failure in failures:
                logging.info(f"  {failure['endpoint']}: {failure.get('error', 'Unknown error')}")
        
        return results

if __name__ == "__main__":
    debugger = ModificationDebugger()
    results = debugger.debug_modification_operations()