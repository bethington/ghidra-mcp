"""
Detailed diagnostic tool to understand why some endpoints are failing
"""
import requests
import json
import logging
from datetime import datetime
import time

# Configure logging with UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/endpoint_diagnostics.log', encoding='utf-8')
    ]
)

class EndpointDiagnostics:
    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip('/')
        
    def check_connection(self):
        """Check if the server is responding"""
        try:
            response = requests.get(f"{self.base_url}/check-connection", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def detailed_endpoint_test(self, endpoint, method='GET', data=None, description=""):
        """Test an endpoint and provide detailed diagnostics"""
        logging.info(f"\n{'='*60}")
        logging.info(f"Testing: {method} {endpoint}")
        logging.info(f"Description: {description}")
        
        try:
            url = f"{self.base_url}{endpoint}"
            start_time = time.time()
            
            response = requests.request(method, url, json=data, timeout=10)
            duration = time.time() - start_time
            
            logging.info(f"Status Code: {response.status_code}")
            logging.info(f"Response Time: {duration:.3f}s")
            logging.info(f"Response Size: {len(response.text)} bytes")
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    if isinstance(json_data, list):
                        logging.info(f"Response Type: list with {len(json_data)} items")
                        if json_data:
                            logging.info(f"First item keys: {list(json_data[0].keys()) if isinstance(json_data[0], dict) else 'Not a dict'}")
                    elif isinstance(json_data, dict):
                        logging.info(f"Response Type: dict with keys: {list(json_data.keys())}")
                    else:
                        logging.info(f"Response Type: {type(json_data)} - {json_data}")
                    return True, json_data
                except json.JSONDecodeError:
                    logging.info(f"Response Type: Plain text")
                    logging.info(f"Response: {response.text[:200]}...")
                    return True, response.text
            else:
                logging.warning(f"Error Response: {response.text[:200]}")
                return False, response.text
                
        except Exception as e:
            logging.error(f"Exception: {type(e).__name__}: {str(e)}")
            return False, str(e)
    
    def diagnose_failing_categories(self):
        """Diagnose specific categories that showed low success rates"""
        
        if not self.check_connection():
            logging.error("❌ Cannot connect to Ghidra server at http://127.0.0.1:8080")
            return
        
        logging.info("✅ Connected to Ghidra server")
        
        # Test endpoints that were showing issues
        failing_tests = [
            # Function Analysis category (was 11.1%)
            ('/function-xrefs/main', 'GET', None, "Get cross-references for main function"),
            ('/function-callers/main', 'GET', None, "Get callers of main function"), 
            ('/function-callees/main', 'GET', None, "Get callees of main function"),
            ('/function-call-graph/main', 'GET', None, "Get call graph for main function"),
            
            # Memory Analysis category (was 40.0%)
            ('/xrefs-to/0x100000', 'GET', None, "Get cross-references to address"),
            ('/xrefs-from/0x100000', 'GET', None, "Get cross-references from address"),
            
            # Data Type Queries (was 37.5%)
            ('/data-types', 'GET', None, "List all data types"),
            ('/data-types/struct', 'GET', None, "List struct data types"),
            ('/search-data-types/int', 'GET', None, "Search for int data types"),
            
            # Modification Operations (was 0.0%)
            ('/create-label', 'POST', {'address': '0x100000', 'name': 'TestLabel'}, "Create a label"),
            ('/set-disassembly-comment', 'POST', {'address': '0x100000', 'comment': 'Test comment'}, "Set disassembly comment"),
        ]
        
        logging.info(f"\n🔍 DIAGNOSING {len(failing_tests)} PROBLEMATIC ENDPOINTS")
        logging.info("="*60)
        
        results = []
        for endpoint, method, data, description in failing_tests:
            success, response = self.detailed_endpoint_test(endpoint, method, data, description)
            results.append((endpoint, success, response))
        
        # Summary
        successful = sum(1 for _, success, _ in results if success)
        logging.info(f"\n📊 DIAGNOSTIC SUMMARY")
        logging.info(f"✅ Successful: {successful}/{len(results)}")
        logging.info(f"❌ Failed: {len(results) - successful}/{len(results)}")
        
        return results

if __name__ == "__main__":
    diagnostics = EndpointDiagnostics()
    diagnostics.diagnose_failing_categories()