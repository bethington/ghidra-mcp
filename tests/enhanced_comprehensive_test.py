#!/usr/bin/env python3
"""
Enhanced Comprehensive Ghidra MCP Testing with Fixed Search Endpoint
"""

import requests
import logging
from dataclasses import dataclass
from typing import List, Dict, Any
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    endpoint: str
    method: str
    description: str
    success: bool
    duration: float
    response_code: int
    error_message: str = ""

class EnhancedGhidraMCPTest:
    def __init__(self, base_url: str = "http://127.0.0.1:8080"):
        self.base_url = base_url
        self.results: List[TestResult] = []
        
    def test_endpoint(self, endpoint: str, method: str, description: str, data: Dict[str, Any] = None) -> TestResult:
        """Test a single MCP endpoint."""
        start_time = time.time()
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            duration = time.time() - start_time
            success = response.status_code == 200
            
            result = TestResult(
                endpoint=endpoint,
                method=method,
                description=description,
                success=success,
                duration=duration,
                response_code=response.status_code,
                error_message="" if success else response.text[:200]
            )
            
            logger.info(f"{'✅' if success else '❌'} {description}: {response.status_code} ({duration:.3f}s)")
            
        except Exception as e:
            duration = time.time() - start_time
            result = TestResult(
                endpoint=endpoint,
                method=method,
                description=description,
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)[:200]
            )
            logger.error(f"❌ {description}: {str(e)}")
            
        self.results.append(result)
        return result
        
    def run_comprehensive_test(self):
        """Run comprehensive test of all MCP endpoints."""
        logger.info("🧪 STARTING ENHANCED COMPREHENSIVE GHIDRA MCP TEST")
        logger.info("=" * 60)
        
        # Test connection first
        connection_result = self.test_endpoint('/check_connection', 'GET', 'Check connection')
        if not connection_result.success:
            logger.error("❌ Cannot connect to MCP plugin. Aborting test.")
            return
            
        # Core endpoints
        logger.info("\n📋 Core Information:")
        self.test_endpoint('/get_metadata', 'GET', 'Get program metadata')
        self.test_endpoint('/get_entry_points', 'GET', 'Get entry points')
        
        # Function endpoints
        logger.info("\n🔧 Function Operations:")
        self.test_endpoint('/functions?limit=10', 'GET', 'List functions')
        self.test_endpoint('/searchFunctions?searchTerm=main&limit=5', 'GET', 'Search functions (FIXED)')
        self.test_endpoint('/decompile_function/main', 'GET', 'Decompile function')
        self.test_endpoint('/function_xrefs/main', 'GET', 'Get function cross-refs')
        self.test_endpoint('/function_callers/main', 'GET', 'Get function callers')
        self.test_endpoint('/function_callees/main', 'GET', 'Get function callees')
        self.test_endpoint('/function_call_graph/main', 'GET', 'Get call graph')
        
        # Get function by address for further testing
        functions_response = requests.get(f"{self.base_url}/functions?limit=1", timeout=10)
        test_address = "0x034c1000"  # Default fallback
        if functions_response.status_code == 200:
            lines = functions_response.text.strip().split('\n')
            if lines and lines[0].strip():
                # Try to extract address from function line
                parts = lines[0].split(' @ ')
                if len(parts) == 2:
                    test_address = parts[1].strip()
                    logger.info(f"Using test address: {test_address}")
        
        self.test_endpoint(f'/get_function_by_address/{test_address}', 'GET', 'Get function by address')
        self.test_endpoint(f'/disassemble_function/{test_address}', 'GET', 'Disassemble function')
        
        # Memory and analysis
        logger.info("\n🧠 Memory & Analysis:")
        self.test_endpoint('/segments', 'GET', 'List memory segments')
        self.test_endpoint(f'/xrefs_to/{test_address}', 'GET', 'Get cross-refs to address')
        self.test_endpoint(f'/xrefs_from/{test_address}', 'GET', 'Get cross-refs from address')
        
        # Data types
        logger.info("\n📊 Data Types:")
        self.test_endpoint('/data_types?limit=10', 'GET', 'List data types')
        self.test_endpoint('/search_data_types?pattern=int&limit=5', 'GET', 'Search data types')
        
        # Creation endpoints
        logger.info("\n🏗️  Creation Operations:")
        self.test_endpoint('/create_struct', 'POST', 'Create structure', {
            "name": "TestStruct_Enhanced",
            "fields": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "char[32]"}
            ]
        })
        
        self.test_endpoint('/create_union', 'POST', 'Create union', {
            "name": "TestUnion_Enhanced",
            "fields": [
                {"name": "as_int", "type": "dword"},
                {"name": "as_bytes", "type": "char[4]"}
            ]
        })
        
        self.test_endpoint('/create_enum', 'POST', 'Create enumeration', {
            "name": "TestEnum_Enhanced",
            "values": {"OPTION_A": 0, "OPTION_B": 1, "OPTION_C": 2}
        })
        
        # Symbols and strings
        logger.info("\n🔤 Symbols & Strings:")
        self.test_endpoint('/imports?limit=10', 'GET', 'List imports')
        self.test_endpoint('/exports?limit=10', 'GET', 'List exports')
        self.test_endpoint('/strings?limit=10', 'GET', 'List strings')
        self.test_endpoint('/namespaces?limit=10', 'GET', 'List namespaces')
        
        # Utilities
        logger.info("\n🛠️  Utilities:")
        self.test_endpoint('/create_label', 'POST', 'Create label', {
            "address": test_address,
            "name": "TEST_LABEL_ENHANCED"
        })
        self.test_endpoint('/convert_number/123', 'GET', 'Convert number')
        
        # Generate summary
        self.generate_summary()
        
    def generate_summary(self):
        """Generate test summary."""
        logger.info("\n" + "=" * 60)
        logger.info("📊 ENHANCED TEST SUMMARY")
        logger.info("=" * 60)
        
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results if r.success)
        failed_tests = total_tests - successful_tests
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        logger.info(f"✅ Total Tests: {total_tests}")
        logger.info(f"✅ Successful: {successful_tests}")
        logger.info(f"❌ Failed: {failed_tests}")
        logger.info(f"📈 Success Rate: {success_rate:.1f}%")
        
        if failed_tests > 0:
            logger.info("\n❌ Failed Tests:")
            for result in self.results:
                if not result.success:
                    logger.info(f"   • {result.description}: {result.response_code} - {result.error_message}")
        
        # Top 5 slowest tests
        sorted_results = sorted(self.results, key=lambda x: x.duration, reverse=True)
        logger.info(f"\n⏱️  Top 5 Slowest Tests:")
        for i, result in enumerate(sorted_results[:5]):
            logger.info(f"   {i+1}. {result.description}: {result.duration:.3f}s")
            
        logger.info("\n🎯 Enhanced testing complete!")

def main():
    """Main function to run enhanced test."""
    tester = EnhancedGhidraMCPTest()
    tester.run_comprehensive_test()

if __name__ == "__main__":
    main()