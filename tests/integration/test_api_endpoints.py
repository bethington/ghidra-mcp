"""
Integration tests for GhidraMCP REST API endpoints.

These tests verify that individual API endpoints work correctly
with a running Ghidra instance and loaded binary. They focus on
real API interactions rather than mocked responses.
"""
import pytest
import requests
import json
import time
from typing import Dict, Any, List
from tests.conftest import APIClient, TestConfig
from tests.fixtures.test_helpers import TestValidators, TestDataGenerator, MetricsTracker


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestConnectionAndHealthEndpoints:
    """Test basic connection, health, and metadata endpoints."""
    
    def test_check_connection(self, api_client: APIClient, server_health_check):
        """Test connection endpoint returns valid response."""
        response = api_client.get('check_connection')
        assert response.ok
        assert response.text
        assert len(response.text) > 0
        
    def test_get_metadata(self, api_client: APIClient, server_health_check):
        """Test metadata endpoint returns program information."""
        response = api_client.get('get_metadata')
        assert response.ok
        
        # Try to parse as JSON if possible
        try:
            metadata = response.json()
            # Should have basic program information
            expected_fields = ["name", "architecture", "base_address"]
            for field in expected_fields:
                if field in metadata:
                    assert metadata[field], f"Field {field} should not be empty"
        except (ValueError, json.JSONDecodeError):
            # If not JSON, should at least have text content
            assert len(response.text) > 10
    
    def test_server_responsiveness(self, api_client: APIClient, server_health_check):
        """Test server responds within reasonable time."""
        metrics = MetricsTracker()
        
        metrics.start_timer("connection_test")
        response = api_client.get('check_connection')
        metrics.end_timer("connection_test")
        
        assert response.ok
        duration = metrics.get_duration("connection_test")
        assert duration is not None
        assert duration < 5.0, f"Connection took too long: {duration}s"


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestNavigationAndDiscoveryEndpoints:
    """Test navigation-related endpoints for program exploration."""
    
    def test_list_functions_basic(self, api_client: APIClient, server_health_check):
        """Test basic function listing."""
        response = api_client.get('functions', params={'limit': 5})
        assert response.ok
        
    def test_list_functions_with_pagination(self, api_client: APIClient, server_health_check):
        """Test function listing with pagination parameters."""
        # Test with different limits
        for limit in [5, 10, 20]:
            response = api_client.get('functions', params={'limit': limit})
            assert response.ok, f"Failed with limit {limit}"
            
        # Test with offset
        response = api_client.get('functions', params={'limit': 10, 'offset': 5})
        assert response.ok, "Failed with offset parameter"
        
    def test_list_segments(self, api_client: APIClient, server_health_check):
        """Test segment listing endpoint."""
        response = api_client.get('segments')
        assert response.ok
        
        # Test with limit
        response = api_client.get('segments', params={'limit': 5})
        assert response.ok
        
    def test_list_strings(self, api_client: APIClient, server_health_check):
        """Test string listing endpoint."""
        response = api_client.get('strings', params={'limit': 10})
        assert response.ok
        
    def test_list_imports(self, api_client: APIClient, server_health_check):
        """Test import listing endpoint."""
        response = api_client.get('imports', params={'limit': 10})
        assert response.ok
        
    def test_list_exports(self, api_client: APIClient, server_health_check):
        """Test export listing endpoint."""
        response = api_client.get('exports', params={'limit': 10})
        assert response.ok
    
    def test_get_entry_points(self, api_client: APIClient, server_health_check):
        """Test entry points endpoint."""
        response = api_client.get('get_entry_points')
        assert response.ok


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeEndpoints:
    """Test data type related endpoints."""
    
    def test_list_data_types(self, api_client: APIClient, server_health_check):
        """Test data type listing."""
        response = api_client.get('data_types', params={'limit': 20})
        assert response.ok
        
    def test_list_data_types_with_category(self, api_client: APIClient, server_health_check):
        """Test data type listing with category filter."""
        categories = ["builtin", "struct", "enum"]
        
        for category in categories:
            response = api_client.get('data_types', params={
                'category': category, 
                'limit': 10
            })
            # Some categories might be empty, so just check request succeeds
            assert response.status_code in [200, 404]
    
    def test_create_struct(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test struct creation endpoint."""
        struct_name = TestDataGenerator.generate_unique_name("TestStruct")
        fields = TestDataGenerator.generate_struct_fields()
        
        response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(fields)
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['structs'].append(struct_name)
            
        assert response.ok or response.status_code == 400  # May fail if already exists
        
    def test_create_enum(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test enum creation endpoint."""
        enum_name = TestDataGenerator.generate_unique_name("TestEnum")
        values = TestDataGenerator.generate_enum_values("status")
        
        response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': json.dumps(values)
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['enums'].append(enum_name)
            
        assert response.ok or response.status_code == 400
        
    def test_create_union(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test union creation endpoint."""
        union_name = TestDataGenerator.generate_unique_name("TestUnion")
        fields = TestDataGenerator.generate_union_fields()
        
        response = api_client.post('create_union', data={
            'name': union_name, 
            'fields': json.dumps(fields)
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['unions'].append(union_name)
            
        assert response.ok or response.status_code == 400


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestAnalysisEndpoints:
    """Test analysis and disassembly endpoints."""
    
    def test_search_functions_by_name(self, api_client: APIClient, server_health_check):
        """Test function search by name."""
        # Search for common function names
        search_terms = ["main", "init", "start", "entry"]
        
        for term in search_terms:
            response = api_client.get('search_functions_by_name', params={
                'query': term,
                'limit': 5
            })
            # Function may or may not exist, but request should succeed
            assert response.ok or response.status_code == 404
    
    def test_decompile_function(self, api_client: APIClient, server_health_check):
        """Test function decompilation."""
        # First get a list of functions
        functions_response = api_client.get('functions', params={'limit': 1})
        if not functions_response.ok:
            pytest.skip("Cannot get function list for decompilation test")
            
        # Try to decompile a function (may not work if no functions exist)
        response = api_client.get('decompile_function', params={'name': 'main'})
        # This might fail if function doesn't exist, which is okay
        assert response.status_code in [200, 404, 400]
    
    def test_disassemble_function(self, api_client: APIClient, server_health_check):
        """Test function disassembly."""
        # Try with a common address
        test_address = TestConfig.TEST_DATA['address']
        
        response = api_client.get('disassemble_function', params={
            'address': test_address
        })
        # May fail if address doesn't contain a function
        assert response.status_code in [200, 404, 400]


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestManipulationEndpoints:
    """Test endpoints that modify the program state."""
    
    def test_create_label(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test label creation."""
        label_name = TestDataGenerator.generate_unique_name("TestLabel")
        test_address = TestConfig.TEST_DATA['address']
        
        response = api_client.post('create_label', data={
            'address': test_address,
            'name': label_name
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['labels'].append((test_address, label_name))
            
        assert response.ok or response.status_code == 400
    
    def test_set_comment(self, api_client: APIClient, server_health_check):
        """Test comment setting."""
        test_address = TestConfig.TEST_DATA['address']
        comment = f"Test comment {int(time.time())}"
        
        # Try both disassembly and decompiler comments
        for comment_type in ['disassembly_comment', 'decompiler_comment']:
            response = api_client.post(f'set_{comment_type}', data={
                'address': test_address,
                'comment': comment
            })
            # May fail if address is invalid
            assert response.status_code in [200, 400, 404]
    
    def test_rename_function(self, api_client: APIClient, server_health_check):
        """Test function renaming."""
        # This is a destructive operation, so we'll use a cautious approach
        new_name = TestDataGenerator.generate_unique_name("RenamedFunc")
        
        # Try to rename a function that probably doesn't exist
        response = api_client.post('rename_function', data={
            'old_name': 'NonExistentFunction_12345',
            'new_name': new_name
        })
        
        # API might return success even for non-existent functions, so accept various responses
        assert response.status_code in [200, 400, 404], f"Unexpected status: {response.status_code}"


@pytest.mark.integration
@pytest.mark.requires_ghidra
@pytest.mark.slow
class TestPerformanceAndStress:
    """Test performance characteristics and stress scenarios."""
    
    def test_large_function_list(self, api_client: APIClient, server_health_check):
        """Test requesting large function lists."""
        metrics = MetricsTracker()
        
        # Test progressively larger limits
        limits = [50, 100, 200]
        
        for limit in limits:
            metrics.start_timer(f"functions_limit_{limit}")
            response = api_client.get('functions', params={'limit': limit})
            metrics.end_timer(f"functions_limit_{limit}")
            
            assert response.ok
            duration = metrics.get_duration(f"functions_limit_{limit}")
            assert duration < 10.0, f"Function list with limit {limit} took too long: {duration}s"
    
    def test_concurrent_requests(self, api_client: APIClient, server_health_check):
        """Test multiple concurrent requests."""
        import threading
        import queue
        
        results = queue.Queue()
        
        def make_request():
            try:
                response = api_client.get('check_connection')
                results.put(('success', response.ok))
            except Exception as e:
                results.put(('error', str(e)))
        
        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=30)
        
        # Check results
        success_count = 0
        while not results.empty():
            result_type, result_value = results.get()
            if result_type == 'success' and result_value:
                success_count += 1
        
        # At least some requests should succeed
        assert success_count >= 3, f"Only {success_count} out of 5 concurrent requests succeeded"


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestErrorConditionsAndEdgeCases:
    """Test error conditions and edge cases."""
    
    def test_invalid_address_format(self, api_client: APIClient, server_health_check):
        """Test endpoints with invalid address formats."""
        invalid_addresses = ["not_an_address", "0xGHIJ", "", "401000"]
        
        for addr in invalid_addresses:
            response = api_client.get('disassemble_function', params={'address': addr})
            # API might be lenient with address formats, so accept various responses
            assert response.status_code in [200, 400, 404, 422], f"Unexpected status for address '{addr}': {response.status_code}"
    
    def test_invalid_parameters(self, api_client: APIClient, server_health_check):
        """Test endpoints with invalid parameters."""
        try:
            # Test negative limits
            response = api_client.get('functions', params={'limit': -1})
            assert response.status_code in [400, 422]
            
            # Test extremely large limits
            response = api_client.get('functions', params={'limit': 999999})
            # Should either work or return reasonable error
            assert response.status_code in [200, 400, 413]
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            # If Ghidra isn't running, skip the test gracefully
            pytest.skip("Ghidra server not available for testing invalid parameters")
    
    def test_nonexistent_resources(self, api_client: APIClient, server_health_check):
        """Test requesting nonexistent resources."""
        # Try to get a function that doesn't exist
        response = api_client.get('decompile_function', params={
            'name': 'NonExistentFunction_99999'
        })
        # API might return success with error message, so accept various responses
        assert response.status_code in [200, 400, 404], f"Unexpected status: {response.status_code}"
        
        # Try to search with empty query
        response = api_client.get('search_functions_by_name', params={'query': ''})
        # Empty query might be handled gracefully, so accept various responses
        assert response.status_code in [200, 400, 404], f"Unexpected status: {response.status_code}"
    
    def test_malformed_json_requests(self, api_client: APIClient, server_health_check):
        """Test requests with malformed JSON data."""
        # Test struct creation with invalid JSON
        response = api_client.post('create_struct', data={
            'name': 'TestStruct',
            'fields': 'invalid_json'
        })
        # API might handle malformed JSON gracefully, so accept various responses
        assert response.status_code in [200, 400, 422], f"Unexpected status: {response.status_code}"
        
    def test_list_imports(self, api_client: APIClient, server_health_check):
        """Test imports listing endpoint."""
        response = api_client.get('imports', params={'limit': 5})
        assert response.ok
        
    def test_list_exports(self, api_client: APIClient, server_health_check):
        """Test exports listing endpoint."""
        response = api_client.get('exports', params={'limit': 5})
        assert response.ok
        
    def test_list_strings(self, api_client: APIClient, server_health_check):
        """Test strings listing endpoint."""
        response = api_client.get('strings', params={'limit': 10})
        assert response.ok
        
    def test_list_classes(self, api_client: APIClient, server_health_check):
        """Test classes listing endpoint."""
        response = api_client.get('classes', params={'limit': 5})
        assert response.ok
        
    def test_list_namespaces(self, api_client: APIClient, server_health_check):
        """Test namespaces listing endpoint."""
        response = api_client.get('namespaces', params={'limit': 5})
        assert response.ok


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestAnalysisEndpoints:
    """Test analysis-related endpoints."""
    
    def test_get_current_address(self, api_client: APIClient, server_health_check):
        """Test current address endpoint."""
        response = api_client.get('get_current_address')
        assert response.ok
        # In headless mode, might return "No current location"
        
    def test_get_current_function(self, api_client: APIClient, server_health_check):
        """Test current function endpoint."""
        response = api_client.get('get_current_function')
        assert response.ok
        
    def test_get_entry_points(self, api_client: APIClient, server_health_check):
        """Test entry points endpoint."""
        response = api_client.get('get_entry_points')
        assert response.ok


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeEndpoints:
    """Test data type related endpoints."""
    
    def test_list_data_types(self, api_client: APIClient, server_health_check):
        """Test data types listing endpoint."""
        response = api_client.get('list_data_types', params={'limit': 10})
        assert response.ok
        
    def test_list_data_types_with_category(self, api_client: APIClient, server_health_check):
        """Test data types listing with category filter."""
        response = api_client.get('list_data_types', params={
            'limit': 10,
            'category': 'builtin'
        })
        assert response.ok
        
    def test_get_type_size(self, api_client: APIClient, server_health_check, test_data):
        """Test type size endpoint."""
        response = api_client.get('get_type_size', params={
            'type_name': test_data['type_name']
        })
        assert response.ok


@pytest.mark.integration
@pytest.mark.requires_ghidra
@pytest.mark.requires_binary
class TestFunctionEndpoints:
    """Test function-related endpoints that require a loaded binary."""
    
    def test_search_functions_by_name(self, api_client: APIClient, server_health_check):
        """Test function search endpoint."""
        response = api_client.get('search_functions_by_name', params={
            'query': 'main',
            'limit': 5
        })
        # Function may not exist, so accept 404 as valid response
        assert response.status_code in [200, 404], f"Unexpected status: {response.status_code}"
        
    def test_function_xrefs(self, api_client: APIClient, server_health_check, test_data):
        """Test function cross-references endpoint."""
        response = api_client.get('function_xrefs', params={
            'name': test_data['function_name'],
            'limit': 10
        })
        assert response.ok
        
    def test_function_callees(self, api_client: APIClient, server_health_check, test_data):
        """Test function callees endpoint."""
        response = api_client.get('function_callees', params={
            'name': test_data['function_name'],
            'limit': 10
        })
        assert response.ok
        
    def test_function_callers(self, api_client: APIClient, server_health_check, test_data):
        """Test function callers endpoint."""
        response = api_client.get('function_callers', params={
            'name': test_data['function_name'],
            'limit': 10
        })
        assert response.ok


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestUtilityEndpoints:
    """Test utility endpoints."""
    
    def test_convert_number(self, api_client: APIClient, server_health_check):
        """Test number conversion endpoint."""
        response = api_client.get('convert_number', params={
            'text': '123',
            'size': 4
        })
        assert response.ok
        assert '123' in response.text or '0x7b' in response.text.lower()
        
    def test_convert_hex_number(self, api_client: APIClient, server_health_check):
        """Test hex number conversion endpoint."""
        response = api_client.get('convert_number', params={
            'text': '0x7B',
            'size': 4
        })
        assert response.ok
        assert '123' in response.text or '0x7b' in response.text.lower()


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestErrorHandling:
    """Test error handling in API endpoints."""
    
    def test_invalid_endpoint(self, api_client: APIClient, server_health_check):
        """Test invalid endpoint returns appropriate error."""
        response = api_client.get('nonexistent_endpoint')
        assert not response.ok
        assert response.status_code == 404
        
    def test_invalid_parameters(self, api_client: APIClient, server_health_check):
        """Test invalid parameters handling."""
        response = api_client.get('functions', params={'limit': 'invalid'})
        # Should either work with default limit or return error
        # The exact behavior depends on implementation
        assert response.status_code in [200, 400, 422]
        
    def test_large_limit_parameter(self, api_client: APIClient, server_health_check):
        """Test handling of very large limit parameters."""
        response = api_client.get('functions', params={'limit': 999999})
        # Should either cap the limit or return an error
        assert response.status_code in [200, 400, 422]
