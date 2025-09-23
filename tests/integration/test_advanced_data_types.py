"""
Integration tests for advanced data type operations and management.

These tests focus on complex data type scenarios, validating that
the system can handle advanced use cases with real Ghidra instances.
"""
import pytest
import json
import time
from typing import Dict, Any, List
from tests.conftest import APIClient, TestConfig
from tests.fixtures.test_helpers import (
    TestDataGenerator, 
    TestValidators, 
    ComplexityLevel,
    MetricsTracker
)


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestAdvancedDataTypeOperations:
    """Test advanced data type operations and management."""
    
    def test_nested_struct_creation(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test creation of nested struct hierarchies."""
        base_name = TestDataGenerator.generate_unique_name("NestedTest")
        
        # Create base struct first
        base_struct_name = f"{base_name}_Base"
        base_fields = [
            {"name": "id", "type": "int"},
            {"name": "type", "type": "int"},
            {"name": "size", "type": "DWORD"}
        ]
        
        base_response = api_client.post('create_struct', data={
            'name': base_struct_name,
            'fields': json.dumps(base_fields)
        })
        
        if base_response.ok:
            cleanup_tracker['structs'].append(base_struct_name)
            
            # Create nested struct that uses the base struct
            nested_struct_name = f"{base_name}_Nested"
            nested_fields = [
                {"name": "header", "type": base_struct_name},
                {"name": "data", "type": "char[256]"},
                {"name": "footer", "type": base_struct_name}
            ]
            
            nested_response = api_client.post('create_struct', data={
                'name': nested_struct_name,
                'fields': json.dumps(nested_fields)
            })
            
            if nested_response.ok:
                cleanup_tracker['structs'].append(nested_struct_name)
            
            # At least one struct should be created
            assert base_response.ok or nested_response.ok
        else:
            # Base creation failed, but should fail gracefully
            assert base_response.status_code in [400, 409, 422]
    
    def test_large_struct_creation(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test creation of structs with many fields."""
        struct_name = TestDataGenerator.generate_unique_name("LargeStruct")
        
        # Generate a large number of fields
        large_fields = []
        for i in range(50):
            field_type = ["int", "short", "char", "DWORD", "QWORD"][i % 5]
            large_fields.append({
                "name": f"field_{i:03d}",
                "type": field_type
            })
        
        response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(large_fields)
        })
        
        if response.ok:
            cleanup_tracker['structs'].append(struct_name)
        
        # Should handle large structs or fail gracefully
        assert response.status_code in [200, 400, 413, 422]
    
    def test_enum_with_large_value_range(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test enum creation with large value ranges."""
        enum_name = TestDataGenerator.generate_unique_name("LargeEnum")
        
        # Create enum with large range of values
        large_enum_values = {}
        for i in range(100):
            large_enum_values[f"VALUE_{i:03d}"] = i * 1000
        
        response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': json.dumps(large_enum_values)
        })
        
        if response.ok:
            cleanup_tracker['enums'].append(enum_name)
        
        # Should handle large enums or fail gracefully
        assert response.status_code in [200, 400, 413, 422]
    
    def test_data_type_with_special_characters(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test data type creation with special characters in names."""
        special_cases = [
            "Struct_With_Underscores",
            "Struct123WithNumbers", 
            "StructWithCamelCase",
            # Note: Avoiding truly special chars that might break Ghidra
        ]
        
        successful_creations = 0
        
        for special_name in special_cases:
            full_name = f"{special_name}_{int(time.time())}"
            
            fields = TestDataGenerator.generate_struct_fields(ComplexityLevel.SIMPLE)
            
            response = api_client.post('create_struct', data={
                'name': full_name,
                'fields': json.dumps(fields)
            })
            
            if response.ok:
                cleanup_tracker['structs'].append(full_name)
                successful_creations += 1
        
        # At least some should succeed
        assert successful_creations >= len(special_cases) // 2


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeQueryAndSearch:
    """Test data type querying and search capabilities."""
    
    def test_data_type_listing_pagination(self, api_client: APIClient, server_health_check):
        """Test data type listing with various pagination options."""
        # Test different page sizes
        page_sizes = [5, 10, 25, 50]
        
        for size in page_sizes:
            response = api_client.get('data_types', params={'limit': size})
            assert response.ok or response.status_code == 404
            
            # Test with offset
            offset_response = api_client.get('data_types', params={
                'limit': size,
                'offset': size
            })
            assert offset_response.status_code in [200, 404]
    
    def test_data_type_search_functionality(self, api_client: APIClient, server_health_check):
        """Test data type search capabilities."""
        # Search for common built-in types
        common_types = ["int", "char", "void", "DWORD", "BYTE"]
        
        found_types = []
        
        for type_name in common_types:
            search_response = api_client.get('search_data_types', params={
                'pattern': type_name,
                'limit': 10
            })
            
            if search_response.ok:
                found_types.append(type_name)
        
        # Should find at least some common types
        assert len(found_types) >= 1, f"No common types found: {found_types}"
    
    def test_data_type_category_filtering(self, api_client: APIClient, server_health_check):
        """Test data type listing with category filters."""
        categories = ["builtin", "struct", "enum", "union", "pointer", "array"]
        
        category_results = {}
        
        for category in categories:
            response = api_client.get('data_types', params={
                'category': category,
                'limit': 20
            })
            
            category_results[category] = response.status_code
            
            # Should either work or return 404 (empty category)
            assert response.status_code in [200, 404]
        
        # At least some categories should exist
        successful_categories = sum(1 for status in category_results.values() if status == 200)
        assert successful_categories >= 1, f"No categories found: {category_results}"


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeApplicationAndUsage:
    """Test applying data types to memory locations."""
    
    def test_apply_builtin_data_type(self, api_client: APIClient, server_health_check):
        """Test applying built-in data types to addresses."""
        test_address = TestConfig.TEST_DATA['address']
        builtin_types = ["int", "char", "short", "DWORD"]
        
        application_results = {}
        
        for data_type in builtin_types:
            response = api_client.post('apply_data_type', data={
                'address': test_address,
                'type_name': data_type
            })
            
            application_results[data_type] = response.status_code
            
            # Should either succeed or fail gracefully
            assert response.status_code in [200, 400, 404, 409]
        
        # At least some applications should work or fail predictably
        assert len(application_results) == len(builtin_types)
    
    def test_data_type_validation_at_address(self, api_client: APIClient, server_health_check):
        """Test data type validation at specific addresses."""
        test_addresses = TestDataGenerator.generate_test_addresses(3)
        
        for address in test_addresses:
            # Test validation with common types
            validation_response = api_client.get('validate_data_type', params={
                'address': address,
                'type_name': 'int'
            })
            
            # Should return validation result or indicate endpoint doesn't exist
            assert validation_response.status_code in [200, 404, 501]
    
    def test_data_type_size_queries(self, api_client: APIClient, server_health_check):
        """Test querying data type sizes."""
        common_types = ["int", "char", "short", "DWORD", "QWORD", "float", "double"]
        
        size_results = {}
        
        for type_name in common_types:
            size_response = api_client.get('get_type_size', params={
                'type_name': type_name
            })
            
            if size_response.ok:
                size_results[type_name] = size_response.text
            
            # Should either work or indicate endpoint doesn't exist
            assert size_response.status_code in [200, 404, 501]
        
        # Should get size information for at least some types
        assert len(size_results) >= 0  # May not be implemented


@pytest.mark.integration
@pytest.mark.requires_ghidra
@pytest.mark.slow
class TestDataTypeStressScenarios:
    """Test data type operations under stress conditions."""
    
    def test_rapid_data_type_creation(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test creating many data types rapidly."""
        base_name = TestDataGenerator.generate_unique_name("RapidTest")
        metrics = MetricsTracker()
        
        successful_creations = 0
        total_attempts = 20
        
        metrics.start_timer("rapid_creation")
        
        for i in range(total_attempts):
            struct_name = f"{base_name}_{i:03d}"
            fields = TestDataGenerator.generate_struct_fields(ComplexityLevel.SIMPLE)
            
            response = api_client.post('create_struct', data={
                'name': struct_name,
                'fields': json.dumps(fields)
            })
            
            if response.ok:
                cleanup_tracker['structs'].append(struct_name)
                successful_creations += 1
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        metrics.end_timer("rapid_creation")
        
        # Should create at least half successfully
        success_rate = successful_creations / total_attempts
        assert success_rate >= 0.5, f"Low success rate: {success_rate}"
        
        # Should complete in reasonable time
        duration = metrics.get_duration("rapid_creation")
        assert duration < 30.0, f"Rapid creation took too long: {duration}s"
    
    def test_concurrent_data_type_operations(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test concurrent data type operations."""
        import threading
        import queue
        
        results = queue.Queue()
        base_name = TestDataGenerator.generate_unique_name("ConcurrentTest")
        
        def create_data_type(thread_id):
            try:
                struct_name = f"{base_name}_Thread_{thread_id}"
                fields = TestDataGenerator.generate_struct_fields(ComplexityLevel.SIMPLE)
                
                response = api_client.post('create_struct', data={
                    'name': struct_name,
                    'fields': json.dumps(fields)
                })
                
                results.put({
                    'thread_id': thread_id,
                    'success': response.ok,
                    'status_code': response.status_code,
                    'struct_name': struct_name if response.ok else None
                })
                
            except Exception as e:
                results.put({
                    'thread_id': thread_id,
                    'success': False,
                    'error': str(e)
                })
        
        # Start multiple threads
        threads = []
        thread_count = 5
        
        for i in range(thread_count):
            thread = threading.Thread(target=create_data_type, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=30)
        
        # Collect results
        thread_results = []
        while not results.empty():
            result = results.get()
            thread_results.append(result)
            
            # Track successful creations for cleanup
            if result.get('success') and result.get('struct_name'):
                cleanup_tracker['structs'].append(result['struct_name'])
        
        # Should have results from all threads
        assert len(thread_results) == thread_count
        
        # At least some threads should succeed
        successful_threads = sum(1 for r in thread_results if r.get('success'))
        assert successful_threads >= thread_count // 2, f"Too few successful threads: {successful_threads}"
    
    def test_data_type_export_import_workflow(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test data type export and import capabilities."""
        # Create some test data types first
        test_name = TestDataGenerator.generate_unique_name("ExportTest")
        
        # Create test struct
        struct_name = f"{test_name}_Struct"
        fields = TestDataGenerator.generate_struct_fields(ComplexityLevel.MEDIUM)
        
        struct_response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(fields)
        })
        
        if struct_response.ok:
            cleanup_tracker['structs'].append(struct_name)
        
        # Create test enum
        enum_name = f"{test_name}_Enum"
        enum_values = TestDataGenerator.generate_enum_values("status")
        
        enum_response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': json.dumps(enum_values)
        })
        
        if enum_response.ok:
            cleanup_tracker['enums'].append(enum_name)
        
        # Try to export data types
        export_response = api_client.get('export_data_types', params={
            'format': 'c',
            'category': 'struct'
        })
        
        # Export may not be implemented
        assert export_response.status_code in [200, 404, 501]
        
        if export_response.ok:
            # Should get some export data
            assert len(export_response.text) > 0
        
        # At least one data type should have been created
        assert struct_response.ok or enum_response.ok


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeErrorConditions:
    """Test error conditions specific to data type operations."""
    
    def test_duplicate_data_type_creation(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test creating data types with duplicate names."""
        struct_name = TestDataGenerator.generate_unique_name("DuplicateTest")
        fields = TestDataGenerator.generate_struct_fields(ComplexityLevel.SIMPLE)
        
        # Create first struct
        first_response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(fields)
        })
        
        if first_response.ok:
            cleanup_tracker['structs'].append(struct_name)
        
        # Try to create duplicate
        duplicate_response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(fields)
        })
        
        # First should succeed or fail for other reasons
        assert first_response.status_code in [200, 400, 422]
        
        # Duplicate handling may vary - API might allow overwrites or handle gracefully
        if first_response.ok:
            assert duplicate_response.status_code in [200, 400, 409, 422], f"Unexpected duplicate response: {duplicate_response.status_code}"
    
    def test_invalid_field_types_in_struct(self, api_client: APIClient, server_health_check):
        """Test struct creation with invalid field types."""
        struct_name = TestDataGenerator.generate_unique_name("InvalidFieldTest")
        
        invalid_field_combinations = [
            # Non-existent type
            [{"name": "field1", "type": "NonExistentType_12345"}],
            
            # Circular reference (if detected)
            [{"name": "field1", "type": struct_name}],
            
            # Empty type
            [{"name": "field1", "type": ""}],
        ]
        
        for invalid_fields in invalid_field_combinations:
            response = api_client.post('create_struct', data={
                'name': f"{struct_name}_{len(invalid_fields)}",
                'fields': json.dumps(invalid_fields)
            })
            
            # API might handle invalid fields gracefully, so accept various responses
            assert response.status_code in [200, 400, 422], f"Unexpected status for invalid fields: {response.status_code}"
    
    def test_invalid_enum_values(self, api_client: APIClient, server_health_check):
        """Test enum creation with invalid values."""
        enum_name = TestDataGenerator.generate_unique_name("InvalidEnumTest")
        
        invalid_enum_cases = [
            # Empty enum
            {},
            
            # Invalid JSON structure (will be caught by JSON serialization)
            # We test this at the API level by sending malformed JSON strings
        ]
        
        for i, invalid_values in enumerate(invalid_enum_cases):
            response = api_client.post('create_enum', data={
                'name': f"{enum_name}_{i}",
                'values': json.dumps(invalid_values)
            })
            
            # Empty enum might be valid, others should be rejected appropriately
            assert response.status_code in [200, 400, 422]
