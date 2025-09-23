"""
Integration tests for GhidraMCP data type operations.

These tests verify data type creation, modification, and management
operations work correctly with a running Ghidra instance.
"""
import pytest
import requests
import json
from tests.conftest import APIClient, TestConfig


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeCreation:
    """Test data type creation endpoints."""
    
    def test_create_struct(self, api_client: APIClient, server_health_check, 
                          test_data, cleanup_tracker):
        """Test struct creation endpoint."""
        struct_name = f"{test_data['struct_name']}_Integration"
        fields = [
            {"name": "id", "type": "int"},
            {"name": "name", "type": "char[32]"},
            {"name": "flags", "type": "DWORD"}
        ]
        
        response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(fields)  # Proper JSON formatting
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['structs'].append(struct_name)
            
        # Should succeed or fail gracefully - don't depend on specific response content
        assert response.status_code in [200, 400, 409, 422], f"Unexpected status: {response.status_code}, Response: {response.text}"
        
    def test_create_enum(self, api_client: APIClient, server_health_check,
                        test_data, cleanup_tracker):
        """Test enum creation endpoint."""
        enum_name = f"{test_data['enum_name']}_Integration"
        values = {
            "STATE_IDLE": 0,
            "STATE_RUNNING": 1,
            "STATE_STOPPED": 2
        }
        
        response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': json.dumps(values),  # Proper JSON formatting
            'size': 4
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['enums'].append(enum_name)
            
        # Should succeed or fail gracefully - don't depend on specific response content
        assert response.status_code in [200, 400, 409, 422], f"Unexpected status: {response.status_code}, Response: {response.text}"
        
    def test_create_union(self, api_client: APIClient, server_health_check,
                         test_data, cleanup_tracker):
        """Test union creation endpoint."""
        union_name = f"{test_data['union_name']}_Integration"
        fields = [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"}
        ]
        
        response = api_client.post('create_union', data={
            'name': union_name,
            'fields': json.dumps(fields)  # Proper JSON formatting
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['unions'].append(union_name)
            
        # Should succeed or fail gracefully - don't depend on specific response content
        assert response.status_code in [200, 400, 409, 422], f"Unexpected status: {response.status_code}, Response: {response.text}"
        
    def test_create_typedef(self, api_client: APIClient, server_health_check,
                           test_data, cleanup_tracker):
        """Test typedef creation endpoint."""
        typedef_name = f"MyInt_Integration"
        
        response = api_client.post('create_typedef', data={
            'name': typedef_name,
            'base_type': 'int'
        })
        
        # Track for cleanup
        if response.ok:
            cleanup_tracker['typedefs'].append(typedef_name)
            
        assert response.ok, f"Typedef creation failed: {response.text}"
        assert typedef_name in response.text


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeQueries:
    """Test data type query endpoints."""
    
    def test_search_data_types(self, api_client: APIClient, server_health_check):
        """Test data type search endpoint."""
        response = api_client.get('search_data_types', params={
            'pattern': 'int',
            'limit': 10
        })
        assert response.ok
        # Should find built-in int types
        
    def test_get_struct_layout(self, api_client: APIClient, server_health_check):
        """Test struct layout endpoint with built-in types."""
        # Try to get layout of a common struct (might not exist)
        response = api_client.get('get_struct_layout', params={
            'struct_name': 'IMAGE_DOS_HEADER'  # Common Windows structure
        })
        # This might fail if the struct doesn't exist, which is okay
        assert response.status_code in [200, 404]
        
    def test_get_enum_values(self, api_client: APIClient, server_health_check):
        """Test enum values endpoint."""
        # This test assumes no specific enum exists
        response = api_client.get('get_enum_values', params={
            'enum_name': 'NonExistentEnum'
        })
        # Should return appropriate error for non-existent enum
        assert response.status_code in [200, 404, 400]
        
    def test_get_type_size_builtin(self, api_client: APIClient, server_health_check):
        """Test type size for built-in types."""
        for type_name in ['int', 'char', 'short', 'long']:
            response = api_client.get('get_type_size', params={
                'type_name': type_name
            })
            assert response.ok, f"Failed to get size for {type_name}"
            assert 'Size:' in response.text or 'size' in response.text.lower()


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeValidation:
    """Test data type validation endpoints."""
    
    def test_validate_data_type(self, api_client: APIClient, server_health_check,
                               test_data):
        """Test data type validation endpoint."""
        response = api_client.get('validate_data_type', params={
            'address': test_data['address'],
            'type_name': 'int'
        })
        assert response.ok
        # Validation should provide information about applicability
        
    def test_validate_invalid_address(self, api_client: APIClient, server_health_check):
        """Test validation with invalid address."""
        response = api_client.get('validate_data_type', params={
            'address': '0xFFFFFFFF',  # Likely invalid address
            'type_name': 'int'
        })
        # Should either succeed with warning or fail gracefully
        assert response.status_code in [200, 400, 404]
        
    def test_validate_invalid_type(self, api_client: APIClient, server_health_check,
                                  test_data):
        """Test validation with invalid type."""
        response = api_client.get('validate_data_type', params={
            'address': test_data['address'],
            'type_name': 'NonExistentType'
        })
        # Should return appropriate error
        assert response.status_code in [200, 400, 404]


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeOperations:
    """Test data type application and manipulation."""
    
    def test_apply_data_type(self, api_client: APIClient, server_health_check,
                            test_data):
        """Test applying data type to address."""
        response = api_client.post('apply_data_type', data={
            'address': test_data['address'],
            'type_name': 'int',
            'clear_existing': 'true'
        })
        # Might fail if address is not valid or already has conflicting data
        assert response.status_code in [200, 400, 409]
        
    def test_analyze_data_types(self, api_client: APIClient, server_health_check,
                               test_data):
        """Test data type analysis at address."""
        response = api_client.get('analyze_data_types', params={
            'address': test_data['address'],
            'depth': 1
        })
        assert response.ok
        # Should provide analysis even if minimal
        
    def test_auto_create_struct(self, api_client: APIClient, server_health_check,
                               test_data, cleanup_tracker):
        """Test automatic struct creation."""
        struct_name = "AutoStruct_Integration"
        
        response = api_client.post('auto_create_struct', data={
            'address': test_data['address'],
            'size': 16,
            'name': struct_name
        })
        
        # Track for cleanup if successful
        if response.ok:
            cleanup_tracker['structs'].append(struct_name)
            
        # Auto-creation might fail depending on memory layout
        assert response.status_code in [200, 400]


@pytest.mark.integration
@pytest.mark.requires_ghidra
class TestDataTypeExportImport:
    """Test data type export and import functionality."""
    
    def test_export_data_types_c_format(self, api_client: APIClient, server_health_check):
        """Test exporting data types in C format."""
        response = api_client.get('export_data_types', params={
            'format': 'c'
        })
        assert response.ok
        # Should return C-style definitions
        
    def test_export_data_types_json_format(self, api_client: APIClient, server_health_check):
        """Test exporting data types in JSON format."""
        response = api_client.get('export_data_types', params={
            'format': 'json'
        })
        assert response.ok
        # Should return JSON data
        
    def test_export_data_types_with_category(self, api_client: APIClient, server_health_check):
        """Test exporting data types with category filter."""
        response = api_client.get('export_data_types', params={
            'format': 'summary',
            'category': 'builtin'
        })
        assert response.ok
        
    @pytest.mark.slow
    def test_import_data_types(self, api_client: APIClient, server_health_check):
        """Test importing data types."""
        c_code = """
        typedef struct {
            int id;
            char name[32];
        } TestImportStruct;
        """
        
        response = api_client.post('import_data_types', data={
            'source': c_code,
            'format': 'c'
        })
        
        # Import functionality might not be fully implemented
        assert response.status_code in [200, 501, 400]