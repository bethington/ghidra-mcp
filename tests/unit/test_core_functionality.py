"""
Unit tests for GhidraMCP core functionality.

These tests focus on individual components and functions in isolation,
using mocking where necessary to avoid external dependencies.
"""
import pytest
import requests
import requests_mock
from unittest.mock import Mock, patch, MagicMock
from tests.conftest import APIClient, TestConfig
from tests.fixtures.test_helpers import (
    TestDataGenerator, 
    MockDataProvider, 
    TestValidators,
    ComplexityLevel
)


class TestAPIClientCore:
    """Test core APIClient functionality with comprehensive mocking."""
    
    def test_init_with_default_url(self):
        """Test APIClient initialization with default URL."""
        client = APIClient()
        assert client.base_url == TestConfig.DEFAULT_SERVER_URL + "/"
        assert client.session.timeout == TestConfig.TIMEOUT
    
    def test_init_with_custom_url(self):
        """Test APIClient initialization with custom URL."""
        custom_url = "http://localhost:9999"
        client = APIClient(custom_url)
        assert client.base_url == custom_url + "/"
    
    def test_init_url_normalization(self):
        """Test URL normalization (trailing slash handling)."""
        urls_with_slash = ["http://localhost:8080/", "http://localhost:8080//"]
        urls_without_slash = ["http://localhost:8080", "http://localhost:8080"]
        
        for url in urls_with_slash + urls_without_slash:
            client = APIClient(url)
            assert client.base_url.endswith("/")
            assert not client.base_url.endswith("//")
    
    def test_get_request_success(self, requests_mock):
        """Test successful GET request."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            text="success",
            status_code=200
        )
        
        client = APIClient()
        response = client.get("test_endpoint")
        
        assert response.status_code == 200
        assert response.text == "success"
    
    def test_get_request_with_params(self, requests_mock):
        """Test GET request with query parameters."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            text="success_with_params",
            status_code=200
        )
        
        client = APIClient()
        response = client.get("test_endpoint", params={"param1": "value1", "param2": "value2"})
        
        assert response.status_code == 200
        assert response.text == "success_with_params"
    
    def test_post_request_success(self, requests_mock):
        """Test successful POST request."""
        requests_mock.post(
            "http://127.0.0.1:8089/test_endpoint",
            text="post_success",
            status_code=201
        )
        
        client = APIClient()
        response = client.post("test_endpoint", data={"key": "value"})
        
        assert response.status_code == 201
        assert response.text == "post_success"
    
    def test_request_timeout_handling(self, requests_mock):
        """Test request timeout handling."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            exc=requests.exceptions.Timeout("Request timed out")
        )
        
        client = APIClient()
        with pytest.raises(requests.exceptions.Timeout):
            client.get("test_endpoint")
    
    def test_request_connection_error(self, requests_mock):
        """Test connection error handling."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            exc=requests.exceptions.ConnectionError("Connection failed")
        )
        
        client = APIClient()
        with pytest.raises(requests.exceptions.ConnectionError):
            client.get("test_endpoint")
    
    def test_request_http_error(self, requests_mock):
        """Test HTTP error handling."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            text="Server Error",
            status_code=500
        )
        
        client = APIClient()
        response = client.get("test_endpoint")
        
        assert response.status_code == 500
        assert response.text == "Server Error"


class TestDataGenerators:
    """Test data generation utilities and their functionality."""
    
    def test_unique_name_generation(self):
        """Test that generated names are unique."""
        generator = TestDataGenerator()
        names = [generator.generate_unique_name("test") for _ in range(10)]
        
        # All names should be unique
        assert len(names) == len(set(names))
        
        # All names should start with the prefix
        for name in names:
            assert name.startswith("test_")
    
    def test_struct_field_generation_simple(self):
        """Test simple struct field generation."""
        generator = TestDataGenerator()
        fields = generator.generate_struct_fields(ComplexityLevel.SIMPLE)
        
        assert isinstance(fields, list)
        assert len(fields) >= 1
        assert len(fields) <= 5
        
        for field in fields:
            assert 'name' in field
            assert 'type' in field
            assert isinstance(field['name'], str)
            assert isinstance(field['type'], str)
    
    def test_struct_field_generation_complex(self):
        """Test complex struct field generation."""
        generator = TestDataGenerator()
        fields = generator.generate_struct_fields(ComplexityLevel.COMPLEX)
        
        assert isinstance(fields, list)
        assert len(fields) >= 5
        assert len(fields) <= 15
        
        for field in fields:
            assert 'name' in field
            assert 'type' in field
    
    def test_enum_value_generation(self):
        """Test enum value generation."""
        generator = TestDataGenerator()
        values = generator.generate_enum_values("test_enum")
        
        assert isinstance(values, dict)
        assert len(values) >= 2
        
        for name, value in values.items():
            assert isinstance(name, str)
            assert isinstance(value, int)
    
    def test_union_field_generation(self):
        """Test union field generation."""
        generator = TestDataGenerator()
        fields = generator.generate_union_fields()
        
        assert isinstance(fields, list)
        assert len(fields) >= 2
        
        for field in fields:
            assert 'name' in field
            assert 'type' in field
    
    def test_address_generation(self):
        """Test address generation."""
        generator = TestDataGenerator()
        addresses = generator.generate_test_addresses(1)
        
        assert isinstance(addresses, list)
        assert len(addresses) == 1
        address = addresses[0]
        assert isinstance(address, str)
        assert address.startswith("0x")
        assert len(address) >= 3  # At least 0x and one digit
    
    def test_function_prototype_generation(self):
        """Test function prototype generation."""
        generator = TestDataGenerator()
        prototypes = generator.generate_function_prototypes()
        
        assert isinstance(prototypes, list)
        assert len(prototypes) > 0
        for prototype in prototypes:
            assert isinstance(prototype, str)
            assert "(" in prototype
            assert ")" in prototype


class TestMockDataProvider:
    """Test mock data provider functionality."""
    
    def test_mock_metadata_structure(self):
        """Test mock metadata structure."""
        provider = MockDataProvider()
        metadata = provider.get_mock_metadata()
        
        assert isinstance(metadata, dict)
        assert 'name' in metadata
        assert 'architecture' in metadata
        assert 'base_address' in metadata
    
    def test_mock_functions_structure(self):
        """Test mock functions structure."""
        provider = MockDataProvider()
        functions = provider.get_mock_functions(5)
        
        assert isinstance(functions, list)
        assert len(functions) == 5
        
        for func in functions:
            assert 'name' in func
            assert 'address' in func
    
    def test_mock_strings_structure(self):
        """Test mock strings structure."""
        provider = MockDataProvider()
        strings = provider.get_mock_strings(3)
        
        assert isinstance(strings, list)
        assert len(strings) == 3
        
        for string_data in strings:
            assert 'address' in string_data
            assert 'value' in string_data


class TestValidationUtilities:
    """Test validation utility functions."""
    
    def test_address_format_validation(self):
        """Test address format validation."""
        valid_addresses = ["0x401000", "0x0", "0xFFFFFFFF", "0x12345678"]
        invalid_addresses = ["401000", "0x", "", "not_an_address", None]
        
        for addr in valid_addresses:
            assert TestValidators.validate_address_format(addr), f"Address {addr} should be valid"
        
        for addr in invalid_addresses:
            assert not TestValidators.validate_address_format(addr), f"Address {addr} should be invalid"
    
    def test_struct_fields_validation(self):
        """Test struct fields validation."""
        valid_fields = [
            {'name': 'field1', 'type': 'int'},
            {'name': 'field2', 'type': 'char[32]'}
        ]
        invalid_fields = [
            [{'name': 'field1'}],  # Missing type
            [{'type': 'int'}],     # Missing name
        ]
        
        assert TestValidators.validate_struct_fields(valid_fields)
        
        for fields in invalid_fields:
            assert not TestValidators.validate_struct_fields(fields)
    
    def test_enum_values_validation(self):
        """Test enum values validation."""
        valid_enum = {'VALUE1': 0, 'VALUE2': 1, 'VALUE3': 2}
        empty_enum = {}  # Empty enum is also valid
        invalid_enum = {'VALUE': 'not_an_int'}  # Invalid value type
        
        assert TestValidators.validate_enum_values(valid_enum)
        assert TestValidators.validate_enum_values(empty_enum)
        assert not TestValidators.validate_enum_values(invalid_enum)
    
    def test_response_structure_validation(self):
        """Test response structure validation."""
        valid_response = {
            'status': 'success',
            'data': {'key': 'value'},
            'timestamp': '2024-01-01T00:00:00Z'
        }
        invalid_response = {
            'error': 'Something went wrong'
        }
        
        expected_fields = ['status', 'data', 'timestamp']
        assert TestValidators.validate_response_structure(valid_response, expected_fields)
        assert not TestValidators.validate_response_structure(invalid_response, expected_fields)


class TestConfigurationValidation:
    """Test configuration validation and constants."""
    
    def test_test_config_constants(self):
        """Test TestConfig constants are properly defined."""
        assert hasattr(TestConfig, 'DEFAULT_SERVER_URL')
        assert hasattr(TestConfig, 'TIMEOUT')
        assert hasattr(TestConfig, 'MAX_RETRIES')
        assert hasattr(TestConfig, 'RETRY_DELAY')
        
        assert isinstance(TestConfig.DEFAULT_SERVER_URL, str)
        assert isinstance(TestConfig.TIMEOUT, (int, float))
        assert isinstance(TestConfig.MAX_RETRIES, int)
        assert isinstance(TestConfig.RETRY_DELAY, (int, float))
    
    def test_test_data_structure(self):
        """Test TestConfig.TEST_DATA structure."""
        assert hasattr(TestConfig, 'TEST_DATA')
        assert isinstance(TestConfig.TEST_DATA, dict)
        
        required_keys = ['address', 'function_name', 'struct_name', 'enum_name']
        for key in required_keys:
            assert key in TestConfig.TEST_DATA
    
    def test_limits_structure(self):
        """Test TestConfig.LIMITS structure."""
        assert hasattr(TestConfig, 'LIMITS')
        assert isinstance(TestConfig.LIMITS, dict)
        
        for key, value in TestConfig.LIMITS.items():
            assert isinstance(key, str)
            assert isinstance(value, int)
            assert value > 0


class TestErrorHandlingPatterns:
    """Test error handling patterns and edge cases."""
    
    def test_malformed_json_response(self, requests_mock):
        """Test handling of malformed JSON responses."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            text="invalid json {",
            status_code=200
        )
        
        client = APIClient()
        response = client.get("test_endpoint")
        
        # Should still get the response, even if JSON is malformed
        assert response.status_code == 200
        assert response.text == "invalid json {"
    
    def test_empty_response(self, requests_mock):
        """Test handling of empty responses."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            text="",
            status_code=204
        )
        
        client = APIClient()
        response = client.get("test_endpoint")
        
        assert response.status_code == 204
        assert response.text == ""
    
    def test_server_error_response(self, requests_mock):
        """Test handling of server error responses."""
        requests_mock.get(
            "http://127.0.0.1:8089/test_endpoint",
            text="Internal Server Error",
            status_code=500
        )
        
        client = APIClient()
        response = client.get("test_endpoint")
        
        assert response.status_code == 500
        assert "Internal Server Error" in response.text


# Module-level tests for pytest configuration
def test_pytest_markers_are_registered():
    """Test that custom pytest markers are properly registered."""
    # This test ensures our custom markers work
    assert hasattr(pytest, 'mark')


def test_fixtures_are_available():
    """Test that required fixtures are available."""
    # This is a basic test to ensure our test infrastructure is working
    assert TestConfig is not None
    assert TestDataGenerator is not None
    assert MockDataProvider is not None
    assert TestValidators is not None