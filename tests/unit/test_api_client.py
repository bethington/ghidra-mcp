"""
Unit tests for GhidraMCP API client and basic functionality.

These tests focus on testing individual components in isolation
without requiring a full Ghidra instance.
"""
import pytest
import requests
from unittest.mock import Mock, patch
from tests.conftest import APIClient, TestConfig


class TestAPIClient:
    """Test the APIClient class."""
    
    def test_init_default_url(self):
        """Test APIClient initialization with default URL."""
        client = APIClient()
        assert client.base_url == TestConfig.DEFAULT_SERVER_URL + "/"
        
    def test_init_custom_url(self):
        """Test APIClient initialization with custom URL."""
        custom_url = "http://localhost:8080"
        client = APIClient(custom_url)
        assert client.base_url == custom_url + "/"
        
    def test_init_url_trailing_slash(self):
        """Test APIClient handles trailing slash correctly."""
        url_with_slash = "http://localhost:8080/"
        client = APIClient(url_with_slash)
        assert client.base_url == url_with_slash
        
    def test_get_request(self, requests_mock):
        """Test GET request functionality."""
        client = APIClient("http://test.com")
        requests_mock.get("http://test.com/test", text="success")
        
        response = client.get("test")
        assert response.text == "success"
        assert response.status_code == 200
        
    def test_get_request_with_params(self, requests_mock):
        """Test GET request with parameters."""
        client = APIClient("http://test.com")
        requests_mock.get("http://test.com/test?param=value", text="success")
        
        response = client.get("test", params={"param": "value"})
        assert response.text == "success"
        
    def test_post_request(self, requests_mock):
        """Test POST request functionality."""
        client = APIClient("http://test.com")
        requests_mock.post("http://test.com/test", text="created")
        
        response = client.post("test", data={"key": "value"})
        assert response.text == "created"
        
    def test_request_timeout(self, requests_mock):
        """Test request timeout configuration."""
        client = APIClient("http://test.com")
        requests_mock.get("http://test.com/test", exc=requests.exceptions.Timeout)
        
        with pytest.raises(requests.exceptions.Timeout):
            client.get("test")


class TestTestConfig:
    """Test the TestConfig class."""
    
    def test_default_server_url(self):
        """Test default server URL."""
        assert TestConfig.DEFAULT_SERVER_URL == "http://127.0.0.1:8089"
        
    def test_timeout_value(self):
        """Test timeout configuration."""
        assert TestConfig.TIMEOUT == 30
        assert isinstance(TestConfig.TIMEOUT, int)
        
    def test_test_data_structure(self):
        """Test test data structure."""
        data = TestConfig.TEST_DATA
        assert isinstance(data, dict)
        assert 'address' in data
        assert 'function_name' in data
        assert 'struct_name' in data
        
    def test_limits_structure(self):
        """Test limits configuration."""
        limits = TestConfig.LIMITS
        assert isinstance(limits, dict)
        assert all(isinstance(v, int) for v in limits.values())


class TestUtilityFunctions:
    """Test utility functions (if any are added to conftest.py)."""
    
    def test_placeholder(self):
        """Placeholder test for future utility functions."""
        # This test ensures the test file is not empty
        # and provides a template for future utility function tests
        assert True