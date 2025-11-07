"""
Test configuration and shared fixtures for GhidraMCP test suite.
"""
import pytest
import requests
import time
import os
import json
from typing import Dict, Optional, Any, Generator
from urllib.parse import urljoin


class TestConfig:
    """Centralized test configuration."""
    
    # Server configuration
    DEFAULT_SERVER_URL = "http://127.0.0.1:8089"
    TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0
    
    # Test data
    TEST_DATA = {
        'address': '0x401000',
        'function_name': 'main',
        'struct_name': 'TestStruct_MCP',
        'enum_name': 'TestEnum_MCP',
        'union_name': 'TestUnion_MCP',
        'label_name': 'test_label_mcp',
        'variable_name': 'test_var',
        'type_name': 'int',
        'prototype': 'int test_function(int param1, char* param2)',
        'comment': 'Test comment from MCP test suite'
    }
    
    # Test limits
    LIMITS = {
        'list_functions': 10,
        'list_strings': 20,
        'list_imports': 10,
        'list_exports': 10,
        'list_segments': 5
    }


class APIClient:
    """HTTP client for testing GhidraMCP REST API."""
    
    def __init__(self, base_url: str = TestConfig.DEFAULT_SERVER_URL):
        self.base_url = base_url.rstrip('/') + '/'
        self.session = requests.Session()
        self.session.timeout = TestConfig.TIMEOUT
        
    def get(self, endpoint: str, params: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Make GET request."""
        url = urljoin(self.base_url, endpoint)
        return self.session.get(url, params=params, **kwargs)
    
    def post(self, endpoint: str, data: Optional[Dict] = None, json: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Make POST request with JSON encoding by default."""
        url = urljoin(self.base_url, endpoint)
        # If data is provided and json is not, convert data to json
        if data is not None and json is None:
            json = data
            data = None
        return self.session.post(url, data=data, json=json, **kwargs)
    
    def put(self, endpoint: str, data: Optional[Dict] = None, json: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Make PUT request with JSON encoding by default."""
        url = urljoin(self.base_url, endpoint)
        # If data is provided and json is not, convert data to json
        if data is not None and json is None:
            json = data
            data = None
        return self.session.put(url, data=data, json=json, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        """Make DELETE request."""
        url = urljoin(self.base_url, endpoint)
        return self.session.delete(url, **kwargs)


@pytest.fixture(scope='session')
def server_url() -> str:
    """Get server URL from environment or use default."""
    return os.getenv('GHIDRA_MCP_SERVER_URL', TestConfig.DEFAULT_SERVER_URL)


@pytest.fixture(scope='session')
def api_client(server_url: str) -> APIClient:
    """Create API client for the test session."""
    return APIClient(server_url)


@pytest.fixture(scope='session')
def server_health_check(api_client: APIClient) -> Dict[str, Any]:
    """Check server health and skip tests if not available."""
    try:
        response = api_client.get('check_connection')
        if not response.ok:
            pytest.skip(f"Ghidra server not available: {response.status_code}")
        
        # Get server metadata
        metadata_response = api_client.get('get_metadata')
        metadata = {}
        if metadata_response.ok:
            metadata['raw'] = metadata_response.text
            
        return {
            'connection': response.text,
            'metadata': metadata,
            'status': 'healthy'
        }
    except Exception as e:
        pytest.skip(f"Cannot connect to Ghidra server: {e}")


@pytest.fixture(scope='function')
def test_data() -> Dict[str, Any]:
    """Provide test data for individual tests."""
    return TestConfig.TEST_DATA.copy()


@pytest.fixture(scope='function')
def cleanup_tracker() -> Generator[Dict[str, list], None, None]:
    """Track created test resources for cleanup."""
    tracker = {
        'structs': [],
        'unions': [],
        'enums': [],
        'typedefs': [],
        'labels': [],
        'functions': []
    }
    
    yield tracker
    
    # Cleanup logic would go here
    # Note: Actual cleanup depends on Ghidra MCP cleanup endpoints
    # which may not exist yet


@pytest.fixture(scope='function')
def retry_config() -> Dict[str, Any]:
    """Configuration for retry logic in flaky tests."""
    return {
        'max_retries': TestConfig.MAX_RETRIES,
        'delay': TestConfig.RETRY_DELAY,
        'backoff_factor': 1.5
    }


def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "functional: mark test as functional test"
    )
    config.addinivalue_line(
        "markers", "requires_ghidra: mark test as requiring Ghidra server"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add markers based on test location
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "functional" in str(item.fspath):
            item.add_marker(pytest.mark.functional)
        elif "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
            
        # Mark tests that require Ghidra
        if "requires_ghidra" in item.keywords or "api_client" in item.fixturenames:
            item.add_marker(pytest.mark.requires_ghidra)


def pytest_runtest_setup(item):
    """Setup for individual test runs."""
    # Skip slow tests unless explicitly requested
    if "slow" in item.keywords and not item.config.getoption("--runslow", default=False):
        pytest.skip("need --runslow option to run")


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--runslow", 
        action="store_true", 
        default=False, 
        help="run slow tests"
    )
    parser.addoption(
        "--server-url",
        action="store",
        default=TestConfig.DEFAULT_SERVER_URL,
        help="Ghidra MCP server URL"
    )