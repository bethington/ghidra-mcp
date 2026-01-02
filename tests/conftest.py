"""
GhidraMCP Test Configuration and Fixtures
"""

import json
import os
import pytest
import requests
from pathlib import Path


# =============================================================================
# Configuration
# =============================================================================

def get_server_url():
    """Get the server URL from environment or use default."""
    return os.environ.get("GHIDRA_MCP_URL", "http://localhost:8089")


def get_test_timeout():
    """Get the default test timeout."""
    return int(os.environ.get("GHIDRA_MCP_TIMEOUT", "30"))


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def server_url():
    """Server URL for all tests."""
    return get_server_url()


@pytest.fixture(scope="session")
def endpoints():
    """Load endpoint specifications from JSON."""
    endpoints_file = Path(__file__).parent / "endpoints.json"
    if endpoints_file.exists():
        with open(endpoints_file) as f:
            data = json.load(f)
            return data.get("endpoints", [])
    return []


@pytest.fixture(scope="session")
def endpoints_by_category(endpoints):
    """Group endpoints by category."""
    by_category = {}
    for endpoint in endpoints:
        cat = endpoint.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(endpoint)
    return by_category


@pytest.fixture(scope="session")
def http_session():
    """Create a requests session with default configuration."""
    session = requests.Session()
    session.timeout = get_test_timeout()
    return session


@pytest.fixture
def http_client(http_session, server_url):
    """HTTP client configured for the server."""
    class HttpClient:
        def __init__(self, session, base_url):
            self.session = session
            self.base_url = base_url
            self.timeout = get_test_timeout()

        def get(self, path, params=None, timeout=None):
            url = f"{self.base_url}{path}"
            return self.session.get(
                url,
                params=params,
                timeout=timeout or self.timeout
            )

        def post(self, path, data=None, json_data=None, timeout=None):
            url = f"{self.base_url}{path}"
            return self.session.post(
                url,
                data=data,
                json=json_data,
                timeout=timeout or self.timeout
            )

    return HttpClient(http_session, server_url)


@pytest.fixture(scope="session")
def server_available(server_url):
    """Check if the server is available."""
    try:
        response = requests.get(f"{server_url}/check_connection", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


@pytest.fixture(scope="session")
def program_loaded(server_url, server_available):
    """Check if a program is loaded in the server."""
    if not server_available:
        return False
    try:
        response = requests.get(f"{server_url}/get_metadata", timeout=5)
        if response.status_code != 200:
            return False
        # Check if response contains error
        if "error" in response.text.lower():
            return False
        return True
    except requests.RequestException:
        return False


@pytest.fixture
def sample_function(http_client, program_loaded):
    """Get a sample function address for testing."""
    if not program_loaded:
        pytest.skip("No program loaded")

    response = http_client.get("/list_methods", params={"limit": 1})
    if response.status_code != 200 or not response.text.strip():
        pytest.skip("No functions available")

    # Return first function name
    return response.text.strip().split("\n")[0]


@pytest.fixture
def sample_address(http_client, program_loaded):
    """Get a sample address for testing."""
    if not program_loaded:
        pytest.skip("No program loaded")

    response = http_client.get("/list_functions", params={"limit": 1})
    if response.status_code != 200 or not response.text.strip():
        pytest.skip("No functions available")

    # Parse address from "name @ address" format
    line = response.text.strip().split("\n")[0]
    if " @ " in line:
        return line.split(" @ ")[1]

    pytest.skip("Could not get sample address")


# =============================================================================
# Markers
# =============================================================================

def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "requires_program: mark test as requiring a loaded program"
    )
    config.addinivalue_line(
        "markers", "requires_server: mark test as requiring server connection"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "write: mark test as performing write operations"
    )


# =============================================================================
# Utility Functions
# =============================================================================

def load_endpoints():
    """Load endpoints for parametrization."""
    endpoints_file = Path(__file__).parent / "endpoints.json"
    if endpoints_file.exists():
        with open(endpoints_file) as f:
            data = json.load(f)
            return data.get("endpoints", [])
    return []


def get_endpoint_ids():
    """Get endpoint IDs for test naming."""
    endpoints = load_endpoints()
    return [f"{e['method']}_{e['path']}" for e in endpoints]
