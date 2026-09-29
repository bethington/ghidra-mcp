"""Regression tests for the endpoint registration integration check."""

import pytest
import requests

from tests.integration.test_all_endpoints import TestEndpointRegistration as _EndpointRegistration


class _Response:
    def __init__(self, status_code):
        self.status_code = status_code


class _HttpClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def get(self, path, timeout=None):
        if self.error:
            raise self.error
        return self.response


def test_endpoint_registration_does_not_skip_http_assertion_failures():
    """A missing endpoint must fail instead of being reported as skipped."""
    client = _HttpClient(response=_Response(status_code=404))

    with pytest.raises(AssertionError, match="/missing returned 404"):
        _EndpointRegistration().test_endpoint_not_404(
            client, {"path": "/missing", "method": "GET"}
        )


def test_endpoint_registration_skips_transport_errors():
    """An unavailable integration server is still an acceptable skip."""
    client = _HttpClient(error=requests.ConnectionError("server unavailable"))

    with pytest.raises(pytest.skip.Exception, match="server unavailable"):
        _EndpointRegistration().test_endpoint_not_404(
            client, {"path": "/health", "method": "GET"}
        )
