"""Regression tests for the endpoint registration integration check."""

from unittest.mock import Mock

import pytest
import requests

from tests.integration.test_all_endpoints import (
    TestEndpointRegistration as _EndpointRegistration,
    server_kind as _server_kind,
)


@pytest.mark.parametrize("server_kind", ["gui", "headless"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_endpoint_registration_does_not_skip_http_assertion_failures(server_kind, method):
    """A supported endpoint returning 404 must fail instead of skipping."""
    client = Mock()
    client.get.return_value.status_code = 404
    client.post.return_value.status_code = 404

    with pytest.raises(AssertionError, match="/missing returned 404"):
        _EndpointRegistration().test_endpoint_not_404(
            client, {"path": "/missing", "method": method, "servers": [server_kind]}, server_kind
        )


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_endpoint_registration_skips_transport_errors(method):
    """An unavailable integration server is still an acceptable skip."""
    client = Mock()
    client.get.side_effect = requests.ConnectionError("server unavailable")
    client.post.side_effect = requests.ConnectionError("server unavailable")

    with pytest.raises(pytest.skip.Exception, match="server unavailable"):
        _EndpointRegistration().test_endpoint_not_404(
            client, {"path": "/missing", "method": method, "servers": ["gui"]}, "gui"
        )


@pytest.mark.parametrize("server_kind, endpoint_kind", [("gui", "headless"), ("headless", "gui")])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_endpoint_registration_skips_other_server_endpoints(server_kind, endpoint_kind, method):
    """An endpoint exclusive to the other server must not be requested."""
    client = Mock()

    with pytest.raises(pytest.skip.Exception, match=f"not supported by the {server_kind} server"):
        _EndpointRegistration().test_endpoint_not_404(
            client, {"path": "/exclusive", "method": method, "servers": [endpoint_kind]}, server_kind
        )

    client.get.assert_not_called()
    client.post.assert_not_called()


@pytest.mark.parametrize("server_kind", ["gui", "headless"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_endpoint_registration_checks_shared_endpoints(server_kind, method):
    """Endpoints advertised by both servers must still be checked on both."""
    client = Mock()
    client.get.return_value.status_code = 200
    client.post.return_value.status_code = 200

    _EndpointRegistration().test_endpoint_not_404(
        client, {"path": "/shared", "method": method, "servers": ["gui", "headless"]}, server_kind
    )

    if method == "GET":
        client.get.assert_called_once_with("/shared", timeout=10)
        client.post.assert_not_called()
    else:
        client.post.assert_called_once_with("/shared", data={}, timeout=10)
        client.get.assert_not_called()


@pytest.mark.parametrize("kind", ["gui", "headless"])
def test_server_kind_reads_health_identity(kind):
    """Server scope comes from the same health identity as the connection test."""
    session = Mock()
    session.get.return_value.status_code = 200
    session.get.return_value.json.return_value = {"status": "ok", "server_kind": kind}

    assert _server_kind.__wrapped__(session, "http://example.test") == kind
    session.get.assert_called_once_with("http://example.test/mcp/health", timeout=10)


def test_server_kind_skips_transport_errors():
    session = Mock()
    session.get.side_effect = requests.ConnectionError("server unavailable")

    with pytest.raises(pytest.skip.Exception, match="server unavailable"):
        _server_kind.__wrapped__(session, "http://example.test")


def test_server_kind_does_not_skip_health_http_failures():
    session = Mock()
    session.get.return_value.status_code = 404

    with pytest.raises(AssertionError):
        _server_kind.__wrapped__(session, "http://example.test")


def test_server_kind_does_not_silently_skip_an_unknown_kind():
    session = Mock()
    session.get.return_value.status_code = 200
    session.get.return_value.json.return_value = {"server_kind": "unknown"}

    with pytest.raises(AssertionError, match="Unknown server kind"):
        _server_kind.__wrapped__(session, "http://example.test")
