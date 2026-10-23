"""Shared tools/ MCP HTTP client and bridge-aligned failure predicate."""

from __future__ import annotations

import json

import pytest

from tools import mcp_http


FAILURE_TABLE = [
    ('{"error": "No function at 0xdead"}', "No function at 0xdead"),
    (
        '{"success": false, "error": "not checked out", "diagnostics": {}}',
        "not checked out",
    ),
    (
        '{"status": "rejected", "error": "first line too short"}',
        "first line too short",
    ),
    (
        '{"status": "rejected", "error": "name_quality", '
        '"message": "Global \'x\' must start with \'g_\'.", '
        '"suggestion": "Prepend g_."}',
        "name_quality — Global 'x' must start with 'g_'. — Prepend g_.",
    ),
    ('{"success": false}', "the server reported failure"),
]

SUCCESS_TABLE = [
    '{"status": "success", "message": "renamed"}',
    '{"functions": ["a", "b"]}',
    '{"error": ""}',
    '{"error": null}',
    "[]",
    "plain text, not JSON",
    "",
]


@pytest.mark.parametrize(("body", "expected"), FAILURE_TABLE)
def test_tools_failure_message_matches_bridge(body, expected):
    from bridge_mcp_ghidra.dispatch import failure_message as bridge_failure

    assert mcp_http.failure_message(body) == expected
    assert bridge_failure(body) == expected
    assert mcp_http.failure_message(body) == bridge_failure(body)


@pytest.mark.parametrize("body", SUCCESS_TABLE)
def test_tools_success_bodies_match_bridge(body):
    from bridge_mcp_ghidra.dispatch import failure_message as bridge_failure

    assert mcp_http.failure_message(body) is None
    assert bridge_failure(body) is None


def test_ensure_ok_fails_on_success_false_and_rejected():
    with pytest.raises(RuntimeError, match="not checked out"):
        mcp_http.ensure_ok("/open_program", {"success": False, "error": "not checked out"})
    with pytest.raises(RuntimeError, match="name_quality"):
        mcp_http.ensure_ok(
            "/rename_symbol",
            {"status": "rejected", "error": "name_quality", "message": "bad"},
        )


def test_ensure_ok_passes_success():
    mcp_http.ensure_ok("/list_open_programs", {"programs": []})


def test_bearer_token_uses_auth_token_env_name(monkeypatch):
    assert mcp_http.AUTH_TOKEN_ENV == "GHIDRA_MCP_AUTH_TOKEN"
    monkeypatch.setenv("GHIDRA_MCP_AUTH_TOKEN", "secret")
    assert mcp_http.bearer_token() == "secret"
    assert mcp_http.bearer_token(env_values={"GHIDRA_MCP_AUTH_TOKEN": "from-dotenv"}) == "from-dotenv"
    assert mcp_http.bearer_token(explicit="") is None


def test_request_unwraps_result_envelope(monkeypatch):
    class FakeResponse:
        status = 200

        def read(self, size=-1):
            return json.dumps({"result": '{"a": 1}'}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        mcp_http.urllib.request, "urlopen", lambda url, timeout=None: FakeResponse()
    )
    assert mcp_http.request("http://h", "x", unwrap_result=True) == {"a": 1}
