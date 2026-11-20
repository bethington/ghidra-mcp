"""The launcher must keep the MCP stream clean and the session pinned to its tunnel."""
import socket

import pytest

from tools import bridge_via_tunnel as tunnel


def test_tunnel_binds_loopback_only_and_fails_rather_than_half_opening():
    command = tunnel.tunnel_command("user@host", 18000, 8089)
    assert "127.0.0.1:18000:127.0.0.1:8089" in command
    assert "ExitOnForwardFailure=yes" in command
    assert "BatchMode=yes" in command, "a password prompt would hang an MCP client's startup"


def test_session_is_pinned_so_a_local_ghidra_cannot_take_over():
    env = tunnel.bridge_environment({"KEEP": "1", "GHIDRA_MCP_URL": "http://127.0.0.1:8089"}, 18000, "t")
    assert env["GHIDRA_MCP_URL"] == "http://127.0.0.1:18000"
    assert env["GHIDRA_MCP_PIN_URL"] == "1"
    assert env["GHIDRA_MCP_AUTH_TOKEN"] == "t"
    assert env["KEEP"] == "1"


def test_url_passes_the_bridges_own_validation():
    from bridge_mcp_ghidra.validation import validate_server_url

    assert validate_server_url(tunnel.bridge_environment({}, 18000, "t")["GHIDRA_MCP_URL"])


def test_token_is_read_from_the_named_container():
    command = tunnel.token_command("user@host", "my-container")
    assert command[-1] == "docker exec my-container printenv GHIDRA_MCP_AUTH_TOKEN"


def test_missing_token_stops_startup(monkeypatch):
    class Result:
        returncode = 0
        stdout = "  \n"
        stderr = ""

    monkeypatch.setattr(tunnel.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(SystemExit):
        tunnel.read_token("user@host", "ghidra-mcp")


def test_log_never_touches_stdout(capsys):
    tunnel.log("hello")
    captured = capsys.readouterr()
    assert captured.out == "", "stdout is the MCP stream"
    assert "hello" in captured.err


def test_free_port_is_bindable():
    port = tunnel.free_port()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))


def test_wait_until_listening_sees_a_listener():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        assert tunnel.wait_until_listening(listener.getsockname()[1], timeout=2)


def test_wait_until_listening_gives_up():
    assert not tunnel.wait_until_listening(tunnel.free_port(), timeout=0.3)
