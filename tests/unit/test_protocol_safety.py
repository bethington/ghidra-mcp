"""Protocol regressions exercised through a real bridge stdio subprocess."""

import json
import queue
import subprocess
import sys
import threading
from unittest.mock import Mock, patch
from pathlib import Path

import pytest

from mcp import types
from mcp.shared.message import SessionMessage

from bridge_mcp_ghidra import transport
from bridge_mcp_ghidra.protocol_safety import guard_message, _cancel_without_response

_SERVER = r"""
import asyncio
from bridge_mcp_ghidra.server import Context, mcp

@mcp.tool(structured_output=False)
def payload(character: str, count: int, fail: bool = False) -> str:
    text = character * count
    if fail:
        raise ValueError(text)
    return text

@mcp.tool(structured_output=False)
async def slow(ctx: Context) -> str:
    await ctx.session.send_log_message(level="info", data="slow started")
    await asyncio.sleep(60)
    return "finished"

mcp.run(transport="stdio")
"""


class StdioPeer:
    def __init__(self):
        self.process = subprocess.Popen(
            [sys.executable, "-c", _SERVER],
            cwd=Path(__file__).resolve().parents[2],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.messages = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            self.messages.put((len(line), json.loads(line)))

    def send(self, **message):
        self.process.stdin.write((json.dumps({"jsonrpc": "2.0", **message}) + "\n").encode())
        self.process.stdin.flush()

    def receive(self):
        return self.messages.get(timeout=10)

    def ping(self, request_id=99):
        self.send(id=request_id, method="ping")
        _, response = self.receive()
        assert response == {"jsonrpc": "2.0", "id": request_id, "result": {}}

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        self.reader.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()


@pytest.fixture
def peer():
    client = StdioPeer()
    try:
        client.send(
            id=1,
            method="initialize",
            params={
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "protocol-safety-test", "version": "1"},
            },
        )
        _, response = client.receive()
        assert response["id"] == 1 and "result" in response
        client.send(method="notifications/initialized")
        yield client
    finally:
        client.close()


@pytest.mark.parametrize(
    "character,count,fail",
    [
        ("x", 11 * 1024 * 1024, False),
        ('"', 6 * 1024 * 1024, False),
        ("😀", 3 * 1024 * 1024, False),
        ("x", 11 * 1024 * 1024, True),
    ],
)
def test_oversized_tool_result_is_small_error_and_session_survives(peer, character, count, fail):
    peer.send(
        id=2,
        method="tools/call",
        params={
            "name": "payload",
            "arguments": {"character": character, "count": count, "fail": fail},
        },
    )
    size, response = peer.receive()
    assert size < 10 * 1024 * 1024
    assert response["id"] == 2
    assert response["result"]["isError"] is True
    assert "not retried" in response["result"]["content"][0]["text"]
    peer.ping()


def test_small_result_is_unchanged(peer):
    text = 'hello "世界"\n'
    peer.send(
        id=2,
        method="tools/call",
        params={
            "name": "payload",
            "arguments": {"character": text, "count": 2},
        },
    )
    _, response = peer.receive()
    assert response["result"] == {"content": [{"type": "text", "text": text * 2}], "isError": False}
    peer.ping()


def test_cancelled_request_has_no_response_and_session_survives(peer):
    peer.send(id=2, method="tools/call", params={"name": "slow", "arguments": {}})
    _, started = peer.receive()
    assert started["method"] == "notifications/message"
    peer.send(method="notifications/cancelled", params={"requestId": 2, "reason": "test"})
    peer.ping()
    peer.send(method="notifications/cancelled", params={"requestId": 2})
    peer.send(method="notifications/cancelled", params={"requestId": "unknown"})
    peer.ping(100)


@pytest.mark.parametrize("text", ['"\\\n' * 100, "😀世界" * 100])
def test_guard_checks_exact_serialized_boundary_and_preserves_metadata(text):
    message = SessionMessage(
        types.JSONRPCMessage(
            types.JSONRPCResponse(
                jsonrpc="2.0",
                id="request-123",
                result={"content": [{"type": "text", "text": text}]},
            )
        )
    )
    size = len(message.message.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")) + 1
    assert guard_message(message, limit=size) is message
    guarded = guard_message(message, limit=size - 1)
    assert guarded.message.root.id == "request-123"
    assert guarded.metadata is message.metadata
    assert guarded.message.root.result["isError"] is True


def test_non_tool_response_and_protocol_error_are_bounded():
    for root in (
        types.JSONRPCResponse(jsonrpc="2.0", id=3, result={"tools": ["x" * 10000]}),
        types.JSONRPCError(jsonrpc="2.0", id=3, error=types.ErrorData(code=0, message="x" * 10000)),
    ):
        guarded = guard_message(SessionMessage(types.JSONRPCMessage(root)), limit=1000)
        assert isinstance(guarded.message.root, types.JSONRPCError)
        assert guarded.message.root.id == 3
        assert len(guarded.message.model_dump_json().encode()) < 1000


def test_oversized_notification_is_not_sent_as_unsolicited_error():
    message = SessionMessage(
        types.JSONRPCMessage(
            types.JSONRPCNotification(
                jsonrpc="2.0",
                method="notifications/message",
                params={"data": "x" * 10000},
            )
        )
    )
    assert guard_message(message, limit=1000) is None


def test_cancellation_keeps_sdk_completion_cleanup_without_reply():
    import anyio
    from mcp.shared.session import RequestResponder

    session = Mock()
    completed = []

    async def cancel():
        responder = RequestResponder(1, None, Mock(), session, completed.append)
        # RequestResponder.__exit__ discards CancelScope.__exit__'s return
        # value; the low-level request handler catches this cancellation.
        with pytest.raises(anyio.get_cancelled_exc_class()):
            with responder:
                await _cancel_without_response(responder)
                assert responder.cancelled
                assert not responder.in_flight
                await anyio.lowlevel.checkpoint()

    anyio.run(cancel)
    assert len(completed) == 1
    assert completed[0]._completed
    session._send_response.assert_not_called()


@pytest.mark.asyncio
async def test_completed_request_is_not_cancelled_again():
    responder = Mock(_completed=True)
    await _cancel_without_response(responder)
    responder._cancel_scope.cancel.assert_not_called()


@pytest.mark.parametrize("declared_length", [100, None])
def test_http_buffer_limit_closes_connection(declared_length):
    connection = Mock()
    response = connection.getresponse.return_value
    response.length = declared_length
    response.read.return_value = b"x" * 11
    with patch.object(transport, "MAX_HTTP_RESPONSE_BYTES", 10):
        with pytest.raises(transport.ResponseTooLargeError):
            transport._request_over_connection(connection, "POST", "/write", None, {})
    connection.close.assert_called_once()
    if declared_length is None:
        response.read.assert_called_once_with(11)
    else:
        response.read.assert_not_called()


def test_short_http_body_remains_outcome_unknown():
    connection = Mock()
    response = connection.getresponse.return_value
    response.length = 20
    response.read.return_value = b"partial"
    with pytest.raises(transport.RequestOutcomeUnknownError):
        transport._request_over_connection(connection, "POST", "/write", None, {})
    connection.close.assert_called_once()
