"""Bridge-local guards around the SDK's server transport boundary."""

from types import MethodType

from mcp import types
from mcp.shared.message import SessionMessage
from mcp.shared.session import RequestResponder

from .config import logger

# OpenCode's stdio reader stops at 10 MiB. Leave room for transport buffering;
# measure the serialized message, not text that JSON escaping can double.
MAX_MCP_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_HTTP_RESPONSE_BYTES = 8 * 1024 * 1024

OVERSIZED_RESULT_MESSAGE = (
    "Ghidra result exceeds the bridge's response size limit. "
    "Request a smaller page or narrower selection, or use a file export where available. "
    "The operation may already have completed in Ghidra and was not retried; "
    "verify its state before repeating a write. No partial result was returned."
)


def guard_message(message: SessionMessage, limit: int = MAX_MCP_MESSAGE_BYTES) -> SessionMessage | None:
    wire = message.message.model_dump_json(by_alias=True, exclude_none=True)
    size = len(wire.encode("utf-8")) + 1
    if size <= limit:
        return message
    root = message.message.root
    logger.warning("Blocked oversized MCP %s (%d bytes; limit %d)", type(root).__name__, size, limit)
    if isinstance(root, types.JSONRPCResponse):
        if "content" in root.result:
            result = types.CallToolResult(
                content=[types.TextContent(type="text", text=OVERSIZED_RESULT_MESSAGE)],
                isError=True,
            )
            replacement = types.JSONRPCResponse(
                jsonrpc="2.0",
                id=root.id,
                result=result.model_dump(by_alias=True, exclude_none=True),
            )
        else:
            replacement = types.JSONRPCError(
                jsonrpc="2.0",
                id=root.id,
                error=types.ErrorData(code=types.INTERNAL_ERROR, message=OVERSIZED_RESULT_MESSAGE),
            )
    elif isinstance(root, types.JSONRPCError):
        replacement = types.JSONRPCError(
            jsonrpc="2.0",
            id=root.id,
            error=types.ErrorData(code=types.INTERNAL_ERROR, message=OVERSIZED_RESULT_MESSAGE),
        )
    else:
        # Unsolicited notifications have no request to fail. Never send a
        # partial notification or an unsolicited error response instead.
        return None
    return SessionMessage(types.JSONRPCMessage(replacement), metadata=message.metadata)


class GuardedWriteStream:
    def __init__(self, stream):
        self.stream = stream

    async def send(self, message):
        guarded = guard_message(message)
        if guarded is not None:
            await self.stream.send(guarded)

    async def __aenter__(self):
        await self.stream.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.stream.__aexit__(*args)


async def _cancel_without_response(responder):
    # SDK 1.28.1 replies after cancellation, contrary to the protocol's SHOULD
    # NOT. Keep its completion bookkeeping but do not write that late reply.
    # This is installed on bridge server responders only, never SDK clients.
    if responder._completed:
        return
    responder._cancel_scope.cancel()
    responder._completed = True


def install_protocol_guards(server):
    original_run = server.run
    original_handle = server._handle_message

    async def run(read_stream, write_stream, *args, **kwargs):
        return await original_run(read_stream, GuardedWriteStream(write_stream), *args, **kwargs)

    async def handle(message, *args, **kwargs):
        if isinstance(message, RequestResponder):
            message.cancel = MethodType(_cancel_without_response, message)
        return await original_handle(message, *args, **kwargs)

    server.run = run
    server._handle_message = handle
