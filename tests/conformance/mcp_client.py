"""Minimal MCP client used to drive the Ghidra tool surface.

Deliberately transport-pluggable. Today the only implementation that speaks MCP
is the Python bridge over stdio; the planned Java-native endpoint will speak
Streamable HTTP. Both satisfy `McpTransport`, so the same conformance corpus
runs against either and the results can be diffed field-by-field. That diff is
the acceptance gate for the Java port -- which is the entire reason this suite
targets MCP rather than the plugin's raw HTTP routes.

No third-party MCP SDK on purpose: the suite must be able to prove a *broken*
server is broken, so it does its own framing rather than trusting a client
library to paper over protocol errors.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

PROTOCOL_VERSION = "2024-11-05"


class McpError(RuntimeError):
    """Transport- or protocol-level failure (not a tool returning an error)."""


@dataclass
class ToolResult:
    """One `tools/call` outcome.

    `is_error` is the MCP-level error flag. A tool that *returns* an error
    payload (e.g. `{"error": "..."}`) with is_error=False is a successful call
    with an error result -- the distinction matters, because plenty of these
    tools signal failure in-band and a conformance gate must not conflate them.
    """

    tool: str
    text: str
    is_error: bool
    raw: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0

    def json(self) -> Any | None:
        """Parse `text` as JSON, or None when it isn't JSON.

        Many tools return plain text despite the project's "all endpoints
        return JSON" convention, so callers must handle None rather than
        assume.
        """
        try:
            return json.loads(self.text)
        except (json.JSONDecodeError, TypeError):
            return None


class McpTransport(Protocol):
    def start(self) -> dict[str, Any]: ...
    def list_tools(self) -> list[dict[str, Any]]: ...
    def call_tool(self, name: str, arguments: dict[str, Any], timeout: float) -> ToolResult: ...
    def stop(self) -> None: ...


class StdioTransport:
    """Speaks MCP over a child process's stdin/stdout (the Python bridge)."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None,
                 cwd: str | None = None):
        self.command = command
        self.env = {**os.environ, **(env or {})}
        self.cwd = cwd
        self.proc: subprocess.Popen | None = None
        self._next_id = 0
        self._stderr: list[str] = []

    def start(self) -> dict[str, Any]:
        self.proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=self.env, cwd=self.cwd,
            text=True, encoding="utf-8", bufsize=1,
        )
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        init = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ghidra-mcp-conformance", "version": "1.0"},
        }, timeout=180)
        self._notify("notifications/initialized", {})
        return init

    def _drain_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            self._stderr.append(line.rstrip())

    def _send(self, payload: dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            raise McpError("transport not started")
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        self._next_id += 1
        req_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        deadline = time.time() + timeout
        assert self.proc and self.proc.stdout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise McpError(
                    f"bridge exited rc={self.proc.returncode} during {method}; "
                    f"stderr tail: {self._stderr[-5:]}"
                )
            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.02)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # server log noise on stdout; ignore
            if msg.get("id") != req_id:
                continue
            if "error" in msg:
                raise McpError(f"{method} -> {msg['error']}")
            return msg.get("result", {})
        raise McpError(f"timeout after {timeout}s waiting for {method}")

    def list_tools(self) -> list[dict[str, Any]]:
        return self._request("tools/list", {}, timeout=120).get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any], timeout: float = 60) -> ToolResult:
        started = time.perf_counter()
        result = self._request(
            "tools/call", {"name": name, "arguments": arguments}, timeout=timeout
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        parts = result.get("content") or []
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        return ToolResult(
            tool=name, text=text, is_error=bool(result.get("isError")),
            raw=result, elapsed_ms=elapsed,
        )

    def stop(self) -> None:
        if not self.proc:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    @property
    def stderr_tail(self) -> list[str]:
        return self._stderr[-40:]


class StreamableHttpTransport:
    """Speaks MCP over Streamable HTTP.

    Placeholder for the Java-native endpoint. Implemented now so the corpus and
    runner are written against a transport-agnostic interface from day one --
    when the Java `/mcp` endpoint lands, only this class needs finishing and the
    entire corpus runs against it unchanged.
    """

    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self.url = url
        self.headers = headers or {}
        self.session_id: str | None = None

    def start(self) -> dict[str, Any]:  # pragma: no cover - not yet implemented
        raise NotImplementedError(
            "Streamable HTTP transport lands with the Java-native /mcp endpoint. "
            "Until then use StdioTransport against the Python bridge."
        )

    def list_tools(self) -> list[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def call_tool(self, name, arguments, timeout=60) -> ToolResult:  # pragma: no cover
        raise NotImplementedError

    def stop(self) -> None:  # pragma: no cover
        return


def bridge_transport(repo_root: str, ghidra_url: str = "http://127.0.0.1:8089",
                     debugger_url: str = "http://127.0.0.1:8099") -> StdioTransport:
    """The Python bridge, configured exactly as Claude Code launches it."""
    return StdioTransport(
        command=[
            "uv", "run", "--no-sync", "--directory", repo_root,
            "bridge-mcp-ghidra", "--transport", "stdio",
        ],
        env={
            "GHIDRA_MCP_URL": ghidra_url,
            "GHIDRA_DEBUGGER_URL": debugger_url,
            "PYTHONIOENCODING": "utf-8",
        },
        cwd=repo_root,
    )
