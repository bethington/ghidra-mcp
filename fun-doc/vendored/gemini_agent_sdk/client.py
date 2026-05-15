"""Main GeminiCli client — spawns the CLI and streams typed events."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from dataclasses import dataclass, field
from typing import AsyncIterator

from .discovery import find_gemini_binary
from .events import (
    ErrorEvent,
    GeminiEvent,
    ResultEvent,
    parse_event,
)


@dataclass
class GeminiOptions:
    """Options for the Gemini CLI session."""

    model: str = "gemini-2.5-pro"
    approval_mode: str = "yolo"
    allowed_mcp_servers: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout: float = 600.0
    gemini_path: str | None = None


@dataclass(frozen=True, slots=True)
class SyncResult:
    """Result from a synchronous (non-streaming) run."""

    response: str
    input_tokens: int = 0
    output_tokens: int = 0
    events: list[GeminiEvent] = field(default_factory=list)


class GeminiCli:
    """Wraps the Gemini CLI binary in headless mode."""

    def __init__(self, options: GeminiOptions | None = None):
        self._options = options or GeminiOptions()
        self._binary = find_gemini_binary(self._options.gemini_path)

    def _build_args(self, prompt: str) -> list[str]:
        """Build the CLI argument list."""
        args = [
            self._binary,
            "--output-format",
            "stream-json",
            "--approval-mode",
            self._options.approval_mode,
        ]

        if self._options.model:
            args.extend(["--model", self._options.model])

        for server in self._options.allowed_mcp_servers:
            args.extend(["--allowed-mcp-server-names", server])

        # Use stdin for the prompt to avoid OS command-line length limits.
        # The -p "" flag enables headless mode; the actual prompt text is
        # piped via stdin (Gemini CLI appends -p value to stdin content).
        args.extend(["-p", ""])

        return args

    def _build_env(self) -> dict[str, str]:
        """Build the process environment."""
        env = os.environ.copy()
        env.update(self._options.env)
        return env

    async def run(self, prompt: str) -> AsyncIterator[GeminiEvent]:
        """Run a prompt and stream typed events.

        Yields GeminiEvent instances as they arrive from the CLI.
        """
        args = self._build_args(prompt)
        env = self._build_env()

        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self._options.cwd,
            env=env,
        )

        # Feed the prompt via stdin to avoid OS command-line length limits
        if process.stdin:
            process.stdin.write(prompt.encode("utf-8"))
            process.stdin.close()

        try:
            async for event in self._read_events(process):
                yield event
        finally:
            if process.returncode is None:
                try:
                    if sys.platform == "win32":
                        process.kill()
                    else:
                        process.send_signal(signal.SIGTERM)
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except (ProcessLookupError, asyncio.TimeoutError):
                    process.kill()

    async def _read_events(
        self, process: asyncio.subprocess.Process
    ) -> AsyncIterator[GeminiEvent]:
        """Read JSONL lines from stdout and yield parsed events."""
        assert process.stdout is not None

        buffer = b""
        while True:
            chunk = await process.stdout.read(8192)
            if not chunk:
                break

            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = parse_event(data)
                if event is not None:
                    yield event

        # Wait for process to finish
        await process.wait()

        # Check for errors on stderr
        if process.returncode != 0 and process.stderr:
            stderr_data = await process.stderr.read()
            stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
            if stderr_text:
                yield ErrorEvent(message=stderr_text, fatal=True)

    async def run_sync(self, prompt: str) -> SyncResult:
        """Run a prompt and return the final result (non-streaming).

        Collects all events and returns a SyncResult with the response text.
        """
        events: list[GeminiEvent] = []
        response = ""
        input_tokens = 0
        output_tokens = 0

        async for event in self.run(prompt):
            events.append(event)
            if isinstance(event, ResultEvent):
                response = event.response
                input_tokens = event.input_tokens
                output_tokens = event.output_tokens

        return SyncResult(
            response=response,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            events=events,
        )
