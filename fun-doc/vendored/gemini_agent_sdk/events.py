"""Typed event dataclasses for Gemini CLI JSONL output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class InitEvent:
    """Emitted once at session start."""

    session_id: str = ""
    model: str = ""


@dataclass(frozen=True, slots=True)
class MessageEvent:
    """A user or assistant message."""

    role: str = ""
    content: str = ""


@dataclass(frozen=True, slots=True)
class ToolUseEvent:
    """A tool call request from the model."""

    name: str = ""
    tool_id: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolResultEvent:
    """The result of a tool execution."""

    name: str = ""
    tool_id: str = ""
    output: str = ""
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class ErrorEvent:
    """A warning or error from the CLI."""

    message: str = ""
    fatal: bool = False


@dataclass(frozen=True, slots=True)
class ResultEvent:
    """Final result emitted at the end of a turn."""

    response: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


# Union type of all events
GeminiEvent = (
    InitEvent | MessageEvent | ToolUseEvent | ToolResultEvent | ErrorEvent | ResultEvent
)

# Mapping from JSONL "type" field to event class
_EVENT_MAP: dict[str, type] = {
    "init": InitEvent,
    "message": MessageEvent,
    "tool_use": ToolUseEvent,
    "tool_result": ToolResultEvent,
    "error": ErrorEvent,
    "result": ResultEvent,
}


def parse_event(data: dict[str, Any]) -> GeminiEvent | None:
    """Parse a JSONL dict into a typed event. Returns None for unknown types."""
    event_type = data.get("type", "")
    cls = _EVENT_MAP.get(event_type)
    if cls is None:
        return None

    # Gemini CLI uses different field names than our dataclasses.
    # Map them before filtering to known fields.
    if event_type == "tool_use":
        mapped = {
            "name": data.get("tool_name", ""),
            "tool_id": data.get("tool_id", ""),
            "arguments": data.get("parameters", {}),
        }
        return cls(**mapped)

    if event_type == "tool_result":
        mapped = {
            "name": _tool_name_from_id(data.get("tool_id", "")),
            "tool_id": data.get("tool_id", ""),
            "output": data.get("output", ""),
            "is_error": data.get("status", "success") != "success",
        }
        return cls(**mapped)

    if event_type == "result":
        # Token counts appear either as top-level keys or nested under a
        # `stats` object depending on the Gemini CLI version. Read the
        # top-level form first, fall back to `stats`.
        stats = data.get("stats") or {}
        mapped = {
            "response": data.get("response", ""),
            "input_tokens": data.get("input_tokens", stats.get("input_tokens", 0)),
            "output_tokens": data.get("output_tokens", stats.get("output_tokens", 0)),
        }
        return cls(**mapped)

    # Generic path: filter data keys to known dataclass fields
    field_names = {f.name for f in cls.__dataclass_fields__.values()}
    kwargs = {k: v for k, v in data.items() if k in field_names and k != "type"}
    return cls(**kwargs)


def _tool_name_from_id(tool_id: str) -> str:
    """Extract tool name from a Gemini CLI tool_id.

    tool_id format: 'mcp_ghidra-mcp_get_current_program_info_1776315320245_0'
    Returns: 'mcp_ghidra-mcp_get_current_program_info'
    """
    if not tool_id:
        return ""
    # Strip the trailing timestamp and sequence number (e.g., '_1776315320245_0')
    parts = tool_id.rsplit("_", 2)
    if len(parts) >= 3 and parts[-1].isdigit() and parts[-2].isdigit():
        return parts[0]
    return tool_id
