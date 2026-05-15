"""gemini-cli-sdk — Python SDK for the Google Gemini CLI."""

from .client import GeminiCli, GeminiOptions, SyncResult
from .discovery import find_gemini_binary
from .events import (
    ErrorEvent,
    GeminiEvent,
    InitEvent,
    MessageEvent,
    ResultEvent,
    ToolResultEvent,
    ToolUseEvent,
    parse_event,
)

__all__ = [
    "GeminiCli",
    "GeminiOptions",
    "SyncResult",
    "find_gemini_binary",
    "GeminiEvent",
    "InitEvent",
    "MessageEvent",
    "ToolUseEvent",
    "ToolResultEvent",
    "ErrorEvent",
    "ResultEvent",
    "parse_event",
]
