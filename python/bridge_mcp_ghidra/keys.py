"""Session-scope settings for the bridge process (stdlib only — no bridge imports)."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import Any

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})

#: Flag overrides for this process, same precedence idea as settings.SESSION for tools.*.
SESSION: dict[str, str] = {}

# Defaults mirror SettingsRegistry.DEFAULT for bridge.* and auth.token.
BRIDGE: dict[str, object] = {
    "auth.token": "",
    "bridge.server_url": "",
    "bridge.max_concurrent_requests": 4,
    "bridge.log_level": "INFO",
    "bridge.lazy": "",
    "bridge.project": "",
    "bridge.expose": "full",
    "bridge.allowed_hosts": [],
    "bridge.inbound_token": "",
    "bridge.rebind_protection": True,
    "bridge.debugger_url": "",
    "bridge.debugger_tools": "",
}


def env_name(key: str) -> str:
    return "GHIDRA_MCP_" + key.upper().replace(".", "_")


RETIRED: dict[str, str] = {
    "GHIDRA_MCP_URL": env_name("bridge.server_url"),
    "GHIDRA_MCP_MAX_CONCURRENT_REQUESTS": env_name("bridge.max_concurrent_requests"),
    "GHIDRA_MCP_LOG_LEVEL": env_name("bridge.log_level"),
    "GHIDRA_MCP_LAZY": env_name("bridge.lazy"),
    "GHIDRA_MCP_PROJECT": env_name("bridge.project"),
    "GHIDRA_MCP_EXPOSE": env_name("bridge.expose"),
    "GHIDRA_MCP_ALLOWED_HOSTS": env_name("bridge.allowed_hosts"),
    "GHIDRA_MCP_INBOUND_TOKEN": env_name("bridge.inbound_token"),
    "GHIDRA_MCP_DISABLE_REBIND_PROTECTION": env_name("bridge.rebind_protection"),
    "GHIDRA_DEBUGGER_URL": env_name("bridge.debugger_url"),
    "GHIDRA_DEBUGGER_TOOLS": env_name("bridge.debugger_tools"),
}


def retired_variables(environ: Mapping[str, str]) -> str | None:
    found = sorted(name for name in RETIRED if name in environ)
    if not found:
        return None
    detail = ", ".join(f"{old} (now {RETIRED[old]})" for old in found)
    return (
        f"Retired environment variable(s) set: {detail}. "
        "Rename them; the bridge does not read the old names."
    )


def _parse_bool(raw: str, default: bool) -> bool:
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default


def _parse_int(raw: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(raw.strip()))
    except ValueError:
        return default


def value(key: str) -> Any:
    """The session value for ``key``: SESSION override, then environment, then default."""
    if key not in BRIDGE:
        raise KeyError(key)
    default = BRIDGE[key]
    raw = SESSION.get(key, os.environ.get(env_name(key)))
    if raw is None:
        return default
    if isinstance(default, bool):
        return _parse_bool(str(raw), default)
    if isinstance(default, int):
        return _parse_int(str(raw), default)
    if isinstance(default, list):
        return [t.strip() for t in str(raw).split(",") if t.strip()]
    return str(raw).strip()


def startup() -> None:
    """Refuse to run while retired variable names are still set.

    An ignored old name is not harmless: a renamed token or rebind switch would leave the
    bridge running looser than its operator configured.
    """
    message = retired_variables(os.environ)
    if message:
        print(message, file=sys.stderr)
        raise SystemExit(2)
