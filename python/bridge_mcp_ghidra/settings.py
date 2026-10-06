"""Bridge side of the settings registry: the session scope and the ``tools.*`` keys.

The server resolves a key through default < server < project < local (``/get_settings``).
This module layers the session on top for the keys the bridge consumes: this bridge
process's own ``GHIDRA_MCP_<KEY>`` environment and its command-line flags. It also keeps
``tools.last_loaded`` current, so a later session can load the same groups again when
``tools.restore_loaded`` is on.
"""

from __future__ import annotations

import json
import logging
import os

from . import state, transport
from .config import CORE_GROUPS

logger = logging.getLogger(__name__)

#: Used when the server predates /get_settings; the same defaults as the registry.
DEFAULTS: dict[str, object] = {
    "tools.autoload": sorted(CORE_GROUPS),
    "tools.restore_loaded": True,
    "tools.last_loaded": [],
    "tools.require_program": False,
}
_LIST_DELTA = {"tools.autoload"}
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}

#: Session values from flags, which outrank this process's environment.
SESSION: dict[str, str] = {}

_last_recorded: list[str] | None = None


def env_name(key: str) -> str:
    return "GHIDRA_MCP_" + key.upper().replace(".", "_")


def session_raw(key: str) -> str | None:
    return SESSION.get(key, os.environ.get(env_name(key)))


def apply_delta(below: list[str], raw: str) -> list[str]:
    """``+x`` adds, ``-x`` removes, and any bare name replaces the list below first."""
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    bare = [t for t in tokens if not t.startswith(("+", "-"))]
    out = list(below) if tokens and not bare else bare
    for t in tokens:
        name = t[1:].strip()
        if t.startswith("+") and name and name not in out:
            out.append(name)
        elif t.startswith("-") and name in out:
            out.remove(name)
    return out


def _parse(key: str, raw: str) -> object:
    if isinstance(DEFAULTS[key], bool):
        v = raw.strip().lower()
        if v in _TRUE or v in _FALSE:
            return v in _TRUE
        raise ValueError(f"{key} is a boolean; {raw!r} is not one of true/false/1/0/yes/no/on/off")
    return [t.strip() for t in raw.split(",") if t.strip()]


def resolve(key: str, server: dict[str, object]) -> object:
    """The server's value for ``key`` with this session's value applied on top."""
    value = server.get(key, DEFAULTS[key])
    raw = session_raw(key)
    if raw is None:
        return value
    try:
        return apply_delta(list(value), raw) if key in _LIST_DELTA else _parse(key, raw)
    except ValueError as e:
        logger.warning("Ignoring session value for %s: %s", key, e)
        return value


def fetch(connection: state.ConnectionSnapshot | None = None) -> dict[str, object]:
    """The server's resolved ``tools.*`` values; empty when it has no /get_settings."""
    try:
        text, status = transport.do_request(
            "GET", "/get_settings", params={"prefix": "tools"}, timeout=10, connection=connection
        )
        if status != 200:
            return {}
        return {row["key"]: row["value"] for row in json.loads(text).get("settings", []) if "value" in row}
    except Exception as e:
        logger.warning("Could not read settings from the server, using defaults: %s", e)
        return {}


def _known(key: str, groups: list[str], valid: set[str]) -> set[str]:
    """The groups that exist, warning about the rest with the valid list."""
    unknown = sorted(set(groups) - valid)
    if unknown:
        logger.warning(
            "%s names unknown tool group(s) %s; valid groups: %s",
            key,
            ", ".join(unknown),
            ", ".join(sorted(valid)),
        )
    return set(groups) & valid


def connect_groups(schema: list[dict], connection: state.ConnectionSnapshot | None = None) -> set[str] | None:
    """Apply the connected project's tool settings; return the groups to register.

    Sets ``state._default_groups`` (tools.autoload) and ``state._require_selectors``
    (tools.require_program). Returns None when every group should load (not lazy);
    otherwise tools.autoload, plus tools.last_loaded when tools.restore_loaded is on.
    """
    global _last_recorded
    server = fetch(connection)
    valid = {t.get("category", "unknown") for t in schema}
    autoload = list(resolve("tools.autoload", server))
    _known("tools.autoload", autoload, valid)
    state._default_groups = set(autoload)
    state._require_selectors = bool(resolve("tools.require_program", server))
    last = list(resolve("tools.last_loaded", server))
    _last_recorded = sorted(last)
    if not state._lazy_mode:
        return None
    groups = set(autoload)
    if resolve("tools.restore_loaded", server):
        groups |= _known("tools.last_loaded", last, valid)
    return groups


def record_loaded_groups() -> None:
    """Store the groups loaded beyond tools.autoload as this machine's tools.last_loaded."""
    global _last_recorded
    extra = sorted(state._loaded_groups - state._default_groups)
    if extra == _last_recorded:
        return
    try:
        text, status = transport.do_request(
            "POST",
            "/set_setting",
            json_data={"key": "tools.last_loaded", "value": ",".join(extra), "scope": "local"},
            timeout=10,
        )
        body = json.loads(text) if status == 200 else {}
        if "error" in body or status != 200:
            logger.warning("Could not record tools.last_loaded: %s", body.get("error") or f"HTTP {status}")
            return
        _last_recorded = extra
    except Exception as e:
        logger.warning("Could not record tools.last_loaded: %s", e)
