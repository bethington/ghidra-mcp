"""Parity between Java SettingsRegistry bridge keys and keys.BRIDGE."""

from __future__ import annotations

import os
import re
from pathlib import Path

from bridge_mcp_ghidra.keys import BRIDGE, RETIRED, env_name, retired_variables, value

GUIDE = Path(__file__).resolve().parents[2] / "docs/prompts/TOOL_USAGE_GUIDE.md"
TABLE_ROW = re.compile(
    r"^\| `(?P<key>[^`]+)` \| \w+ \| (?P<type>\w+) \| (?P<default>[^|]+) \|"
)


def _expected_default(type_name: str, cell: str) -> object:
    cell = cell.strip()
    if cell == "hidden":
        return ""
    if cell == "none":
        return [] if type_name == "list" else ""
    raw = cell.strip("`")
    if type_name == "bool":
        return raw.lower() == "true"
    if type_name == "int":
        return int(raw)
    if type_name == "list":
        return [t.strip() for t in raw.split(",") if t.strip()]
    return raw


def _guide_bridge_rows() -> dict[str, tuple[str, object]]:
    text = GUIDE.read_text(encoding="utf-8")
    start = text.index("<!-- settings-keys:start -->")
    end = text.index("<!-- settings-keys:end -->")
    rows: dict[str, tuple[str, object]] = {}
    for line in text[start:end].splitlines():
        m = TABLE_ROW.match(line.strip())
        if not m:
            continue
        key = m.group("key")
        if not (key.startswith("bridge.") or key == "auth.token"):
            continue
        type_name = m.group("type")
        rows[key] = (type_name, _expected_default(type_name, m.group("default")))
    return rows


def test_bridge_keys_match_registry_table():
    guide = _guide_bridge_rows()
    assert set(guide) == set(BRIDGE)
    for key, (type_name, expected) in guide.items():
        actual = BRIDGE[key]
        if type_name == "bool":
            assert isinstance(actual, bool)
        elif type_name == "int":
            assert isinstance(actual, int)
        elif type_name == "list":
            assert isinstance(actual, list)
        else:
            assert isinstance(actual, str)
        assert actual == expected


def test_value_parsing_and_fallbacks(monkeypatch):
    monkeypatch.setenv(env_name("bridge.max_concurrent_requests"), "not-a-number")
    assert value("bridge.max_concurrent_requests") == 4
    monkeypatch.setenv(env_name("bridge.max_concurrent_requests"), "0")
    assert value("bridge.max_concurrent_requests") == 1

    monkeypatch.setenv(env_name("bridge.rebind_protection"), "off")
    assert value("bridge.rebind_protection") is False
    monkeypatch.setenv(env_name("bridge.rebind_protection"), "yes")
    assert value("bridge.rebind_protection") is True

    monkeypatch.setenv(env_name("bridge.allowed_hosts"), "a.example,b.example")
    assert value("bridge.allowed_hosts") == ["a.example", "b.example"]


def test_retired_variables_names_new_keys(monkeypatch):
    for old, new in RETIRED.items():
        monkeypatch.setenv(old, "1")
        msg = retired_variables(os.environ)
        assert msg is not None
        assert old in msg
        assert new in msg
        monkeypatch.delenv(old, raising=False)


def test_rebind_protection_false_disables_protection(monkeypatch):
    monkeypatch.setenv(env_name("bridge.rebind_protection"), "false")
    assert value("bridge.rebind_protection") is False
    monkeypatch.setenv(env_name("bridge.rebind_protection"), "0")
    assert value("bridge.rebind_protection") is False
    monkeypatch.setenv(env_name("bridge.rebind_protection"), "true")
    assert value("bridge.rebind_protection") is True
