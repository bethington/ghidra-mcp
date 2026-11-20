"""Shared bridge boolean parsing (config.parse_bool)."""

from __future__ import annotations

import logging

import pytest

from bridge_mcp_ghidra.config import parse_bool


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        (" on ", True),
        ("0", False),
        ("false", False),
        ("NO", False),
        ("off", False),
    ],
)
def test_parse_bool_known_spellings(raw, expected):
    assert parse_bool(raw, default=True, on_unknown="default") is expected
    assert parse_bool(raw, default=False, on_unknown="error") is expected


def test_parse_bool_empty_is_unset_returns_default():
    assert parse_bool("", default=True, on_unknown="default") is True
    assert parse_bool("   ", default=False, on_unknown="error") is False
    assert parse_bool("", default=True, on_unknown="warn") is True


def test_parse_bool_unknown_default():
    assert parse_bool("maybe", default=True, on_unknown="default") is True
    assert parse_bool("maybe", default=False, on_unknown="default") is False


def test_parse_bool_unknown_error():
    with pytest.raises(ValueError, match="maybe"):
        parse_bool("maybe", default=True, on_unknown="error")


def test_parse_bool_unknown_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="bridge_mcp_ghidra.config"):
        assert parse_bool("maybe", default=True, on_unknown="warn") is True
    assert "maybe" in caplog.text
