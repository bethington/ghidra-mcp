"""Offline tests for fun-doc/benchmark/ghidra_bridge.py.

Mocks the Ghidra HTTP endpoints so tests run without a live Ghidra.
Covers: scrape_function_state normalizes its input correctly,
find_function_by_name picks the exact-name match, restore_pristine
issues the expected restore calls, and unreachable-Ghidra produces
a clear GhidraBridgeError (not a cryptic ConnectionError).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "fun-doc" / "benchmark"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

import ghidra_bridge


def _mock_response(json_payload, ok=True, status_code=200, text=""):
    """Build a requests.Response-alike."""
    m = MagicMock()
    m.ok = ok
    m.status_code = status_code
    m.json.return_value = json_payload
    m.text = text or (str(json_payload)[:200])
    return m


def test_scrape_function_state_normalizes_signature_and_locals(monkeypatch):
    """scrape returns name/return/params/locals/plate in the shape
    the scorer expects, regardless of minor variations in Ghidra's
    response envelope."""

    def fake_get(url, params=None, timeout=None):
        path = url.split(ghidra_bridge.GHIDRA_URL, 1)[-1]
        if path.startswith("/get_function_signature"):
            return _mock_response(
                {
                    "name": "calc_crc16",
                    "return_type": "unsigned short",
                    "parameters": [
                        {"name": "data", "type": "const unsigned char *"},
                        {"name": "length", "type": "unsigned int"},
                    ],
                }
            )
        if path.startswith("/get_function_variables"):
            return _mock_response(
                {
                    "variables": [
                        {"name": "data", "type": "const unsigned char *", "is_parameter": True},
                        {"name": "length", "type": "unsigned int", "is_parameter": True},
                        {"name": "crc", "type": "unsigned short"},
                        {"name": "byte_index", "type": "unsigned int"},
                    ]
                }
            )
        if path.startswith("/get_plate_comment"):
            return _mock_response({"comment": "Computes CRC-16-CCITT..."})
        raise AssertionError(f"Unexpected GET {path}")

    monkeypatch.setattr(ghidra_bridge.requests, "get", fake_get)

    state = ghidra_bridge.scrape_function_state(
        program="/benchmark/Benchmark.dll", address="10001010"
    )

    assert state["name"] == "calc_crc16"
    assert state["return_type"] == "unsigned short"
    assert len(state["parameters"]) == 2
    assert state["parameters"][0]["name"] == "data"
    # Locals exclude the parameters
    assert {l["name"] for l in state["locals"]} == {"crc", "byte_index"}
    assert state["plate"] == "Computes CRC-16-CCITT..."


def test_find_function_by_name_picks_exact_match(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        return _mock_response(
            {
                "results": [
                    {"name": "calc_crc16_wrapper", "address": "0x10002000"},
                    {"name": "calc_crc16", "address": "0x10001010"},
                    {"name": "calc_crc16_cached", "address": "0x10003000"},
                ]
            }
        )

    monkeypatch.setattr(ghidra_bridge.requests, "get", fake_get)

    addr = ghidra_bridge.find_function_by_name(
        "/benchmark/Benchmark.dll", "calc_crc16"
    )
    assert addr == "10001010"


def test_find_function_by_name_returns_none_when_not_found(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        return _mock_response({"results": []})

    monkeypatch.setattr(ghidra_bridge.requests, "get", fake_get)
    assert (
        ghidra_bridge.find_function_by_name("/benchmark/Benchmark.dll", "nope") is None
    )


def test_restore_pristine_issues_expected_writes(monkeypatch):
    """restore_pristine must call rename + set_plate + set_prototype +
    set_local_variable_type. We capture the posts and assert the shape."""
    posts = []

    def fake_post(url, json=None, params=None, timeout=None):
        path = url.split(ghidra_bridge.GHIDRA_URL, 1)[-1]
        posts.append({"path": path, "json": json, "params": params})
        return _mock_response({"success": True})

    monkeypatch.setattr(ghidra_bridge.requests, "post", fake_post)

    snapshot = {
        "name": "FUN_10001010",
        "return_type": "undefined4",
        "parameters": [{"name": "param_1", "type": "undefined4"}],
        "locals": [{"name": "local_4", "type": "undefined4"}],
        "plate": "",
    }
    ghidra_bridge.restore_pristine(
        program="/benchmark/Benchmark.dll", address="10001010", snapshot=snapshot
    )

    paths = [p["path"].split("?")[0] for p in posts]
    # Must at minimum rename, set plate, set prototype, and set local type
    assert "/rename_function_by_address" in paths
    assert "/set_plate_comment" in paths
    assert "/set_function_prototype" in paths
    assert "/set_local_variable_type" in paths


def test_unreachable_ghidra_raises_bridge_error(monkeypatch):
    import requests as real_requests

    def raise_connection_error(*args, **kwargs):
        raise real_requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(ghidra_bridge.requests, "get", raise_connection_error)

    with pytest.raises(ghidra_bridge.GhidraBridgeError) as exc_info:
        ghidra_bridge.scrape_function_state(
            "/benchmark/Benchmark.dll", "10001010"
        )
    assert "unreachable" in str(exc_info.value).lower()


def test_http_error_surfaces_as_bridge_error(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        return _mock_response({"error": "bad request"}, ok=False, status_code=400, text="bad request")

    monkeypatch.setattr(ghidra_bridge.requests, "get", fake_get)

    with pytest.raises(ghidra_bridge.GhidraBridgeError) as exc_info:
        ghidra_bridge.scrape_function_state(
            "/benchmark/Benchmark.dll", "10001010"
        )
    assert "400" in str(exc_info.value)
