"""Regression tests for fun_doc._sync_conf_rung -- the port_status -> CONF_ hook.

Background: the CONF_* tag ladder and fun-doc's `port_status` were two
disconnected state machines. `port_status` was written by the workers on every
transition; the CONF_ rung was written only by
`port_live_prove.record_proof()`, which the main worker path never calls. The
observable damage: D2Client.dll carried 0 CONF_ tags across 5,739 functions
while SQL held 35 static-harness passes for it, and CONF_DRAFT/CONF_VECTORS had
no writer anywhere in the codebase.

These tests pin the hook's contract:
  * it fires on a port_status transition and writes the mapped rung
  * it is PROMOTE-ONLY -- an earned rung is never lowered
  * it clears the other rungs (mutual exclusivity) before adding
  * CONF_BLOCKED carries its reason into the Conf property map
  * it NEVER raises -- a tag write must not fail a worker
  * it trips a circuit breaker rather than paying an HTTP timeout per
    transition when Ghidra is unreachable
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

fun_doc = pytest.importorskip("fun_doc")
import conf_ladder  # noqa: E402


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


@pytest.fixture
def calls(monkeypatch):
    """Capture the hook's HTTP traffic. `current` sets the tag already on the
    function; `add_result` lets a test force a failed write."""
    rec = {"get": [], "post": [], "current": [], "add_result": {"status": "success"}}

    def fake_get(url, params=None, timeout=None):
        rec["get"].append((url, params))
        return _Resp({"tags": [{"name": t} for t in rec["current"]]})

    def fake_post(url, json=None, params=None, timeout=None):
        rec["post"].append((url.rsplit("/", 1)[-1], json, params))
        if url.endswith("/add_function_tag"):
            return _Resp(rec["add_result"])
        return _Resp({"success": True})

    monkeypatch.setattr(fun_doc.requests, "get", fake_get)
    monkeypatch.setattr(fun_doc.requests, "post", fake_post)
    monkeypatch.setattr(fun_doc, "_CONF_SYNC_FAILURES", 0, raising=False)
    monkeypatch.setenv("FUNDOC_CONF_TAGS", "1")
    return rec


KEY = "/Mods/PD2-S12/D2Client.dll::6fabb150"


def _posted(rec, endpoint):
    return [c for c in rec["post"] if c[0] == endpoint]


# --- it fires, and targets the right program -------------------------------

def test_static_harness_pass_writes_conf_vectors(calls):
    fun_doc._sync_conf_rung(KEY, {"port_status": "proven_pending_review"})
    add = _posted(calls, "add_function_tag")
    assert len(add) == 1
    assert add[0][1]["tags"] == "CONF_VECTORS"
    assert add[0][1]["function"] == "0x6fabb150"


def test_program_is_a_query_param_not_a_body_field(calls):
    """@Param(value="program") defaults to ParamSource.QUERY. A body-sourced
    program is ignored and the write lands on whatever program is ACTIVE --
    the same failure class as the wrong-binary default fixed 2026-07-27."""
    fun_doc._sync_conf_rung(KEY, {"port_status": "proven_pending_review"})
    for _ep, body, params in calls["post"]:
        assert params == {"program": "D2Client.dll"}
        assert "program" not in body


def test_blocked_status_records_its_reason(calls):
    fun_doc._sync_conf_rung(KEY, {"port_status": "stateful_skip"})
    add = _posted(calls, "add_function_tag")
    assert add[0][1]["tags"] == conf_ladder.CONF_BLOCKED
    prop = _posted(calls, "set_property")
    assert len(prop) == 1
    assert prop[0][1]["map"] == conf_ladder.CONF_PROPERTY_MAP
    assert '"reason":"stateful"' in prop[0][1]["value"]


def test_rungs_are_mutually_exclusive(calls):
    """A live transition really can move between rungs, unlike the one-shot
    backfill where every source rung was `none`."""
    calls["current"] = ["CONF_VECTORS"]
    fun_doc._sync_conf_rung(KEY, {"port_status": "proven_live_pending_review"})
    removed = _posted(calls, "remove_function_tag")
    assert len(removed) == 1
    assert "CONF_VECTORS" in removed[0][1]["tags"]
    assert "CONF_LIVE" not in removed[0][1]["tags"].split(",")
    assert _posted(calls, "add_function_tag")[0][1]["tags"] == "CONF_LIVE"


# --- it does not fire when it shouldn't ------------------------------------

def test_promote_only_never_demotes(calls):
    calls["current"] = ["CONF_BATTLETESTED"]
    fun_doc._sync_conf_rung(KEY, {"port_status": "shadow_leaf_pending"})
    assert _posted(calls, "add_function_tag") == []
    assert _posted(calls, "remove_function_tag") == []


def test_blocked_never_overwrites_a_proof(calls):
    """Stale SQL saying stateful_skip must not erase a live proof."""
    calls["current"] = ["CONF_LIVE"]
    fun_doc._sync_conf_rung(KEY, {"port_status": "stateful_skip"})
    assert _posted(calls, "add_function_tag") == []


def test_transient_failure_changes_nothing(calls):
    fun_doc._sync_conf_rung(KEY, {"port_status": "live_prove_failed"})
    assert calls["post"] == []


def test_no_port_status_is_a_noop(calls):
    fun_doc._sync_conf_rung(KEY, {"score": 91})
    assert calls["get"] == [] and calls["post"] == []


def test_env_kill_switch(calls, monkeypatch):
    monkeypatch.setenv("FUNDOC_CONF_TAGS", "0")
    fun_doc._sync_conf_rung(KEY, {"port_status": "proven_pending_review"})
    assert calls["get"] == [] and calls["post"] == []


# --- it never takes a worker down ------------------------------------------

def test_never_raises_when_ghidra_is_unreachable(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(fun_doc.requests, "get", boom)
    monkeypatch.setattr(fun_doc, "_CONF_SYNC_FAILURES", 0, raising=False)
    monkeypatch.setenv("FUNDOC_CONF_TAGS", "1")
    fun_doc._sync_conf_rung(KEY, {"port_status": "proven_pending_review"})  # must not raise


def test_circuit_breaker_stops_retrying(monkeypatch):
    """Without this, every transition pays a full HTTP timeout while Ghidra is
    down -- which would stall the worker loop, not just lose a tag."""
    hits = {"n": 0}

    def boom(*a, **k):
        hits["n"] += 1
        raise OSError("connection refused")

    monkeypatch.setattr(fun_doc.requests, "get", boom)
    monkeypatch.setattr(fun_doc, "_CONF_SYNC_FAILURES", 0, raising=False)
    monkeypatch.setenv("FUNDOC_CONF_TAGS", "1")
    for _ in range(fun_doc._CONF_SYNC_MAX_FAILURES + 25):
        fun_doc._sync_conf_rung(KEY, {"port_status": "proven_pending_review"})
    assert hits["n"] == fun_doc._CONF_SYNC_MAX_FAILURES


def test_failed_write_is_reported_not_swallowed(calls, capsys):
    calls["add_result"] = {"error": "no function at address"}
    fun_doc._sync_conf_rung(KEY, {"port_status": "proven_pending_review"})
    assert "write-back WARN" in capsys.readouterr().out
