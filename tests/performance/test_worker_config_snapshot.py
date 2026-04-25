"""Regression tests for WorkerManager config snapshot freeze.

Locks in the design from the Q1-Q7 conversation on 2026-04-25:

  * Snapshot includes Tier 1 + Tier 2 fields (audit_provider/min_delta,
    complexity_handoff_provider/max, good_enough_score) plus a per-provider
    map for every provider this worker can actually invoke (primary +
    audit + escalation).
  * Snapshot is captured at worker start. Mid-run live config edits do NOT
    affect a worker that's already running.
  * Snapshot map omits providers this worker won't invoke — codex isn't
    snapshotted on a minimax-only worker.
  * select_model and process_function read from the snapshot when present;
    fall through to live config when None (CLI / legacy callers).
  * snapshotted scalar fields (good_enough_score, audit_min_delta) coerce
    to int so json.dumps doesn't get surprised by a string sneaking in
    from a queue file edited by hand.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc" / "fun_doc.py"


@pytest.fixture
def fun_doc_module(tmp_path, monkeypatch):
    """Load fun_doc.py with sibling-imports resolvable.

    Same pattern test_state_lock_reentrant.py uses — fun_doc imports
    `event_bus` etc. via top-level import, so we prepend fun-doc/ to
    sys.path before exec.
    """
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    fun_doc_dir = str(FUN_DOC.parent)
    monkeypatch.syspath_prepend(fun_doc_dir)

    spec = importlib.util.spec_from_file_location("fun_doc_under_test", FUN_DOC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fun_doc_under_test"] = mod
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pytest.skip("fun_doc.py raised SystemExit during import")
    yield mod
    sys.modules.pop("fun_doc_under_test", None)


def _queue_with(**cfg) -> dict:
    """Build a synthetic priority_queue dict with the given config overrides."""
    base = {
        "good_enough_score": 80,
        "audit_provider": None,
        "audit_min_delta": 5,
        "complexity_handoff_provider": None,
        "complexity_handoff_max": 0,
        "provider_max_turns": {
            "minimax": 25,
            "claude": 25,
            "gemini": 25,
            "codex": 25,
        },
        "provider_models": {
            "minimax": {"FULL": "MiniMax-M2", "FIX": "MiniMax-M2", "VERIFY": "MiniMax-M2"},
            "claude": {"FULL": "claude-opus-4-7", "FIX": "claude-haiku-4-5", "VERIFY": "claude-haiku-4-5"},
            "gemini": {"FULL": "gemini-2.5-pro", "FIX": "gemini-2.5-flash", "VERIFY": "gemini-2.5-flash"},
            "codex": {"FULL": "gpt-5-codex", "FIX": "gpt-5-codex", "VERIFY": "gpt-5-codex"},
        },
    }
    base.update(cfg)
    return {"config": base, "pinned": []}


# ---------- snapshot shape ----------


def test_snapshot_captures_tier1_and_tier2_fields(fun_doc_module):
    """The snapshot must include every field the design committed to
    freezing — top-level policy fields and the per-provider map.
    Missing any of these means downstream snapshot consumers fall through
    to live reads and the freeze is broken."""
    queue = _queue_with(
        good_enough_score=85,
        audit_provider="gemini",
        audit_min_delta=7,
        complexity_handoff_provider="claude",
        complexity_handoff_max=4,
    )
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")

    assert snap["good_enough_score"] == 85
    assert snap["audit_provider"] == "gemini"
    assert snap["audit_min_delta"] == 7
    assert snap["complexity_handoff_provider"] == "claude"
    assert snap["complexity_handoff_max"] == 4
    assert snap["primary_provider"] == "minimax"
    assert "providers" in snap
    assert isinstance(snap["providers"], dict)


def test_providers_map_includes_only_invokable_providers(fun_doc_module):
    """Snapshot.providers should contain primary + audit + handoff and
    nothing else. Including providers this worker can never invoke would
    bloat run records and confuse "what did this worker actually use" diffs."""
    queue = _queue_with(
        audit_provider="gemini",
        complexity_handoff_provider="claude",
    )
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    assert set(snap["providers"].keys()) == {"minimax", "gemini", "claude"}
    # Codex was never configured for this worker — must NOT appear
    assert "codex" not in snap["providers"]


def test_providers_map_omits_audit_and_handoff_when_unset(fun_doc_module):
    """If audit and escalation aren't configured, only the primary provider's
    slice is captured — nothing speculative."""
    snap = fun_doc_module.build_worker_config_snapshot(_queue_with(), "minimax")
    assert set(snap["providers"].keys()) == {"minimax"}


def test_provider_entry_holds_max_turns_and_models_slice(fun_doc_module):
    """Each provider entry under .providers must carry max_turns AND the
    FULL/FIX/VERIFY model slice. Missing either means process_function
    can't fully resolve "what should this provider do" from the snapshot."""
    queue = _queue_with(
        provider_max_turns={"minimax": 40, "claude": 25, "gemini": 25, "codex": 25}
    )
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    entry = snap["providers"]["minimax"]
    assert entry["max_turns"] == 40
    assert entry["models"] == {
        "FULL": "MiniMax-M2",
        "FIX": "MiniMax-M2",
        "VERIFY": "MiniMax-M2",
    }


def test_snapshot_handles_unsupported_audit_provider(fun_doc_module):
    """An audit_provider name that isn't in SUPPORTED_PROVIDERS (corrupt
    config, future provider not yet supported) must not crash snapshot
    construction — it just gets silently skipped from the providers map."""
    queue = _queue_with(audit_provider="not_a_real_provider")
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    # Top-level field still records what was configured, even if invalid
    assert snap["audit_provider"] == "not_a_real_provider"
    # But providers map only contains supported providers
    assert "not_a_real_provider" not in snap["providers"]
    assert "minimax" in snap["providers"]


def test_snapshot_coerces_numeric_fields_to_int(fun_doc_module):
    """A string '80' in good_enough_score (e.g. someone hand-edited
    priority_queue.json with quotes) should normalize to int(80) in the
    snapshot. JSON serialization stays clean and downstream comparisons
    don't accidentally do string-vs-int."""
    queue = _queue_with(good_enough_score="85", audit_min_delta="3")
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    assert snap["good_enough_score"] == 85
    assert isinstance(snap["good_enough_score"], int)
    assert snap["audit_min_delta"] == 3
    assert isinstance(snap["audit_min_delta"], int)


# ---------- freeze guarantees ----------


def test_snapshot_is_independent_of_source_queue(fun_doc_module):
    """The snapshot must be a deep-enough copy that mutating the source
    queue config after snapshot doesn't affect the captured values.
    Otherwise the snapshot is a live view, defeating the freeze."""
    queue = _queue_with(good_enough_score=80)
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")

    # Mutate the source queue's config — should NOT propagate
    queue["config"]["good_enough_score"] = 99
    queue["config"]["provider_max_turns"]["minimax"] = 999
    queue["config"]["provider_models"]["minimax"]["FULL"] = "different-model"

    assert snap["good_enough_score"] == 80
    assert snap["providers"]["minimax"]["max_turns"] == 25
    assert snap["providers"]["minimax"]["models"]["FULL"] == "MiniMax-M2"


# ---------- select_model fall-through ----------


def test_select_model_uses_snapshot_when_present(fun_doc_module):
    """select_model must prefer the snapshot's per-provider model slice
    over the live config. This is the entry point for process_function
    deciding what model to invoke; if it leaks to the live config, the
    worker isn't actually frozen."""
    queue = _queue_with()
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    # Mutate the snapshot to a sentinel value, then ensure select_model
    # returns it instead of consulting live config.
    snap["providers"]["minimax"]["models"]["FULL"] = "snapshot-only-model"
    selected = fun_doc_module.select_model("FULL", provider="minimax", config_snapshot=snap)
    assert selected == "snapshot-only-model"


def test_select_model_falls_through_when_no_snapshot(fun_doc_module, monkeypatch):
    """When called without a snapshot — CLI mode, legacy code paths, tests
    that don't pass one — select_model must honor the live config exactly
    as it did pre-snapshot. Backwards compat is mandatory."""
    # Patch get_configured_model to a known sentinel
    monkeypatch.setattr(
        fun_doc_module, "get_configured_model",
        lambda provider, mode: f"live-{provider}-{mode}"
    )
    selected = fun_doc_module.select_model("FULL", provider="minimax")
    assert selected == "live-minimax-FULL"


def test_select_model_falls_through_when_snapshot_lacks_provider(fun_doc_module, monkeypatch):
    """If a snapshot exists but the requested provider isn't in its providers
    map (e.g. an unconfigured handoff target fires), select_model should fall
    through to live config rather than guessing or erroring."""
    queue = _queue_with()
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    monkeypatch.setattr(
        fun_doc_module, "get_configured_model",
        lambda provider, mode: f"live-fallback-{provider}-{mode}"
    )
    # Ask for codex which isn't in the snapshot
    selected = fun_doc_module.select_model(
        "FULL", provider="codex", config_snapshot=snap
    )
    assert selected == "live-fallback-codex-FULL"


# ---------- mode banner conditional model ----------


def test_format_mode_banner_omits_model_when_matches_snapshot(fun_doc_module):
    """When the model passed to the banner equals the snapshot's expected
    model for this provider/mode, the banner omits the model token. This
    is the steady-state line — concise."""
    queue = _queue_with()
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    line = fun_doc_module._format_mode_banner(
        "FULL:recovery", "MiniMax-M2", "minimax", 50, snap, prompt="x" * 100
    )
    # Steady state: just mode label + score
    assert "MiniMax-M2" not in line
    assert "FULL/pass1 (types+structs)" in line
    assert "score: 50%" in line


def test_format_mode_banner_includes_model_on_deviation(fun_doc_module):
    """When the model deviates from the snapshot — handoff fired,
    model swap, recovery picked a different model — the banner shows
    the model so the deviation is visible."""
    queue = _queue_with()
    snap = fun_doc_module.build_worker_config_snapshot(queue, "minimax")
    # Pretend a handoff fired and gemini-2.5-pro is the new effective model
    line = fun_doc_module._format_mode_banner(
        "FULL", "gemini-2.5-pro", "gemini", 50, snap, prompt="x" * 100
    )
    assert "gemini-2.5-pro" in line


def test_format_mode_banner_always_shows_model_without_snapshot(fun_doc_module):
    """No snapshot means we can't detect deviation, so we fall back to
    always including the model. Pre-snapshot behavior preserved for CLI
    and legacy callers."""
    line = fun_doc_module._format_mode_banner(
        "FULL", "MiniMax-M2", "minimax", 50, None, prompt="x" * 100
    )
    assert "MiniMax-M2" in line
