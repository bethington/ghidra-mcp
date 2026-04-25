import sys
from pathlib import Path


FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import fun_doc  # noqa: E402


def test_select_model_reads_dashboard_config():
    queue = {
        "config": {
            "provider_models": {
                "claude": {
                    "FULL": "sonnet-4",
                    "FIX": "sonnet-4",
                    "VERIFY": "haiku-4",
                }
            }
        }
    }
    assert fun_doc.get_configured_model("claude", "FULL", queue=queue) == "sonnet-4"


def test_default_queue_does_not_auto_handoff_or_auto_escalate():
    assert fun_doc.DEFAULT_QUEUE_CONFIG["complexity_handoff_provider"] is None
    assert fun_doc.DEFAULT_QUEUE_CONFIG["auto_escalate_provider"] is None
    assert fun_doc.DEFAULT_QUEUE_CONFIG["pre_escalate_retry"] is False
    # provider_models in the default config is now seeded from
    # DEFAULT_PROVIDER_MODELS so a fresh install / partial config gets
    # auto-populated dashboard inputs instead of blanks.
    assert fun_doc.DEFAULT_QUEUE_CONFIG["provider_models"] == fun_doc.DEFAULT_PROVIDER_MODELS


def test_select_model_raises_when_defaults_and_config_both_empty(monkeypatch):
    """The 'nothing configured anywhere' error path still fires when defaults
    are stripped (e.g. someone deletes a model in DEFAULT_PROVIDER_MODELS) and
    the persisted config has no model for that provider either."""
    monkeypatch.setattr(fun_doc, "DEFAULT_PROVIDER_MODELS", {})
    queue = {"config": {"provider_models": {}}}
    assert fun_doc.get_configured_model("claude", "FULL", queue=queue) is None

    original_loader = fun_doc.load_priority_queue
    try:
        fun_doc.load_priority_queue = lambda: queue
        try:
            fun_doc.select_model("FULL", provider="claude")
        except ValueError as exc:
            assert "No model configured" in str(exc)
        else:
            raise AssertionError(
                "select_model should fail when no dashboard model is configured"
            )
    finally:
        fun_doc.load_priority_queue = original_loader


# ---------- backfill regressions ----------


def test_normalize_backfills_missing_provider_from_defaults():
    """The codex regression: when a config has minimax/gemini/claude but no
    codex entry, normalize must fill codex from DEFAULT_PROVIDER_MODELS so the
    settings UI doesn't render blank inputs."""
    raw = {
        "minimax": {"FULL": "MiniMax-M2.7", "FIX": "MiniMax-M2.7", "VERIFY": "MiniMax-M2.7"},
        "gemini": {"FULL": "gemini-2.5-pro", "FIX": "gemini-2.5-flash", "VERIFY": "gemini-2.5-flash"},
        "claude": {"FULL": "claude-sonnet-4-6", "FIX": "claude-sonnet-4-6", "VERIFY": "claude-sonnet-4-6"},
    }
    normalized = fun_doc._normalize_provider_models(raw)
    assert "codex" in normalized
    assert normalized["codex"] == fun_doc.DEFAULT_PROVIDER_MODELS["codex"]


def test_normalize_backfills_missing_mode_within_provider():
    """If a user has FULL/FIX set but VERIFY missing, the missing mode comes
    from defaults instead of being absent."""
    raw = {"gemini": {"FULL": "gemini-2.5-pro", "FIX": "gemini-2.5-flash"}}
    normalized = fun_doc._normalize_provider_models(raw)
    assert normalized["gemini"]["FULL"] == "gemini-2.5-pro"
    assert normalized["gemini"]["FIX"] == "gemini-2.5-flash"
    assert normalized["gemini"]["VERIFY"] == fun_doc.DEFAULT_PROVIDER_MODELS["gemini"]["VERIFY"]


def test_normalize_user_value_wins_over_default():
    """Sanity: explicit user values override defaults rather than the other
    way around."""
    raw = {"claude": {"FULL": "claude-opus-custom"}}
    normalized = fun_doc._normalize_provider_models(raw)
    assert normalized["claude"]["FULL"] == "claude-opus-custom"
    # FIX/VERIFY still come from defaults
    assert normalized["claude"]["FIX"] == fun_doc.DEFAULT_PROVIDER_MODELS["claude"]["FIX"]


def test_normalize_empty_or_missing_returns_full_defaults():
    """A None / empty / non-dict input yields a deep copy of all defaults so
    a fresh queue file gets the full table."""
    for raw in (None, {}, "not a dict", 42):
        normalized = fun_doc._normalize_provider_models(raw)
        assert normalized == fun_doc.DEFAULT_PROVIDER_MODELS
        # Deep copy: mutating result must not affect the source.
        normalized["claude"]["FULL"] = "mutated"
        assert fun_doc.DEFAULT_PROVIDER_MODELS["claude"]["FULL"] != "mutated"


def test_normalize_max_turns_backfills_missing_providers():
    """provider_max_turns had the same flaw: if a user config set turns for
    minimax only, cfg.update would replace the entire dict and lose the
    other providers' defaults. Normalize must backfill them from
    DEFAULT_QUEUE_CONFIG."""
    raw = {"minimax": 40}
    normalized = fun_doc._normalize_provider_max_turns(raw)
    assert normalized["minimax"] == 40
    for provider in ("claude", "codex", "gemini"):
        assert normalized[provider] == fun_doc.DEFAULT_QUEUE_CONFIG["provider_max_turns"][provider]


def test_normalize_max_turns_coerces_strings():
    """Hand-edited priority_queue.json could have '40' as a string. Coerce."""
    raw = {"minimax": "40", "gemini": 30}
    normalized = fun_doc._normalize_provider_max_turns(raw)
    assert normalized["minimax"] == 40
    assert isinstance(normalized["minimax"], int)
    assert normalized["gemini"] == 30


def test_load_priority_queue_backfills_codex_when_persisted_config_missing_it(tmp_path, monkeypatch):
    """End-to-end: a priority_queue.json on disk that pre-dates the codex
    addition (only minimax/gemini/claude) loads with codex backfilled. This
    is the bug the user hit."""
    import json
    fake_qfile = tmp_path / "priority_queue.json"
    fake_qfile.write_text(json.dumps({
        "pinned": [],
        "config": {
            "provider_models": {
                "minimax": {"FULL": "MiniMax-M2.7", "FIX": "MiniMax-M2.7", "VERIFY": "MiniMax-M2.7"},
                "gemini": {"FULL": "gemini-2.5-pro", "FIX": "gemini-2.5-flash", "VERIFY": "gemini-2.5-flash"},
                "claude": {"FULL": "claude-sonnet-4-6", "FIX": "claude-sonnet-4-6", "VERIFY": "claude-sonnet-4-6"},
            },
            "provider_max_turns": {"minimax": 40},  # partial — others should backfill
        },
    }))
    monkeypatch.setattr(fun_doc, "PRIORITY_QUEUE_FILE", fake_qfile)
    queue = fun_doc.load_priority_queue()
    cfg = queue["config"]
    assert "codex" in cfg["provider_models"]
    assert cfg["provider_models"]["codex"] == fun_doc.DEFAULT_PROVIDER_MODELS["codex"]
    # max_turns: minimax kept at 40, others backfilled to default 25
    assert cfg["provider_max_turns"]["minimax"] == 40
    assert cfg["provider_max_turns"]["claude"] == 25
    assert cfg["provider_max_turns"]["codex"] == 25
    assert cfg["provider_max_turns"]["gemini"] == 25


def test_get_auto_escalation_provider_requires_explicit_opt_in():
    queue = {
        "config": {
            "auto_escalate_provider": "gemini",
            "pre_escalate_retry": True,
        }
    }
    assert fun_doc.get_auto_escalation_provider("minimax", queue=queue) == "gemini"


def test_get_auto_escalation_provider_stays_off_without_retry_flag():
    queue = {
        "config": {
            "auto_escalate_provider": "gemini",
            "pre_escalate_retry": False,
        }
    }
    assert fun_doc.get_auto_escalation_provider("minimax", queue=queue) is None
