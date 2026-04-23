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
    assert fun_doc.DEFAULT_QUEUE_CONFIG["provider_models"] == {}


def test_select_model_raises_without_dashboard_config():
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
