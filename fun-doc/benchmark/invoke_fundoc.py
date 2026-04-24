"""Driver that invokes fun_doc.process_function in isolation.

Tells fun_doc to document exactly one function, captures every
tool_call event emitted during the run via the shared event bus,
and keeps the production state.json / priority_queue.json
completely untouched by redirecting fun_doc's module-level path
constants to a fresh temp directory per invocation.

Why not subprocess it? Because a subprocess would need the entire
fun_doc runtime set up fresh per invocation (provider caches, MCP
schema bootstrap, debug context) — slow and error-prone. In-process
monkey-patching of STATE_FILE / PRIORITY_QUEUE_FILE is the minimal
intervention that isolates state writes without disturbing the rest
of the runtime.

Caveats:
  * Event-bus subscribers added by this module are never removed
    (EventBus has no off() method). Per-invocation subscribers leak,
    but each leaked handler writes to its own local list that dies
    with the invocation. Over 50 function invocations that's 50 dead
    handlers on the bus — fine.
  * If the provider subprocess hangs past its hard timeout, the
    watchdog kills it; invoke_fundoc returns a BLOCKED result and
    the benchmark scores the captured state even if it's incomplete.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

BENCHMARK_DIR = Path(__file__).resolve().parent
FUN_DOC_DIR = BENCHMARK_DIR.parent

# Ensure fun_doc + event_bus are importable before anyone calls invoke().
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))


def invoke_fundoc(
    program: str,
    address: str,
    fn_name: str,
    provider: str = "minimax",
    model: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]], float]:
    """Run fun-doc on a single function. Returns (result, tool_calls, wall_seconds).

    Args:
        program:   Ghidra program path (e.g. "/benchmark/Benchmark.dll")
        address:   hex address string without 0x prefix (e.g. "10001010")
        fn_name:   current Ghidra function name (pre-doc baseline)
        provider:  provider key: minimax / gemini / claude / codex
        model:     optional specific model override; pulls from priority_queue config if None

    Result codes mirror process_function: "completed", "partial",
    "failed", "skipped", "needs_redo", "blocked", "stopped".
    """
    import fun_doc
    from event_bus import get_bus

    # Redirect state + queue writes to a fresh temp directory. The
    # originals on disk are untouched; benchmark runs cannot pollute
    # production. Restoration on exit is handled by the caller cleaning
    # up the temp dir (or just leaving it; it's tiny).
    tmp_dir = Path(tempfile.mkdtemp(prefix="fundoc_bench_"))
    original_state_file = fun_doc.STATE_FILE
    original_queue_file = fun_doc.PRIORITY_QUEUE_FILE
    fun_doc.STATE_FILE = tmp_dir / "state.json"
    fun_doc.PRIORITY_QUEUE_FILE = tmp_dir / "priority_queue.json"

    func_key = f"{program}::{address}"
    program_name = Path(program).name

    # Minimal seed state. process_function loads state and updates it
    # via update_function_state — we only need the one target entry.
    seed_state = {
        "functions": {
            func_key: {
                "program": program,
                "program_name": program_name,
                "address": address,
                "name": fn_name,
                "score": 0,
                "fixable": 0,
                "has_custom_name": False,
                "has_plate_comment": False,
                "is_leaf": True,
                "is_thunk": False,
                "is_external": False,
                "classification": "unknown",
                "deductions": [],
                "caller_count": 0,
            }
        },
        "sessions": [],
        "active_binary": program_name,
        "project_folder": str(Path(program).parent),
    }
    fun_doc.STATE_FILE.write_text(json.dumps(seed_state), encoding="utf-8")

    # Minimal queue. provider_models must include the target provider
    # or _require_model_name raises. Pull from the production queue if
    # available; fall back to sensible defaults if not.
    provider_models: dict[str, dict[str, str]] = {}
    try:
        if original_queue_file.is_file():
            orig = json.loads(original_queue_file.read_text(encoding="utf-8"))
            provider_models = (orig.get("config") or {}).get("provider_models") or {}
    except (OSError, json.JSONDecodeError):
        pass
    if provider not in provider_models:
        # Generic fallbacks so the benchmark can run without depending
        # on a production queue file. Override via explicit --model.
        provider_models.setdefault(
            "minimax", {"FULL": "MiniMax-M2", "FIX": "MiniMax-M2", "VERIFY": "MiniMax-M2"}
        )
        provider_models.setdefault(
            "gemini",
            {"FULL": "gemini-2.5-pro", "FIX": "gemini-2.5-flash", "VERIFY": "gemini-2.5-flash"},
        )
        provider_models.setdefault(
            "claude",
            {"FULL": "claude-opus-4-7", "FIX": "claude-haiku-4-5", "VERIFY": "claude-haiku-4-5"},
        )
        provider_models.setdefault(
            "codex",
            {"FULL": "gpt-5-codex", "FIX": "gpt-5-codex", "VERIFY": "gpt-5-codex"},
        )

    seed_queue = {
        "config": {
            "good_enough_score": 80,
            "provider_models": provider_models,
            "pre_refresh_on_start": False,  # skip pre-refresh; benchmark targets one fn
            "complexity_handoff_provider": None,
            "audit_provider": None,
        },
        "pinned": [func_key],
        "meta": {},
    }
    fun_doc.PRIORITY_QUEUE_FILE.write_text(json.dumps(seed_queue), encoding="utf-8")

    # Subscribe to bus events. These fire synchronously on whichever
    # thread emits, which includes the cross-process drain thread
    # (events from the provider subprocess arrive here).
    bus = get_bus()
    tool_calls: list[dict[str, Any]] = []

    def _on_tool_call(data):
        if not isinstance(data, dict):
            return
        tool_calls.append(
            {
                "tool": data.get("tool"),
                "args": data.get("args") or {},
                "status": data.get("status", "calling"),
                "phase": "call",
                "ts": time.time(),
            }
        )

    def _on_tool_result(data):
        if not isinstance(data, dict):
            return
        tool_calls.append(
            {
                "tool": data.get("tool"),
                "args": data.get("args") or {},
                "status": data.get("status", "ok"),
                "phase": "result",
                "ts": time.time(),
            }
        )

    bus.on("tool_call", _on_tool_call)
    bus.on("tool_result", _on_tool_result)

    # Drive process_function. state is a fresh in-memory dict built
    # from our seed; process_function's internal load_state calls
    # go to the temp STATE_FILE we set above.
    stop_flag = threading.Event()
    func = seed_state["functions"][func_key]

    t_start = time.monotonic()
    try:
        result = fun_doc.process_function(
            func_key,
            func,
            seed_state,
            model=model,
            provider=provider,
            stop_flag=stop_flag,
        )
    except Exception as e:
        result = f"error: {type(e).__name__}: {e}"
    finally:
        wall_seconds = time.monotonic() - t_start
        # Restore the original fun_doc state file paths so subsequent
        # invocations (e.g. the production dashboard if it's running)
        # point at the real files again.
        fun_doc.STATE_FILE = original_state_file
        fun_doc.PRIORITY_QUEUE_FILE = original_queue_file

    return result, tool_calls, wall_seconds
