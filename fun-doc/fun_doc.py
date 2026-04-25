"""
fun-doc: Intelligent function documentation engine for Ghidra MCP.

Scores every function in a Ghidra project for "documentation completeness",
ranks them by ROI (fixable points × xref impact), and drives an LLM to fix
the best candidates. State is persisted in state.json; a live web dashboard
lets you start/stop workers, queue specific functions, and watch progress.

Primary interface: the web dashboard at http://127.0.0.1:5000 (auto-started
on launch). CLI modes below are kept for scripting and one-shot operations.

Architecture:
    * state.json              — per-function score/classification cache
    * priority_queue.json     — user-queued functions + config + refresh meta
    * logs/runs.jsonl         — JSONL audit trail of every worker run
    * logs/debug/{date}/      — per-function tool-call traces (when debug_mode on)
    * select_candidates()     — single source of truth for worker pick order
    * update_function_state() — atomic per-function RMW (no lost-update races)
    * Providers: dashboard-configurable provider routing with per-run override
                 support via --provider.

Usage:
    python fun_doc.py                         # Dashboard + idle (primary entry point)
    python fun_doc.py --web                   # Standalone blocking dashboard
    python fun_doc.py --auto                  # Auto-mode: document next best function
    python fun_doc.py --auto --count 10       # Document 10 functions
    python fun_doc.py --auto --provider claude    # Override provider per-run
    python fun_doc.py -s                      # Select mode: current function + neighbors
    python fun_doc.py -s --depth 2            # Select mode with depth 2
    python fun_doc.py -m                      # Manual mode: copy prompts to clipboard
    python fun_doc.py --status                # Terminal progress snapshot
    python fun_doc.py --scan                  # Incremental scan (only re-score changed)
    python fun_doc.py --scan --refresh        # Full rescan (re-score every function)
    python fun_doc.py --scan --refresh --binary D2Common.dll  # One-binary rescan
    python fun_doc.py --dry-run --auto        # Show what would run without invoking

Dashboard config (edit via header controls or priority_queue.json):
    good_enough_score           — functions at/above this are considered done (80)
    require_scored              — surface unscored entries to cold-start lane (false)
    complexity_handoff_provider — "claude" | "codex" | "gemini" | null. Swap provider mid-flight
                                  when minimax's complexity gate fires.
    complexity_handoff_max      — cap handoffs per worker session (default 5,
                                  0 = unlimited). After the cap is hit, massive
                                  functions stay with the primary provider.
    auto_escalate_provider      — optional provider for one immediate retry when
                                  a worker finishes below good_enough_score.
    pre_escalate_retry          — enable/disable that immediate retry.
    debug_mode                  — write per-tool-call JSONL to logs/debug/
    pre_refresh_on_start        — batch-rescore top 20 before worker loop begins
    provider_max_turns          — dict of per-provider tool-call turn limits, e.g.
                                  {"claude": 30, "minimax": 20, "codex": 15, "gemini": 25}

Recovery-pass one-shot (automatic, no config):
    Functions that finish a complexity-forced recovery pass ("COMPLEXITY: massive
    — forcing recovery-only mode") get flagged with recovery_pass_done and are
    excluded from future selector picks. This prevents the "re-queue forever
    below good_enough" loop that burns tokens for marginal improvement on
    legitimately-massive functions. Clear the flag by:
      * Pinning the function (pinned funcs bypass the flag)
      * `--scan --refresh` (full rescan rebuilds entries from scratch)
      * Dashboard "Refresh Top N" button (clears the flag on refreshed funcs)

Offline analysis:
    python analyze_debug.py                   # Today's tool-call traces
    python analyze_debug.py 2026-04-13        # Specific date
    python analyze_debug.py --summary-only    # Cross-function stats
    python analyze_debug.py --tool create_struct  # Filter to one tool
"""

import argparse
import contextvars
import copy
import json
import multiprocessing
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections import defaultdict
from datetime import datetime, date
from pathlib import Path

# Force UTF-8 on stdout/stderr so printing Unicode from LLM responses
# (smart quotes, em-dashes, non-ASCII identifiers) doesn't crash worker
# threads with 'charmap' codec errors on Windows legacy consoles. A crashed
# print inside a worker thread silently kills the worker — runs stop
# appearing in runs.jsonl and dashboard_active_workers drifts out of sync.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

from event_bus import emit as bus_emit, get_bus, get_worker_id

# Thread safety for state.json access across concurrent workers.
# RLock (reentrant) is required because the common read-modify-write
# pattern holds the lock while calling load_state(), which also takes
# it internally for its own mid-write retry protection. With a plain
# Lock that self-acquire deadlocks the holding thread forever and
# every other worker piles up behind it — confirmed via py-spy when
# four workers wedged in refresh_candidate_scores on 2026-04-24.
_state_lock = threading.RLock()

# Thread safety for priority_queue.json access across concurrent workers
_queue_lock = threading.RLock()

# Per-thread tracker for the last Ghidra HTTP call's error kind. Used by
# fetch_function_data to detect when a decompile-heavy endpoint hit a read
# timeout (the hallmark of a pathological function) so the caller can mark
# the function with a one-strike `decompile_timeout` flag instead of burning
# three consecutive_fails cycles on it. Reset at the start of every
# ghidra_get/ghidra_post call; only meaningful immediately after a call.
_ghidra_call_state = threading.local()


def _reset_ghidra_call_state():
    _ghidra_call_state.last_was_timeout = False
    _ghidra_call_state.last_was_offline = False


def _mark_ghidra_call_timeout():
    _ghidra_call_state.last_was_timeout = True


def _mark_ghidra_call_offline():
    _ghidra_call_state.last_was_offline = True


def ghidra_last_call_timed_out():
    """True if the most recent ghidra_get/ghidra_post call on this thread
    raised a requests read timeout. Caller must inspect immediately — the
    flag resets on the next call."""
    return getattr(_ghidra_call_state, "last_was_timeout", False)


def ghidra_last_call_offline():
    """True if the most recent ghidra_get/ghidra_post call on this thread
    raised a connection error (server not running / actively refused).
    Caller must inspect immediately — the flag resets on the next call."""
    return getattr(_ghidra_call_state, "last_was_offline", False)


# Force unbuffered output so redirected stdout shows progress
(
    sys.stdout.reconfigure(line_buffering=True)
    if hasattr(sys.stdout, "reconfigure")
    else None
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MODULE_DIR = SCRIPT_DIR / "prompts"
STATE_FILE = SCRIPT_DIR / "state.json"
LOG_DIR = SCRIPT_DIR / "logs"
LOG_FILE = LOG_DIR / "runs.jsonl"
GHIDRA_HTTP_LOG_FILE = LOG_DIR / "ghidra_http.jsonl"
_http_log_lock = threading.Lock()

# Load .env from repo root (API keys, server URLs, etc.)
try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass

GHIDRA_URL = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")

# ---------------------------------------------------------------------------
# AI Provider Configuration
# ---------------------------------------------------------------------------
# Model names are intentionally not hard-coded here. The web dashboard owns
# provider/mode model selection and persists it in priority_queue.json.

AI_PROVIDER = "minimax"  # Primary provider when no per-run override is given.
SUPPORTED_PROVIDERS = ("claude", "codex", "minimax", "gemini")
SUPPORTED_MODEL_MODES = ("FULL", "FIX", "VERIFY")


def _read_single_key():
    """Read a single keypress without requiring Enter. Works on Windows and Unix."""
    try:
        import msvcrt

        key = msvcrt.getch()
        return key.decode("utf-8", errors="replace").lower()
    except ImportError:
        pass
    # Unix fallback
    import tty
    import termios

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        key = sys.stdin.read(1)
        return key.lower()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


PREFIXES_FILE = MODULE_DIR / "prefixes.json"


def _load_prefixes_block():
    """Load known module prefixes and format as a prompt section."""
    if not PREFIXES_FILE.exists():
        return None
    try:
        with open(PREFIXES_FILE, "r") as f:
            data = json.load(f)
        prefixes = data.get("prefixes", [])
        if not prefixes:
            return None
        lines = ["## Known Module Prefixes", ""]
        lines.append(
            "Prefer these prefixes when the function belongs to a known module. New prefixes are allowed if none fit."
        )
        lines.append("")
        lines.append("| Prefix | Source File | Description |")
        lines.append("|--------|-----------|-------------|")
        for p in prefixes:
            lines.append(
                f"| `{p['prefix']}` | {p.get('source', '')} | {p.get('description', '')} |"
            )
        lines.append("")
        return "\n".join(lines)
    except Exception:
        return None


# Category -> fix module mapping
CATEGORY_TO_MODULE = {
    "unresolved_struct_accesses": "fix-struct-access.md",
    "undefined_variables": "fix-undefined-types.md",
    "hungarian_notation_violations": "fix-hungarian.md",
    "undocumented_magic_numbers": "fix-magic-numbers.md",
    "unrenamed_globals": "fix-globals.md",
    "unrenamed_labels": "fix-labels.md",
    "missing_plate_comment": "fix-plate-comment.md",
    "plate_comment_stub": "fix-plate-comment.md",
    "plate_comment_incomplete": "fix-plate-comment.md",
    "plate_comment_minor": "fix-plate-comment.md",
    "missing_prototype": "fix-prototype.md",
    "return_type_unresolved": "fix-prototype.md",
    "address_suffix_name": "fix-prototype.md",
    "undocumented_ordinals": "fix-ordinals.md",
}

ALL_FIX_MODULES = sorted(set(CATEGORY_TO_MODULE.values()))

# ---------------------------------------------------------------------------
# Ghidra HTTP helpers
# ---------------------------------------------------------------------------

import requests


def _short_jsonish(value, limit=1000):
    try:
        text = json.dumps(value, default=str)
    except Exception:
        text = str(value)
    return text[:limit] + ("..." if len(text) > limit else "")


def _log_ghidra_http_event(entry):
    """Persist detailed Ghidra HTTP diagnostics without cluttering stdout."""
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with _http_log_lock:
            with open(GHIDRA_HTTP_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def _parse_response(r):
    """Parse response, trying JSON first then falling back to text."""
    text = r.text
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def ghidra_get(path, params=None, timeout=60):
    """GET request to Ghidra HTTP server."""
    _reset_ghidra_call_state()
    started = time.perf_counter()
    try:
        r = requests.get(f"{GHIDRA_URL}{path}", params=params, timeout=timeout)
        r.raise_for_status()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "GET",
                "path": path,
                "params": params or {},
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "status_code": r.status_code,
                "ok": True,
                "response_preview": r.text[:500],
            }
        )
        return _parse_response(r)
    except requests.exceptions.ReadTimeout as e:
        _mark_ghidra_call_timeout()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "GET",
                "path": path,
                "params": params or {},
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "ok": False,
                "error_type": type(e).__name__,
                "error": str(e),
            }
        )
        print(
            f"  WARNING: Ghidra GET {path} failed: read timeout after {timeout}s",
            file=sys.stderr,
        )
        return None
    except requests.exceptions.ConnectionError as e:
        _mark_ghidra_call_offline()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "GET",
                "path": path,
                "params": params or {},
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "ok": False,
                "error_type": type(e).__name__,
                "error": str(e),
            }
        )
        print(
            f"  WARNING: Ghidra GET {path} failed: server not reachable at {GHIDRA_URL}",
            file=sys.stderr,
        )
        return None
    except requests.RequestException as e:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response = getattr(e, "response", None)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "GET",
                "path": path,
                "params": params or {},
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "status_code": getattr(response, "status_code", None),
                "ok": False,
                "error_type": type(e).__name__,
                "error": str(e),
                "response_preview": (getattr(response, "text", "") or "")[:500],
            }
        )
        print(f"  WARNING: Ghidra GET {path} failed: {e}", file=sys.stderr)
        return None


def ghidra_post(path, data=None, params=None, timeout=60):
    """POST request to Ghidra HTTP server."""
    _reset_ghidra_call_state()
    started = time.perf_counter()
    try:
        r = requests.post(
            f"{GHIDRA_URL}{path}", json=data, params=params, timeout=timeout
        )
        r.raise_for_status()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "POST",
                "path": path,
                "params": params or {},
                "data_preview": _short_jsonish(data),
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "status_code": r.status_code,
                "ok": True,
                "response_preview": r.text[:500],
            }
        )
        return _parse_response(r)
    except requests.exceptions.ReadTimeout as e:
        _mark_ghidra_call_timeout()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "POST",
                "path": path,
                "params": params or {},
                "data_preview": _short_jsonish(data),
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "ok": False,
                "error_type": type(e).__name__,
                "error": str(e),
            }
        )
        print(
            f"  WARNING: Ghidra POST {path} failed: read timeout after {timeout}s",
            file=sys.stderr,
        )
        return None
    except requests.exceptions.ConnectionError as e:
        _mark_ghidra_call_offline()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "POST",
                "path": path,
                "params": params or {},
                "data_preview": _short_jsonish(data),
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "ok": False,
                "error_type": type(e).__name__,
                "error": str(e),
            }
        )
        print(
            f"  WARNING: Ghidra POST {path} failed: server not reachable at {GHIDRA_URL}",
            file=sys.stderr,
        )
        return None
    except requests.RequestException as e:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response = getattr(e, "response", None)
        _log_ghidra_http_event(
            {
                "ts": datetime.now().isoformat(),
                "method": "POST",
                "path": path,
                "params": params or {},
                "data_preview": _short_jsonish(data),
                "timeout": timeout,
                "elapsed_ms": elapsed_ms,
                "status_code": getattr(response, "status_code", None),
                "ok": False,
                "error_type": type(e).__name__,
                "error": str(e),
                "response_preview": (getattr(response, "text", "") or "")[:500],
            }
        )
        print(f"  WARNING: Ghidra POST {path} failed: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Ghidra health check and auto-launch
# ---------------------------------------------------------------------------

# Tracks whether we've already attempted a Ghidra launch in this process
# so we only try once per worker run rather than every function.
_ghidra_launch_attempted = False
_ghidra_launch_lock = threading.Lock()


def check_ghidra_online(timeout=3):
    """Return True if the Ghidra HTTP server is reachable."""
    try:
        r = requests.get(f"{GHIDRA_URL}/mcp/schema", timeout=timeout)
        return r.status_code < 500
    except requests.RequestException:
        return False


def try_launch_ghidra():
    """Attempt to start Ghidra using GHIDRA_INSTALL_DIR env var or common paths.

    Returns True if a launch was attempted (not necessarily successful yet).
    Returns False if no Ghidra installation could be found.
    """
    global _ghidra_launch_attempted
    with _ghidra_launch_lock:
        if _ghidra_launch_attempted:
            return False
        _ghidra_launch_attempted = True

    candidates = []
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    if env_dir:
        candidates.append(Path(env_dir))
    # Common install locations
    candidates += [
        Path("F:/ghidra_12.0.4_PUBLIC"),
        Path("C:/ghidra_12.0.4_PUBLIC"),
        Path("C:/Program Files/ghidra"),
        Path(os.path.expanduser("~/ghidra")),
    ]

    for ghidra_dir in candidates:
        bat = ghidra_dir / "ghidraRun.bat"
        if bat.exists():
            print(
                f"  GHIDRA OFFLINE — attempting to launch Ghidra from {ghidra_dir} ...",
                flush=True,
            )
            try:
                subprocess.Popen(
                    [str(bat)],
                    cwd=str(ghidra_dir),
                    creationflags=(
                        subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
                    ),
                )
                return True
            except Exception as exc:
                print(f"  WARNING: Failed to launch Ghidra: {exc}", file=sys.stderr)
                return False

    print(
        "  GHIDRA OFFLINE — no Ghidra installation found. "
        "Set GHIDRA_INSTALL_DIR env var to enable auto-launch.",
        file=sys.stderr,
    )
    return False


def wait_for_ghidra(timeout_secs=120, poll_interval=5):
    """Block until Ghidra comes online or timeout expires.

    Returns True if Ghidra became reachable within the timeout.
    """
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        if check_ghidra_online():
            return True
        remaining = int(deadline - time.time())
        print(f"  Waiting for Ghidra to start... ({remaining}s remaining)", flush=True)
        time.sleep(poll_interval)
    return False


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


def _default_state():
    return {
        "project_folder": "/Mods/PD2-S12",
        "last_scan": None,
        "functions": {},
        "sessions": [],
        "current_session": None,
    }


def load_state():
    """Load or create fresh state. Retries on partial-read JSONDecodeError so
    concurrent callers (CLI, web server worker threads, external scripts) don't
    explode when another writer is mid-flush. Falls back to state.json.bak if
    the main file is unrecoverably corrupt."""
    if not STATE_FILE.exists():
        return _default_state()

    # Retry up to 5 times with a short sleep — covers the common case of
    # another worker mid-write (now atomic via os.replace, so this is rare).
    last_err = None
    for attempt in range(5):
        try:
            with _state_lock:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except (json.JSONDecodeError, ValueError) as e:
            last_err = e
            if attempt < 4:
                time.sleep(0.2)

    # Main file is unrecoverably bad — try the backup
    bak = STATE_FILE.with_suffix(".json.bak")
    if bak.exists():
        try:
            with open(bak, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(
                f"WARNING: state.json was corrupt ({last_err}); loaded from {bak.name}",
                flush=True,
            )
            return data
        except (json.JSONDecodeError, ValueError):
            pass

    # Both files are corrupt. Don't silently start fresh — raise so the operator
    # can run the recovery script. Starting fresh would silently lose all scoring.
    raise RuntimeError(
        f"state.json is corrupt and backup is missing or corrupt: {last_err}. "
        f"Run the recovery logic in fun_doc.py to truncate at the last clean "
        f"function entry, or delete state.json to start fresh."
    )


def _atomic_write_state(state):
    """Write the given state dict to STATE_FILE atomically. Caller must hold
    `_state_lock`. Used by save_state() and update_function_state()."""
    tmp_path = STATE_FILE.with_suffix(".json.tmp")
    bak_path = STATE_FILE.with_suffix(".json.bak")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, default=str)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, AttributeError):
            pass  # fsync not supported on this platform or FD

    # Rotate current → .bak, then atomically replace with new
    if STATE_FILE.exists():
        try:
            os.replace(STATE_FILE, bak_path)
        except OSError:
            pass  # best-effort backup rotation

    # On Windows, os.replace can transiently fail with PermissionError (WinError 5)
    # when another thread has state.json open for reading. Retry with backoff so
    # a transient lock doesn't propagate up and kill the worker.
    last_err = None
    for attempt in range(5):
        try:
            os.replace(tmp_path, STATE_FILE)
            return
        except PermissionError as e:
            last_err = e
            if attempt < 4:
                time.sleep(0.05 * (2**attempt))  # 50ms, 100ms, 200ms, 400ms
    print(
        f"  WARNING: could not replace state.json after 5 attempts: {last_err}. "
        f"State is preserved in {tmp_path} and will be written on next save.",
        file=sys.stderr,
        flush=True,
    )


def save_state(state):
    """Persist state to disk atomically.

    Writes to state.json.tmp, fsyncs it, renames atomically over state.json,
    and keeps state.json.bak as a rolling one-generation backup. This prevents
    the 'truncated mid-write' corruption that happens when a process is killed
    or crashes during a direct-write save.

    For per-function updates during worker iteration, prefer
    update_function_state() — it re-reads from disk before writing, avoiding
    the lost-update race where one worker's save clobbers another's.
    """
    with _state_lock:
        _atomic_write_state(state)
    bus_emit("state_changed")


_ACCUMULATOR_FIELDS = (
    # Per-function accumulator fields maintained by _update_function_cost_history.
    # Callers that do not explicitly set these should not wipe them — otherwise
    # the cost-tracking history gets clobbered by every post-run state sync that
    # passes its locally-loaded func (which predates the mid-run history append).
    "attempts",
    "total_input_tokens",
    "total_output_tokens",
    "net_delta",
    "cost_per_point",
    "is_thrashing",
    "_thrashing_alerted",
)


def update_function_state(func_key, updated_func):
    """Atomically update a single function's state entry.

    Read-modify-write within `_state_lock`: re-reads state.json from disk to
    pick up any concurrent updates, overwrites only `state["functions"][func_key]`,
    writes atomically. Prevents the lost-update race where two workers each
    load state, modify different functions, and their full-state saves clobber
    each other's unrelated changes.

    Preserves accumulator fields (attempts, cost_per_point, etc.) from the
    on-disk version when the caller does not explicitly set them. This lets
    `_update_function_cost_history` append to history mid-run without being
    overwritten by the process_function post-run state save that uses the
    locally-cached func dict loaded before the history append.

    Use this in per-function code paths (skip handlers, completion handlers,
    _sync_func_state calls) instead of save_state(state).
    """
    with _state_lock:
        # Re-read latest state from disk. Retry on mid-write partial reads.
        latest = None
        for _ in range(5):
            try:
                if STATE_FILE.exists():
                    with open(STATE_FILE, "r", encoding="utf-8") as f:
                        latest = json.load(f)
                    break
            except (json.JSONDecodeError, ValueError):
                time.sleep(0.1)
        if latest is None:
            # Nothing readable — fall back to a fresh state scaffold
            latest = _default_state()

        funcs = latest.setdefault("functions", {})
        merged = dict(updated_func)
        # Preserve accumulator fields from on-disk version when the caller
        # didn't explicitly provide them. This is the key invariant that
        # prevents the post-run state save from wiping mid-run history.
        on_disk = funcs.get(func_key)
        if isinstance(on_disk, dict):
            for field in _ACCUMULATOR_FIELDS:
                if field not in updated_func and field in on_disk:
                    merged[field] = on_disk[field]
        funcs[func_key] = merged

        _atomic_write_state(latest)
    bus_emit("state_changed")


def start_session(state):
    """Start a new documentation session."""
    session = {
        "started": datetime.now().isoformat(),
        "date": date.today().isoformat(),
        "completed": 0,
        "skipped": 0,
        "failed": 0,
        "partial": 0,
        "functions": [],
    }
    state["current_session"] = session
    return session


def end_session(state):
    """Finalize and archive current session."""
    session = state.get("current_session")
    if session:
        session["ended"] = datetime.now().isoformat()
        state.setdefault("sessions", []).append(session)
        state["current_session"] = None


_SESSION_UPDATE_MISSING = object()


def finalize_worker_session(session, *, active_binary=_SESSION_UPDATE_MISSING):
    """Atomically merge a worker's finished session into the latest on-disk state.

    Read-modify-write under `_state_lock`: re-reads state.json, sets
    `session["ended"]`, appends to `state["sessions"]`, clears
    `state["current_session"]` when it still points at this session, and
    optionally updates `state["active_binary"]`. Writes atomically.

    Replaces the `end_session(state); save_state(state)` pattern in worker
    loops. A full-state save there would write the functions dict that was
    loaded at iteration start, clobbering per-function updates made
    concurrently by other workers through update_function_state().

    `session` is the worker's local session dict (as returned by
    start_session). If None or falsy, only active_binary handling runs.

    `active_binary` uses a sentinel: pass a string to set, pass None to
    clear (pop the key), or omit to leave whatever is on disk alone.
    """
    with _state_lock:
        # Re-read latest state from disk using the same backup/raise behavior
        # as normal loads, so a transient worker finish cannot overwrite a
        # recoverable corrupt state file with a fresh default state.
        latest = load_state()

        if session:
            session["ended"] = datetime.now().isoformat()
            latest.setdefault("sessions", []).append(session)
            # Only clear current_session if it still references this worker's
            # session (match on the "started" timestamp, which is unique per
            # start_session call). Another worker's concurrent session should
            # stay untouched.
            cur = latest.get("current_session")
            if isinstance(cur, dict) and cur.get("started") == session.get("started"):
                latest["current_session"] = None

        if active_binary is not _SESSION_UPDATE_MISSING:
            if active_binary is None:
                latest.pop("active_binary", None)
            else:
                latest["active_binary"] = active_binary

        _atomic_write_state(latest)
    bus_emit("state_changed")


# ---------------------------------------------------------------------------
# Ghidra data fetching
# ---------------------------------------------------------------------------


def _fetch_programs(project_folder):
    """Get list of programs in a project folder via Ghidra project files API.

    Uses /list_project_files to discover all binaries in the folder,
    then returns them as a list of {name, path} dicts. Programs don't
    need to be open — FrontEndProgramProvider opens them on demand.
    """
    resp = ghidra_get("/list_project_files", params={"folder": project_folder})
    if not resp:
        print("ERROR: Cannot list project files. Is Ghidra running?", file=sys.stderr)
        return None

    if isinstance(resp, str):
        try:
            resp = json.loads(resp)
        except (json.JSONDecodeError, TypeError):
            print(
                f"ERROR: Unexpected response from list_project_files: {str(resp)[:200]}",
                file=sys.stderr,
            )
            return None

    files = resp.get("files", [])
    programs = [
        {"name": f["name"], "path": f["path"]}
        for f in files
        if isinstance(f, dict) and f.get("content_type") == "Program"
    ]

    if not programs:
        print(f"ERROR: No programs found in {project_folder}", file=sys.stderr)
        return None

    return programs


def _fetch_function_list(prog_path):
    """Fetch enhanced function list for a program. Returns list or None.

    Pages through /list_functions_enhanced in 10k chunks. The endpoint's
    default limit is 10,000 — without paging we silently lose everything
    past the first 10k, which is how libcrypto-1_1.dll and glide3x.dll
    ended up with exactly 10,000 functions in state.
    """
    PAGE_SIZE = 10000
    all_funcs = []
    offset = 0
    while True:
        funcs_resp = ghidra_get(
            "/list_functions_enhanced",
            params={"program": prog_path, "offset": offset, "limit": PAGE_SIZE},
            timeout=60,
        )
        if not funcs_resp:
            return None if not all_funcs else all_funcs
        if isinstance(funcs_resp, str):
            try:
                funcs_resp = json.loads(funcs_resp)
            except (json.JSONDecodeError, TypeError):
                return None if not all_funcs else all_funcs
        page = funcs_resp.get("functions") or []
        if not page:
            break
        all_funcs.extend(page)
        if len(page) < PAGE_SIZE:
            break  # Short page = end of data
        offset += PAGE_SIZE
        # Safety cap: don't spin forever on a hypothetical Ghidra bug
        if offset > 1_000_000:
            print(
                f"    WARNING: pagination exceeded 1M functions for {prog_path}; stopping",
                flush=True,
            )
            break
    return all_funcs


def _score_single(addr_hex, prog_path=None):
    """Score a single function via analyze_function_completeness. Returns score_info dict or None."""
    params = {"function_address": addr_hex}
    if prog_path:
        params["program"] = prog_path
    result = ghidra_get("/analyze_function_completeness", params=params, timeout=30)
    if not result or not isinstance(result, dict) or "error" in result:
        return None
    eff = result.get("effective_score", result.get("completeness_score", 0))
    classification = result.get("classification", "unknown")
    return {
        "score": int(eff) if eff is not None else 0,
        "fixable": float(result.get("fixable_deductions", 0)),
        "has_custom_name": result.get("has_custom_name", False),
        "has_plate_comment": result.get("has_plate_comment", False),
        "is_leaf": classification == "leaf",
        "classification": classification,
        "deductions": result.get("deduction_breakdown", []),
    }


def _parse_batch_results(addresses, offset, resp):
    """Parse a `/batch_analyze_completeness` response into (score_map, count).

    Returns (dict of address -> score_info, number of valid entries extracted).
    The offset is the starting index into `addresses` for this batch.
    """
    out = {}
    if not resp or not isinstance(resp, dict) or "results" not in resp:
        return out, 0
    results = resp["results"]
    for j, result in enumerate(results):
        idx = offset + j
        if idx >= len(addresses):
            break
        if not isinstance(result, dict) or "error" in result:
            continue
        addr = addresses[idx].replace("0x", "")
        eff = result.get("effective_score", result.get("completeness_score", 0))
        classification = result.get("classification", "unknown")
        out[addr] = {
            "score": int(eff) if eff is not None else 0,
            "fixable": float(result.get("fixable_deductions", 0)),
            "has_custom_name": result.get("has_custom_name", False),
            "has_plate_comment": result.get("has_plate_comment", False),
            "is_leaf": classification == "leaf",
            "classification": classification,
            "deductions": result.get("deduction_breakdown", []),
        }
    return out, len(out)


def _batch_score(
    addresses,
    prog_path=None,
    fallback=True,
    first_batch_timeout=300,
    progress_callback=None,
):
    """Score addresses via batch endpoint with honest progress and retry pass.

    Counts are tracked two ways:
      - loop_progress: how far through the address list we've iterated
      - scored: how many addresses actually got a valid result in score_map
    Old behavior claimed "Scored N/M" based on loop position even when batches
    failed. New behavior reports both.

    After the first pass, any batches that failed (ghidra_post returned None)
    are retried with a smaller batch size — slow Ghidra can usually handle
    10-function batches even when 25-function batches time out.

    Parameters:
        fallback: When True (default), fall back to per-address scoring if the
            batch endpoint returns errors. When False, return whatever the
            batch call produced and skip individual retries.
        first_batch_timeout: Override the first-batch HTTP timeout (default 300s).
            Pre-refresh paths pass 60 to fail fast.
        progress_callback: Optional callable invoked after each batch with
            (scored, total, failed_batches). Used by scan_functions to emit
            scan_progress events to the dashboard.
    """
    score_map = {}
    # BATCH_SIZE is sized to fit under PER_BATCH_TIMEOUT even when every
    # function in the batch is at the Java-side 90s per-chunk cap.
    # 6 × 90s = 540s fully-pathological worst case, under the 600s client
    # budget with 60s headroom for HTTP overhead. With the new no-retry
    # decompile path (caps decompile at 60s, no 360s escalation), this
    # headroom is realistic, not a guess.
    BATCH_SIZE = 6
    PER_BATCH_TIMEOUT = 600

    params = {}
    if prog_path:
        params["program"] = prog_path

    failed_ranges = []  # list of (start, end) slices of `addresses` that failed
    batch_works = None  # None = untested, True/False after first batch
    first_failure_logged = False

    def _notify(scored_count, failed_count):
        print(
            f"    Scored {scored_count}/{len(addresses)}"
            + (f" ({failed_count} failed batches so far)" if failed_count else ""),
            flush=True,
        )
        if progress_callback:
            try:
                progress_callback(scored_count, len(addresses), failed_count)
            except Exception:
                pass

    for i in range(0, len(addresses), BATCH_SIZE):
        batch = addresses[i : i + BATCH_SIZE]
        batch_end = i + len(batch)

        if batch_works is not False:
            timeout = first_batch_timeout if i == 0 else PER_BATCH_TIMEOUT
            resp = ghidra_post(
                "/batch_analyze_completeness",
                data={"addresses": batch},
                params=params,
                timeout=timeout,
            )

            # Detect a server-side timeout: Java returns {"error": "chunk_timeout: ..."}
            # when a single chunk's decompile runs past its 30s EDT deadline.
            # Treat this as a failed batch, NOT a reason to fall back to
            # individual scoring (individual calls would also hang on the same
            # pathological function). Just record the range and move on —
            # the retry pass at the end will try with smaller chunks, and the
            # final summary reports what's missing.
            server_side_error = (
                resp
                and isinstance(resp, dict)
                and "error" in resp
                and "results" not in resp
            )
            if server_side_error:
                err_msg = str(resp.get("error", ""))[:120]
                print(
                    f"    Ghidra chunk timeout: {err_msg}",
                    flush=True,
                )
                failed_ranges.append((i, batch_end))
                _notify(len(score_map), len(failed_ranges))
                continue

            if resp and isinstance(resp, dict) and "results" in resp:
                results = resp["results"]
                # Detect "batch endpoint unsupported for this program":
                # triggered when ALL entries in the first batch are errors
                # (meaning the endpoint itself is broken for this program).
                # A single error entry mid-batch just means one pathological
                # function — we should NOT fall back to individual scoring,
                # because individual calls would hit the same wall.
                all_errors = results and all(
                    isinstance(r, dict) and "error" in r for r in results
                )
                if all_errors and batch_works is None:
                    batch_works = False
                    msg = (
                        (
                            "Batch scoring unavailable, falling back to "
                            "individual scoring..."
                        )
                        if fallback
                        else ("Batch scoring unavailable, fallback disabled — skipping")
                    )
                    print(f"    {msg}", flush=True)
                else:
                    batch_works = True
                    parsed, parsed_count = _parse_batch_results(addresses, i, resp)
                    score_map.update(parsed)
                    # If the batch had mixed success/error (some functions
                    # timed out on the Ghidra side), record the failure but
                    # keep the successful results.
                    failed_in_batch = len(results) - parsed_count
                    if failed_in_batch > 0:
                        failed_ranges.append((i, batch_end))
                        err_samples = [
                            r.get("error", "")[:80]
                            for r in results
                            if isinstance(r, dict) and "error" in r
                        ][:3]
                        print(
                            f"    Partial batch: {parsed_count}/{len(results)} scored, "
                            f"{failed_in_batch} per-function errors: {err_samples}",
                            flush=True,
                        )
                    _notify(len(score_map), len(failed_ranges))
                    continue  # success path done (possibly partial)
            elif resp is None:
                # Timeout or HTTP error. Record the failure and keep going.
                if batch_works is None and not first_failure_logged:
                    # First batch failed — decide whether to fall back or skip
                    batch_works = False
                    msg = (
                        (
                            "Batch scoring timed out, falling back to "
                            "individual scoring..."
                        )
                        if fallback
                        else ("Batch scoring timed out, fallback disabled — skipping")
                    )
                    print(f"    {msg}", flush=True)
                    first_failure_logged = True
                else:
                    failed_ranges.append((i, batch_end))
                    _notify(len(score_map), len(failed_ranges))
                    continue

        if batch_works is False:
            if not fallback:
                break
            # Individual fallback for this batch
            for addr_hex in batch:
                addr = addr_hex.replace("0x", "")
                info = _score_single(addr_hex, prog_path)
                if info:
                    score_map[addr] = info
            _notify(len(score_map), len(failed_ranges))
            continue

    # Retry pass: any batches that failed during the main loop get a second
    # shot with a smaller batch size to isolate the pathological functions.
    # RETRY_SIZE must fit in PER_BATCH_TIMEOUT even when every function in a
    # retry chunk hits the Java-side 90s per-chunk cap. 3 × 90 = 270s, well
    # under the 600s client budget. Smaller than the main BATCH_SIZE=6 so
    # more retries get a chance to isolate good functions between bad ones.
    # The old RETRY_SIZE=10 was a bug: 10 × 90 = 900s > 600s client timeout,
    # which caused the retry pass to fail entirely on any cluster that
    # was already pathological enough to time out at 6-function batches.
    if failed_ranges and fallback and batch_works is not False:
        retry_addrs = []
        for start, end in failed_ranges:
            retry_addrs.extend(addresses[start:end])
        print(
            f"    Retrying {len(failed_ranges)} failed batches "
            f"({len(retry_addrs)} functions) with smaller batch size...",
            flush=True,
        )
        RETRY_SIZE = 3
        retry_recovered = 0
        still_failed = 0
        for j in range(0, len(retry_addrs), RETRY_SIZE):
            chunk = retry_addrs[j : j + RETRY_SIZE]
            resp = ghidra_post(
                "/batch_analyze_completeness",
                data={"addresses": chunk},
                params=params,
                timeout=PER_BATCH_TIMEOUT,
            )
            if resp and isinstance(resp, dict) and "results" in resp:
                # Build a temporary index for this chunk so _parse_batch_results
                # can align offsets correctly
                parsed, count = _parse_batch_results(chunk, 0, resp)
                score_map.update(parsed)
                retry_recovered += count
            else:
                still_failed += len(chunk)
            if (j // RETRY_SIZE) % 5 == 0 or j + RETRY_SIZE >= len(retry_addrs):
                print(
                    f"    Retry progress: {min(j + RETRY_SIZE, len(retry_addrs))}"
                    f"/{len(retry_addrs)} (recovered {retry_recovered}, still failing {still_failed})",
                    flush=True,
                )
        print(
            f"    Retry complete: recovered {retry_recovered}, still failing {still_failed}",
            flush=True,
        )

    # Final honest summary line
    final_scored = len(score_map)
    missing = len(addresses) - final_scored
    if missing > 0:
        print(
            f"    Batch score done: {final_scored}/{len(addresses)} scored, "
            f"{missing} missing (may be stale in state)",
            flush=True,
        )

    return score_map


def scan_functions(state, project_folder, refresh=False, binary_filter=None):
    """Scan functions from Ghidra with incremental or full scoring.

    Default (refresh=False): Only re-score functions whose name changed since
    last scan or that have no cached score. New functions are scored, removed
    functions are pruned.

    Full (refresh=True): Re-score every function (original behavior).
    """
    existing = state.get("functions", {})
    is_incremental = bool(existing) and not refresh

    scan_mode = "incremental" if is_incremental else "full"
    bus_emit("scan_started", {"mode": scan_mode, "folder": project_folder})
    if is_incremental:
        print(
            f"Incremental scan in {project_folder} (use --refresh for full rescan)...",
            flush=True,
        )
    else:
        print(f"Full scan in {project_folder}...", flush=True)

    print(f"  Fetching project file list from Ghidra...", flush=True)
    target_programs = _fetch_programs(project_folder)
    if target_programs is None:
        print(f"  ERROR: Could not list project files. Is Ghidra running?", flush=True)
        return False
    print(f"  Found {len(target_programs)} program(s) in {project_folder}", flush=True)

    # Filter to specific binary if requested
    if binary_filter:
        target_programs = [p for p in target_programs if p["name"] == binary_filter]
        if not target_programs:
            print(
                f"ERROR: Binary '{binary_filter}' not found in {project_folder}",
                file=sys.stderr,
            )
            return False

    # Build name lookup from existing state for incremental comparison
    cached_names = {}
    if is_incremental:
        for key, func in existing.items():
            cached_names[key] = func.get("name", "")

    all_functions = {}
    total_rescored = 0
    total_kept = 0
    total_new = 0

    for prog_idx, prog in enumerate(target_programs):
        prog_path = prog["path"]
        prog_name = prog["name"]
        bus_emit(
            "scan_progress",
            {
                "program": prog_name,
                "index": prog_idx,
                "total": len(target_programs),
                "phase": "starting",
                "scored": 0,
                "program_total": 0,
            },
        )
        print(
            f"\n  [{prog_idx + 1}/{len(target_programs)}] {prog_name} ({prog_path})",
            flush=True,
        )
        print(f"    listing functions...", flush=True)

        func_list = _fetch_function_list(prog_path)
        if func_list is None:
            print(f"    WARNING: Could not list functions for {prog_path}", flush=True)
            continue

        non_thunk = [
            f for f in func_list if not f.get("isThunk") and not f.get("isExternal")
        ]
        print(
            f"    {len(func_list)} functions ({len(non_thunk)} non-thunk)", flush=True
        )

        # Determine which addresses need scoring
        if is_incremental:
            needs_scoring = []
            for f in non_thunk:
                key = f"{prog_path}::{f['address']}"
                cached = existing.get(key)
                if cached is None:
                    # New function — needs scoring
                    needs_scoring.append(f)
                elif cached.get("name", "") != f["name"]:
                    # Name changed — needs re-scoring
                    needs_scoring.append(f)
                elif cached.get("score", 0) == 0 and not cached.get("deductions"):
                    # Never properly scored (added to state but scoring was skipped)
                    needs_scoring.append(f)
                # else: name unchanged and has valid score, keep cached

            needs_scoring_addrs = [f"0x{f['address']}" for f in needs_scoring]
            print(
                f"    {len(needs_scoring)} changed/new, {len(non_thunk) - len(needs_scoring)} cached",
                flush=True,
            )
        else:
            needs_scoring_addrs = [f"0x{f['address']}" for f in non_thunk]

        # Score only what's needed
        score_map = {}
        if needs_scoring_addrs:
            print(f"    Scoring {len(needs_scoring_addrs)} functions...", flush=True)
            # Bridge per-batch progress to the bus so the dashboard banner
            # can show a live progress bar within each binary's scan. The
            # callback receives (scored_count, total, failed_batch_count);
            # failed_batch_count is surfaced on the bus so the UI can warn
            # when Ghidra is struggling.
            _p_idx = prog_idx
            _p_name = prog_name
            _p_total_progs = len(target_programs)

            def _batch_progress_cb(
                scored_count,
                batch_total,
                failed_count,
                _idx=_p_idx,
                _name=_p_name,
                _tp=_p_total_progs,
            ):
                bus_emit(
                    "scan_progress",
                    {
                        "program": _name,
                        "index": _idx,
                        "total": _tp,
                        "phase": "scoring",
                        "scored": scored_count,
                        "program_total": batch_total,
                        "failed_batches": failed_count,
                    },
                )

            score_map = _batch_score(
                needs_scoring_addrs, prog_path, progress_callback=_batch_progress_cb
            )

        # Build function entries
        for func in func_list:
            addr = func["address"]
            name = func["name"]
            is_thunk = func.get("isThunk", False)
            is_external = func.get("isExternal", False)
            func_key = f"{prog_path}::{addr}"

            # Check if we have a fresh score or should use cached
            scored_this_run = False
            if addr in score_map:
                score_info = score_map[addr]
                scored_this_run = True
                if func_key in cached_names:
                    total_rescored += 1
                else:
                    total_new += 1
            elif is_incremental and func_key in existing:
                # Use cached data, just update name in case it changed
                cached = existing[func_key]
                all_functions[func_key] = cached
                all_functions[func_key]["name"] = name  # Reflect current name
                total_kept += 1
                continue
            else:
                score_info = {}

            # Stamp last_processed when we just got a fresh score from scoring.
            # Previously this carried forward whatever `existing.last_processed`
            # was, which left functions stuck as "unscored" on the dashboard
            # even after --scan --refresh successfully scored them, because
            # their old entry had last_processed=None and we never overwrote it.
            if scored_this_run:
                last_processed_val = datetime.now().isoformat()
                last_result_val = "scanned"
            else:
                last_processed_val = existing.get(func_key, {}).get("last_processed")
                last_result_val = existing.get(func_key, {}).get("last_result")

            all_functions[func_key] = {
                "program": prog_path,
                "program_name": prog_name,
                "address": addr,
                "name": name,
                "score": score_info.get("score", 0),
                "fixable": score_info.get("fixable", 0),
                "has_custom_name": score_info.get("has_custom_name", False),
                "has_plate_comment": score_info.get("has_plate_comment", False),
                "deductions": score_info.get("deductions", []),
                "caller_count": 0,
                "is_leaf": score_info.get("is_leaf", False),
                "classification": score_info.get("classification", "unknown"),
                "is_thunk": is_thunk,
                "is_external": is_external,
                "last_processed": last_processed_val,
                "last_result": last_result_val,
            }

    if binary_filter:
        # Merge: update only the scanned binary's functions, keep everything else
        for key, func in all_functions.items():
            state["functions"][key] = func
        # Remove functions from this binary that no longer exist
        stale_keys = [
            k
            for k, f in state["functions"].items()
            if f.get("program_name") == binary_filter and k not in all_functions
        ]
        for k in stale_keys:
            del state["functions"][k]
    else:
        state["functions"] = all_functions

    # Populate call-graph data (callee lists) for scanned programs.
    # Uses the bulk /get_full_call_graph endpoint — one HTTP call per program.
    # Enables the bottom-up readiness-based prioritization in select_candidates().
    programs_to_graph = (
        [p for p in target_programs if p["name"] == binary_filter]
        if binary_filter
        else target_programs
    )
    for prog in programs_to_graph:
        print(f"  Fetching call graph for {prog['name']}...", flush=True)
        populate_call_graph(state, prog["path"])

    state["last_scan"] = datetime.now().isoformat()
    state["project_folder"] = project_folder
    save_state(state)

    # Report stats for what was scanned
    if binary_filter:
        # When scanning one binary, report stats for that binary + total state
        binary_total = len(all_functions)
        binary_done = sum(1 for f in all_functions.values() if f["score"] >= 90)
        state_total = len(state["functions"])
        state_done = sum(1 for f in state["functions"].values() if f["score"] >= 90)
        print(
            f"\nScan complete: {binary_filter} — {binary_total} functions, {binary_done} done (>= 90%)"
        )
        print(f"  {total_rescored} scored, {total_kept} thunk/external")
        print(
            f"  State total: {state_total} functions across all binaries, {state_done} done"
        )
        bus_emit(
            "scan_complete",
            {
                "total": state_total,
                "done": state_done,
                "mode": scan_mode,
                "binary": binary_filter,
            },
        )
    else:
        total = len(all_functions)
        done = sum(1 for f in all_functions.values() if f["score"] >= 90)
        if is_incremental:
            removed = len(existing) - total_kept - total_rescored - total_new
            print(
                f"\nIncremental scan complete: {total} functions, {done} done (>= 90%)"
            )
            print(
                f"  {total_kept} cached, {total_rescored} re-scored, {total_new} new, {max(0, removed)} removed"
            )
        else:
            print(
                f"\nFull scan complete: {total} functions, {done} documented (>= 90%), {total - done} remaining"
            )
        bus_emit("scan_complete", {"total": total, "done": done, "mode": scan_mode})
    return True


def fetch_available_tools():
    """Fetch available MCP tool names from Ghidra's schema endpoint."""
    schema = ghidra_get("/mcp/schema", timeout=10)
    if schema and isinstance(schema, dict):
        tools = schema.get("tools", schema.get("endpoints", []))
        if isinstance(tools, list):
            return sorted(
                set(
                    t.get("name", t.get("path", "")).lstrip("/")
                    for t in tools
                    if isinstance(t, dict)
                )
            )
    return None


def fetch_function_data(program, address, mode="FIX"):
    """Pre-fetch all Ghidra data needed for prompt assembly.

    If any decompile-heavy endpoint hits a read timeout, bail out early and
    set `data["decompile_timeout"] = True`. The caller inspects that flag
    and marks the function with a one-strike `decompile_timeout` blacklist
    so the selector stops re-picking it. This turns each pathological
    function from ~3 × 60s = 180s of wasted worker time into one 60s miss.
    """
    data = {
        "decompiled": None,
        "completeness": None,
        "variables": None,
        "analyze_for_doc": None,
        "score": None,
        "deductions": [],
        "fixable_categories": [],
        "decompile_timeout": False,
        "ghidra_offline": False,
    }

    # Navigation removed — was calling /tool/goto_address on every function,
    # stealing Ghidra focus from the user. Navigation is now controlled by the
    # dashboard's Focus button (auto-follow checkbox) via /api/navigate.

    # Decompile
    data["decompiled"] = ghidra_get(
        "/decompile_function", params={"address": f"0x{address}", "program": program}
    )
    if ghidra_last_call_timed_out():
        data["decompile_timeout"] = True
        return data
    if ghidra_last_call_offline():
        data["ghidra_offline"] = True
        return data

    # Completeness
    raw = ghidra_get(
        "/analyze_function_completeness",
        params={"function_address": f"0x{address}", "program": program},
    )
    if ghidra_last_call_timed_out():
        data["decompile_timeout"] = True
        return data
    if raw and isinstance(raw, dict):
        data["completeness"] = raw
        data["score"] = int(
            raw.get("effective_score", raw.get("completeness_score", 0))
        )
        deductions = raw.get("deduction_breakdown", [])
        data["deductions"] = deductions
        data["fixable_categories"] = [
            d["category"] for d in deductions if d.get("fixable")
        ]
    elif raw and isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            data["completeness"] = parsed
            data["score"] = int(
                parsed.get("effective_score", parsed.get("completeness_score", 0))
            )
            deductions = parsed.get("deduction_breakdown", [])
            data["deductions"] = deductions
            data["fixable_categories"] = [
                d["category"] for d in deductions if d.get("fixable")
            ]
        except (json.JSONDecodeError, TypeError):
            pass

    # Variables
    func_name = (
        data["completeness"].get("function_name", f"FUN_{address}")
        if data["completeness"]
        else f"FUN_{address}"
    )
    data["variables"] = ghidra_get(
        "/get_function_variables",
        params={"function_name": func_name, "program": program},
    )
    if ghidra_last_call_timed_out():
        data["decompile_timeout"] = True
        return data

    # Full analysis for FULL mode (retry once on failure)
    if mode == "FULL":
        afd = ghidra_get(
            "/analyze_for_documentation",
            params={"function_address": f"0x{address}", "program": program},
            timeout=60,
        )
        if ghidra_last_call_timed_out():
            data["decompile_timeout"] = True
            return data
        if _is_error_response(afd):
            # Retry once — the first call sometimes fails on cold decompiler cache
            afd = ghidra_get(
                "/analyze_for_documentation",
                params={"function_address": f"0x{address}", "program": program},
                timeout=90,
            )
            if ghidra_last_call_timed_out():
                data["decompile_timeout"] = True
                return data
        data["analyze_for_doc"] = afd

    return data


# ---------------------------------------------------------------------------
# Call-graph traversal — bottom-up prioritization
# ---------------------------------------------------------------------------


def populate_call_graph(state, prog_path):
    """Fetch the full call graph for a program and stamp callees on each function.

    Uses the bulk /get_full_call_graph endpoint with json_edges format to get
    all caller→callee edges in one HTTP call. Stamps func["callees"] as a list
    of callee entry-point addresses (hex strings, stable across renames).

    Idempotent: re-running overwrites previous callee data cleanly.
    Returns the number of functions stamped.
    """
    resp = ghidra_get(
        "/get_full_call_graph",
        params={"program": prog_path, "format": "json_edges", "limit": "0"},
        timeout=120,
    )
    if not resp or not isinstance(resp, dict):
        print(f"  WARNING: Could not fetch call graph for {prog_path}", file=sys.stderr)
        return 0

    edges = resp.get("edges", [])
    # Build adjacency: caller_addr → set of callee_addrs
    adjacency = defaultdict(set)
    for edge in edges:
        caller = edge.get("caller_addr", "")
        callee = edge.get("callee_addr", "")
        if caller and callee:
            adjacency[caller].add(callee)

    # Stamp each function's state entry with its callee list
    funcs = state.get("functions", {})
    # Collect addresses — separate scoreable (non-thunk) from all for BFS.
    # BFS layers are computed on non-thunk functions only so they match the
    # dashboard's Call Graph Layers visualization. Thunks participate in
    # callee lists (so readiness can track them) but don't get layer numbers.
    prog_addrs = set()  # all addresses (including thunks)
    scoreable_addrs = set()  # non-thunk only (for BFS)
    addr_to_key = {}
    stamped = 0
    for key, func in funcs.items():
        if func.get("program") != prog_path:
            continue
        addr = func.get("address", "")
        func["callees"] = sorted(adjacency.get(addr, set()))
        prog_addrs.add(addr)
        addr_to_key[addr] = key
        if not func.get("is_thunk") and not func.get("is_external"):
            scoreable_addrs.add(addr)
        stamped += 1

    # BFS layer assignment: leaf = layer 0, callers of leaves = layer 1, etc.
    # Uses scoreable (non-thunk) addresses only so layers match the dashboard.
    internal_callees = {}
    callers_of = defaultdict(set)
    for addr in scoreable_addrs:
        ic = adjacency.get(addr, set()) & scoreable_addrs
        internal_callees[addr] = ic
        for c in ic:
            callers_of[c].add(addr)

    depth = {}
    current = set()
    for addr in scoreable_addrs:
        if not internal_callees.get(addr):
            depth[addr] = 0
            current.add(addr)
    layer_num = 0
    while current:
        nxt = set()
        for addr in current:
            for caller in callers_of.get(addr, set()):
                if caller in depth:
                    continue
                if all(c in depth for c in internal_callees.get(caller, set())):
                    depth[caller] = layer_num + 1
                    nxt.add(caller)
        current = nxt
        layer_num += 1
        if layer_num > 200:
            break

    # Stamp layer on each scoreable function
    for addr, d in depth.items():
        if addr in addr_to_key:
            funcs[addr_to_key[addr]]["call_graph_layer"] = d
    # Cyclic functions get no layer (None); thunks keep whatever they had
    for addr in scoreable_addrs - set(depth.keys()):
        if addr in addr_to_key:
            funcs[addr_to_key[addr]]["call_graph_layer"] = None

    edge_count = resp.get("edge_count", len(edges))
    assigned = len(depth)
    cyclic = len(prog_addrs) - assigned
    print(
        f"  Call graph: {edge_count} edges, {len(adjacency)} callers, "
        f"{stamped} stamped, {assigned} layered, {cyclic} cyclic",
        flush=True,
    )
    return stamped


def _callee_readiness(func, all_funcs, good_enough=80):
    """Fraction of this function's callees that are documented (score >= good_enough).

    Returns 1.0 for leaf functions (no callees) — they're trivially ready.
    Used by select_candidates() to implement bottom-up call-graph ordering:
    functions whose callees are all documented sort ahead of functions with
    undocumented dependencies.

    External callees (address not found in state) are treated as documented —
    they're imports from other DLLs that we can't control.
    """
    callees = func.get("callees")
    if not callees:
        return 1.0  # leaf function or callees not yet populated
    prog_path = func.get("program")
    documented = 0
    for callee_addr in callees:
        callee_key = f"{prog_path}::{callee_addr}"
        callee_func = all_funcs.get(callee_key)
        if callee_func is None:
            # External callee (thunk to another DLL, or not in state) — treat as documented
            documented += 1
        elif callee_func.get("score", 0) >= good_enough:
            documented += 1
    return documented / len(callees)


# ---------------------------------------------------------------------------
# Priority engine
# ---------------------------------------------------------------------------


def compute_priority(func):
    """
    Compute priority score for a function. Higher = process first.

    Strategy: bottom-up, impact-weighted.
    - Leaf functions get highest base priority (easiest, unlock callers)
    - Among leaves, more callers = higher priority (more impact)
    - Non-leaves get lower base priority, scaled by caller count
    - Already-documented functions (score >= 90) get priority 0
    """
    score = func.get("score", 0)

    # Skip already-documented
    if score >= 90:
        return 0

    caller_count = func.get("caller_count", 0)
    is_leaf = func.get("is_leaf", False)
    fixable = func.get("fixable", 0)

    # Base priority
    if is_leaf:
        base = 10000  # Leaves first
    else:
        base = 1000  # Non-leaves after

    # Impact: more callers = higher priority
    impact = caller_count * 10

    # Effort discount: near-complete functions are cheaper to finish
    if score >= 70:
        effort_bonus = 500  # Quick fix, high ROI
    elif score >= 50:
        effort_bonus = 200
    else:
        effort_bonus = 0

    # Fixable deductions bonus: functions with known fixable issues are easier
    fixable_bonus = int(fixable * 20)

    return base + impact + effort_bonus + fixable_bonus


# Per-provider FULL/FIX/VERIFY model defaults. Used to backfill missing
# providers / modes when normalizing the dashboard config so:
#   * a fresh priority_queue.json with no provider_models gets every provider
#     populated with sensible values,
#   * a partial config (e.g. minimax/gemini/claude set, codex unset) backfills
#     codex from defaults instead of showing blank dashboard inputs,
#   * a user-set value always wins (empty strings count as unset).
# Update these whenever a model is renamed/deprecated upstream — they're the
# single source of truth for "what model should each provider call by default."
DEFAULT_PROVIDER_MODELS = {
    "minimax": {"FULL": "MiniMax-M2.7", "FIX": "MiniMax-M2.7", "VERIFY": "MiniMax-M2.7"},
    "gemini":  {"FULL": "gemini-2.5-pro", "FIX": "gemini-2.5-flash", "VERIFY": "gemini-2.5-flash"},
    "claude":  {"FULL": "claude-sonnet-4-6", "FIX": "claude-sonnet-4-6", "VERIFY": "claude-sonnet-4-6"},
    "codex":   {"FULL": "gpt-5.5", "FIX": "gpt-5.5", "VERIFY": "gpt-5.5"},
}


DEFAULT_QUEUE_CONFIG = {
    "good_enough_score": 80,
    "require_scored": False,
    # Dashboard-owned provider -> mode -> model mapping. Defaults from
    # DEFAULT_PROVIDER_MODELS — overridable per-provider/mode via the dashboard.
    "provider_models": copy.deepcopy(DEFAULT_PROVIDER_MODELS),
    # Auto-handoff: when the active provider's complexity gate fires, swap to
    # this provider for the current function instead of skipping. Off by
    # default so stronger providers are only consumed when explicitly enabled.
    "complexity_handoff_provider": None,
    # Cap handoffs per worker session to limit expensive-provider spend.
    # 0 = unlimited.
    # Default 5: after five handoffs, massive functions stay with the primary
    # provider (typically minimax) and accept lower per-function quality.
    # Reset via the dashboard's Reset Handoffs button or by restarting the
    # worker. Raise it only if you want more stronger-provider coverage.
    "complexity_handoff_max": 5,
    # Detailed tool-call logging: writes per-function JSONL files under
    # logs/debug/{date}/ and prints verbose console lines. Use analyze_debug.py
    # to spot inefficiencies (consecutive same-tool runs, retries, etc).
    "debug_mode": False,
    # Audit stage: after the worker finishes, a second provider reviews the
    # result and fixes gaps (missing plate sections, unrenamed variables, etc.).
    # Set to None / "off" to disable. Only fires when score gain < audit_min_delta.
    "audit_provider": None,
    # Optional immediate retry after a below-threshold run. Off by default so
    # the dashboard worker does not silently escalate to a more expensive model.
    "auto_escalate_provider": None,
    "pre_escalate_retry": False,
    # Minimum score delta to skip audit. If the worker gained >= this many
    # points, audit is skipped (the worker did well enough). Lower = more audits.
    "audit_min_delta": 5,
    # Pre-refresh top candidates' scores when a worker starts. Skipped when:
    # - This flag is False
    # - No active_binary is set (would touch every binary Ghidra has)
    # - Last refresh was < freshness window ago (default 5 minutes)
    "pre_refresh_on_start": True,
    # Minutes of freshness to honor: if the last refresh is newer than this,
    # skip pre-refresh entirely. Multiple workers starting together share one.
    "pre_refresh_freshness_min": 5,
    # Per-provider max tool-call turns. Edit via dashboard or priority_queue.json.
    # Lower values prevent over-analysis loops; higher values give the model more
    # room to complete complex functions in one session.
    "provider_max_turns": {
        "claude": 25,
        "codex": 25,
        "gemini": 25,
        "minimax": 25,
    },
    # Background inventory scorer (opt-in, Q9). When True, a single thread runs
    # `analyze_function_completeness` against every binary in the Ghidra project
    # tree to fill in missing scores in state.json. Yields MCP bandwidth to doc
    # workers — only runs when zero workers are active. See inventory_scorer.py
    # and the Inventory panel on the dashboard.
    "inventory_enabled": False,
}

PRIORITY_QUEUE_FILE = SCRIPT_DIR / "priority_queue.json"


def _normalize_provider_models(raw_models):
    """Normalize provider->mode->model config, backfilling missing entries
    from DEFAULT_PROVIDER_MODELS.

    Deep-merge semantics: every supported provider/mode is populated. User
    values win when present and non-empty; defaults fill the rest. This is
    what makes a fresh priority_queue.json or a partially-configured one
    show fully-populated dashboard inputs without manual setup.
    """
    normalized = copy.deepcopy(DEFAULT_PROVIDER_MODELS)
    if not isinstance(raw_models, dict):
        return normalized

    for provider, mode_map in raw_models.items():
        if provider not in SUPPORTED_PROVIDERS or not isinstance(mode_map, dict):
            continue
        for mode, model_name in mode_map.items():
            normalized_mode = str(mode).upper()
            if normalized_mode not in SUPPORTED_MODEL_MODES:
                continue
            if model_name is None:
                continue
            normalized_model = str(model_name).strip()
            if not normalized_model:
                continue
            normalized.setdefault(provider, {})[normalized_mode] = normalized_model

    return normalized


def build_worker_config_snapshot(queue, primary_provider):
    """Build a frozen config snapshot for a worker about to start.

    Captures every queue.config field that should remain constant for the
    worker's lifetime. The snapshot is opaque to the worker thread — it just
    holds it and passes it to process_function on every iteration. The
    snapshot's shape is stable across the codebase: tests, the dashboard, the
    event-log persister, and process_function all agree on what fields exist.

    Includes settings for every provider this worker can actually invoke:
        * primary_provider (passed in)
        * audit_provider (if config.audit_provider is set and != primary)
        * complexity_handoff_provider (if set and != primary)

    Each provider entry holds its `max_turns` and the FULL/FIX/VERIFY model
    slice from `provider_models`. Providers this worker won't invoke are not
    snapshotted — keeps the snapshot compact and the run records clean.

    Returns a plain dict suitable for json.dumps. No references back into
    the queue dict.
    """
    cfg = (queue or {}).get("config") or {}

    # Top-level worker policy (Tier 1 + Tier 2 from the design discussion)
    snapshot = {
        "good_enough_score": int(cfg.get("good_enough_score", 80)),
        "audit_provider": cfg.get("audit_provider"),
        "audit_min_delta": int(cfg.get("audit_min_delta", 5)),
        "complexity_handoff_provider": cfg.get("complexity_handoff_provider"),
        "complexity_handoff_max": int(cfg.get("complexity_handoff_max", 0) or 0),
    }

    # Per-provider slices — only the providers this worker can invoke. The
    # primary's slice is always present; audit and escalation are added only
    # when configured (and only if they differ from primary, since the same
    # provider's slice would just duplicate).
    pmt = cfg.get("provider_max_turns") or {}
    pm = cfg.get("provider_models") or {}
    providers_seen: set[str] = set()
    providers: dict[str, dict] = {}

    def _add_provider(name):
        if not name or name in providers_seen:
            return
        if name not in SUPPORTED_PROVIDERS:
            return
        providers_seen.add(name)
        # Default max_turns is 25 (matches DEFAULT_QUEUE_CONFIG); coerce to int
        # so JSON serialization doesn't surface accidental floats.
        providers[name] = {
            "max_turns": int(pmt.get(name, 25)),
            "models": dict(pm.get(name) or {}),
        }

    _add_provider(primary_provider)
    _add_provider(snapshot["audit_provider"])
    _add_provider(snapshot["complexity_handoff_provider"])
    snapshot["providers"] = providers
    snapshot["primary_provider"] = primary_provider
    return snapshot


def _normalize_provider_max_turns(raw):
    """Backfill provider_max_turns with DEFAULT_QUEUE_CONFIG values for any
    missing provider. Mirrors _normalize_provider_models — partial user
    config gets the missing keys filled in instead of dropped on the floor."""
    defaults = DEFAULT_QUEUE_CONFIG.get("provider_max_turns") or {}
    normalized = dict(defaults)
    if isinstance(raw, dict):
        for provider, turns in raw.items():
            if provider not in SUPPORTED_PROVIDERS:
                continue
            try:
                normalized[provider] = int(turns)
            except (TypeError, ValueError):
                continue
    return normalized


def load_priority_queue():
    """Load the priority queue file. Always returns a dict with pinned/config.

    The legacy `skipped` list is no longer honored — auto-dequeue on completion
    plus the consecutive_fails / good_enough_score filters cover every case the
    skip list used to. Old `skipped` data is loaded but ignored by the selector.
    """
    if PRIORITY_QUEUE_FILE.exists():
        try:
            with open(PRIORITY_QUEUE_FILE, "r") as f:
                queue = json.load(f)
        except (json.JSONDecodeError, OSError):
            queue = {}
    else:
        queue = {}
    queue.setdefault("pinned", [])
    cfg = copy.deepcopy(DEFAULT_QUEUE_CONFIG)
    cfg.update(queue.get("config") or {})
    cfg["provider_models"] = _normalize_provider_models(cfg.get("provider_models"))
    cfg["provider_max_turns"] = _normalize_provider_max_turns(cfg.get("provider_max_turns"))
    queue["config"] = cfg
    return queue


def get_auto_escalation_provider(current_provider, queue=None):
    """Return the explicitly configured retry provider for dashboard workers.

    This intentionally has no implicit fallback ladder. If the user did not
    opt into escalation, we do not consume a stronger provider.
    """
    queue = queue or load_priority_queue()
    cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
    if not cfg.get("pre_escalate_retry", False):
        return None

    target = cfg.get("auto_escalate_provider")
    if not target or target in ("off", current_provider):
        return None
    if target not in SUPPORTED_PROVIDERS:
        return None
    return target


def get_configured_model(provider, mode, queue=None):
    """Return the dashboard-configured model for a provider/mode pair."""
    effective_provider = provider or AI_PROVIDER
    normalized_mode = str(mode).upper()

    if effective_provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider: {effective_provider}")
    if normalized_mode not in SUPPORTED_MODEL_MODES:
        raise ValueError(f"Unsupported model mode: {normalized_mode}")

    queue = queue or load_priority_queue()
    cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
    provider_models = _normalize_provider_models(cfg.get("provider_models"))
    return provider_models.get(effective_provider, {}).get(normalized_mode)


def _require_model_name(model, provider):
    normalized_model = (model or "").strip()
    if normalized_model:
        return normalized_model
    raise ValueError(
        f"No model configured for provider '{provider}'. Set it in the web dashboard."
    )


# Backwards-compat alias for any external callers
_load_priority_queue = load_priority_queue


def save_priority_queue(queue):
    """Persist priority_queue.json atomically."""
    if isinstance(queue, dict):
        cfg = dict(queue.get("config") or {})
        cfg["provider_models"] = _normalize_provider_models(cfg.get("provider_models"))
        cfg["provider_max_turns"] = _normalize_provider_max_turns(cfg.get("provider_max_turns"))
        queue["config"] = cfg
        # Drop any lingering dashboard_active_workers meta — workers no
        # longer auto-restore across restarts, so persisting a snapshot
        # only serves to confuse future readers.
        meta = queue.get("meta")
        if isinstance(meta, dict) and "dashboard_active_workers" in meta:
            meta.pop("dashboard_active_workers", None)
    tmp_path = PRIORITY_QUEUE_FILE.with_suffix(".json.tmp")
    with _queue_lock:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        tmp_path.replace(PRIORITY_QUEUE_FILE)


def select_candidates(funcs, queue=None, active_binary=None, with_scoring_lane=None):
    """Canonical work-queue selector. Used by both fun_doc CLI and web dashboard.

    Returns a list of dicts sorted by descending priority. Each dict contains:
        key, func (raw state entry), roi, pinned, needs_scoring

    Selection rules:
    - Skip thunks / externals
    - Skip funcs at/above good_enough_score (unless pinned or needs cold scoring)
    - Skip funcs from other binaries when active_binary is set
    - Skip funcs with >=3 consecutive_fails (unless pinned)
    - Skip funcs with recovery_pass_done (complexity-forced recovery already ran)
    - Skip funcs with decompile_timeout (pathological, one-shot blacklist)
    - Skip funcs with >=3 stagnation_runs (no-progress / regression safety net)
    - When require_scored is on, treat unscored funcs as top priority so the
      worker scores them on first contact instead of leaving them stranded
    - Pinned (explicitly queued) funcs always sort to the top in pin order
    """
    if queue is None:
        queue = load_priority_queue()
    pinned_list = list(queue.get("pinned", []))
    pinned = set(pinned_list)
    cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
    good_enough = cfg.get("good_enough_score", 80)
    require_scored = (
        cfg.get("require_scored", False)
        if with_scoring_lane is None
        else with_scoring_lane
    )

    pin_order = {k: i for i, k in enumerate(pinned_list)}
    candidates = []
    for key, func in funcs.items():
        if func.get("is_thunk") or func.get("is_external"):
            continue
        is_pinned = key in pinned
        if active_binary and func.get("program_name") != active_binary:
            continue

        score = func.get("score", 0)
        fixable = func.get("fixable", 0)
        callers = func.get("caller_count", 0)
        last_processed = func.get("last_processed")
        needs_scoring = require_scored and last_processed is None

        if score >= good_enough and not is_pinned and not needs_scoring:
            continue

        consecutive_fails = func.get("consecutive_fails", 0)
        if consecutive_fails >= 3 and not is_pinned:
            continue
        # Safety valve: even pinned functions get removed after 6 consecutive
        # failures (2 full escalation cycles). Prevents infinite retry loops.
        if consecutive_fails >= 6 and is_pinned:
            pinned_list_copy = list(queue.get("pinned", []))
            if key in pinned_list_copy:
                pinned_list_copy.remove(key)
                queue["pinned"] = pinned_list_copy
                save_priority_queue(queue)
                print(
                    f"  Auto-unpinned {func.get('name', key)} after {consecutive_fails} consecutive failures"
                )
            continue

        # Recovery-pass one-shot: massive functions get exactly one
        # complexity-forced recovery pass; after that they stay out of the
        # selector until the user explicitly refreshes or pins them. This
        # stops the "re-queue forever below good_enough" loop that burns
        # extra provider budget for marginal score improvement. Cleared by
        # --scan --refresh (full rescan) or the dashboard's Refresh Top N.
        if func.get("recovery_pass_done") and not is_pinned:
            continue

        # Decompile-timeout one-shot: pathological functions whose decompile
        # exceeds the Ghidra scoring-path timeout (~12s per call) get flagged
        # by fetch_function_data. Skip them until explicit refresh — the cost
        # of retrying is 60s+ of HTTP thread time per attempt for a function
        # we already know can't be scored. Cleared by the same refresh paths
        # as recovery_pass_done.
        if func.get("decompile_timeout") and not is_pinned:
            continue

        # Stagnation safety net: blacklist functions that have completed 3+
        # runs in a row with no meaningful progress (delta <= 1%) OR with
        # regression. This catches infinite re-pick loops for any provider
        # where the other guards miss (notably codex, which returns
        # tool_calls_made = -1 so the "no tools, no progress" downgrade never
        # fires). Cleared by refresh — same as the other one-shot flags.
        if func.get("stagnation_runs", 0) >= 3 and not is_pinned:
            continue

        if needs_scoring:
            roi = 1_000_000  # Cold-start lane: surface unscored funcs first
            readiness = 1.0
        else:
            if fixable <= 0 and not is_pinned:
                # Already scored, nothing concrete to fix — leave it alone
                continue
            # Bottom-up call-graph traversal: readiness is used as a
            # PRIMARY sort key (not a ROI multiplier) so that:
            #   1. Leaves (readiness=1.0, 0 callees) sort first
            #   2. Ready callers (readiness=1.0, callees>0) sort next
            #   3. Partially-ready functions sort after
            #   4. Trunk functions (readiness~0) sort last
            # Within each tier, ROI determines which function to pick.
            readiness = _callee_readiness(func, funcs, good_enough)
            is_leaf = not func.get("callees")
            roi = fixable * (1 + callers / 10)
            if score < good_enough and fixable > 0:
                roi += (good_enough - score) * 2

        partial_runs = func.get("partial_runs", 0)
        if partial_runs >= 3 and not is_pinned:
            roi *= 0.1

        candidates.append(
            {
                "key": key,
                "func": func,
                "roi": roi,
                "readiness": readiness,
                "is_leaf": not func.get("callees"),
                "call_graph_layer": func.get("call_graph_layer"),
                "pinned": is_pinned,
                "pin_order": pin_order.get(key, 10**9),
                "needs_scoring": needs_scoring,
            }
        )

    # Sort: pinned first → cold-start → strict bottom-up (readiness desc,
    # leaves before non-leaves within same readiness) → highest ROI.
    candidates.sort(
        key=lambda c: (
            not c["pinned"],
            c["pin_order"],
            not c["needs_scoring"],
            -c["readiness"],  # higher readiness first (1.0 before 0.5)
            not c["is_leaf"],  # within same readiness, leaves before callers
            -c["roi"],  # within same tier, highest ROI first
        )
    )
    return candidates


def get_next_functions(state, count=1):
    """Return up to N (key, func) tuples for the worker to process."""
    queue = load_priority_queue()
    active_binary = state.get("active_binary")
    candidates = select_candidates(state["functions"], queue, active_binary)
    return [(c["key"], c["func"]) for c in candidates[:count]]


def refresh_candidate_scores(
    state,
    active_binary=None,
    count=50,
    save=True,
    fallback=True,
    first_batch_timeout=300,
):
    """Batch-refresh the live completeness scores of the top-N ROI candidates.

    Avoids the "walk through 6 stale candidates fetching one at a time" problem
    by doing a single `/batch_analyze_completeness` call per program. Updates
    state.json in place so the next selector pass sees fresh data.

    Parameters:
        fallback: passed to _batch_score. False = skip individual retries on
            batch failure (used by pre-refresh on worker start).
        first_batch_timeout: passed to _batch_score. Default 300s; pre-refresh
            uses 60s so it fails fast when Ghidra is unresponsive.

    Returns: {"refreshed": int, "stale": int, "by_program": {prog: count}}
             where "stale" counts candidates whose score drifted >=5 points.
    """
    funcs = state.get("functions", {})
    queue = load_priority_queue()
    candidates = select_candidates(funcs, queue, active_binary=active_binary)[:count]
    if not candidates:
        return {"refreshed": 0, "stale": 0, "by_program": {}}

    by_prog = defaultdict(list)
    for c in candidates:
        by_prog[c["func"]["program"]].append(c)

    refreshed = 0
    stale = 0
    by_program_stats = {}
    for prog, items in by_prog.items():
        addresses = [c["func"]["address"] for c in items]
        try:
            score_map = _batch_score(
                addresses,
                prog_path=prog,
                fallback=fallback,
                first_batch_timeout=first_batch_timeout,
            )
        except Exception as e:
            print(f"  Refresh failed for {prog}: {e}")
            continue
        prog_refreshed = 0
        prog_stale = 0
        for c in items:
            addr = c["func"]["address"]
            if addr not in score_map:
                continue
            info = score_map[addr]
            func = c["func"]
            old_score = func.get("score", 0)
            func["score"] = info["score"]
            func["fixable"] = info["fixable"]
            func["has_custom_name"] = info["has_custom_name"]
            func["has_plate_comment"] = info["has_plate_comment"]
            func["is_leaf"] = info["is_leaf"]
            func["classification"] = info["classification"]
            func["deductions"] = info["deductions"]
            # Clear recovery-pass one-shot flag so the user can re-run these
            # functions after a refresh — the refresh gesture is an explicit
            # "look at everything fresh" signal.
            func.pop("recovery_pass_done", None)
            func.pop("recovery_pass_score", None)
            func.pop("recovery_pass_at", None)
            # Same for decompile-timeout: refresh clears the blacklist so the
            # user can retry after e.g. Ghidra analysis improvements.
            func.pop("decompile_timeout", None)
            func.pop("decompile_timeout_at", None)
            # And the stagnation counter: a refresh is the user saying
            # "re-score this from scratch, I'm willing to try again."
            func.pop("stagnation_runs", None)
            prog_refreshed += 1
            if abs(info["score"] - old_score) >= 5:
                prog_stale += 1
        refreshed += prog_refreshed
        stale += prog_stale
        if prog_refreshed > 0:
            by_program_stats[prog] = {"refreshed": prog_refreshed, "stale": prog_stale}

    if save and refreshed > 0:
        # Read-modify-write: re-read the latest state from disk before saving
        # so we don't clobber functions that were added (e.g. by a concurrent
        # state merge) between when this refresh started and now. Only the
        # specific function entries we scored get overwritten.
        refreshed_funcs = {
            c["key"]: c["func"]
            for prog_items in by_prog.values()
            for c in prog_items
            if c["func"].get("score") is not None
        }
        with _state_lock:
            latest = load_state()
            latest_funcs = latest.setdefault("functions", {})
            for key, func in refreshed_funcs.items():
                if key in latest_funcs:
                    latest_funcs[key].update(func)
                else:
                    latest_funcs[key] = func
            _atomic_write_state(latest)
        bus_emit("state_changed")

    # Record refresh metadata on the queue so the dashboard can display it
    queue = load_priority_queue()
    meta = queue.get("meta") or {}
    meta["last_refresh_at"] = datetime.now().isoformat()
    meta["last_refresh_count"] = refreshed
    meta["last_refresh_stale"] = stale
    meta["stale_skips_since_refresh"] = 0
    queue["meta"] = meta
    save_priority_queue(queue)

    return {"refreshed": refreshed, "stale": stale, "by_program": by_program_stats}


def _emit_skip(func_key, skip_type, reason, live_score=None):
    """Emit function_complete events for a skipped function so the dashboard
    worker pane shows what happened instead of leaving the entry hanging.

    Sends both `function_mode` (so the pane shows "SKIP" in place of FIX/FULL)
    and `function_complete` with a reason field the JS handler renders.
    """
    bus_emit(
        "function_mode",
        {
            "key": func_key,
            "mode": f"SKIP:{skip_type}",
            "model": "—",
            "score": live_score,
        },
    )
    bus_emit(
        "score_update",
        {
            "key": func_key,
            "score_before": live_score,
            "score_after": live_score,
            "result": "skipped",
        },
    )
    bus_emit(
        "function_complete",
        {
            "key": func_key,
            "result": "skipped",
            "score": live_score,
            "reason": reason,
            "skip_type": skip_type,
        },
    )


def _increment_stale_skip_counter():
    """Bump the stale-skip counter in priority_queue.meta. Called when a worker
    skips a function whose live score was already at good_enough — indicates
    state.json was stale for that entry."""
    try:
        queue = load_priority_queue()
        meta = queue.get("meta") or {}
        meta["stale_skips_since_refresh"] = meta.get("stale_skips_since_refresh", 0) + 1
        queue["meta"] = meta
        save_priority_queue(queue)
    except Exception:
        pass


def _bump_handoff_counter():
    """Bump the per-session complexity-handoff counter and return the new value."""
    try:
        queue = load_priority_queue()
        meta = queue.get("meta") or {}
        meta["handoffs_this_session"] = meta.get("handoffs_this_session", 0) + 1
        queue["meta"] = meta
        save_priority_queue(queue)
        return meta["handoffs_this_session"]
    except Exception:
        return 0


def reset_handoff_counter():
    """Reset the per-session handoff counter. Called when a worker starts."""
    try:
        queue = load_priority_queue()
        meta = queue.get("meta") or {}
        meta["handoffs_this_session"] = 0
        queue["meta"] = meta
        save_priority_queue(queue)
    except Exception:
        pass


def drain_done_pinned(state):
    """Batch-score every currently pinned function and auto-dequeue any that
    are already at or above good_enough_score. Used to drain stuck queue items
    that were pinned based on stale state.json scores ("0%" really meaning
    "unscored") and turned out to be already documented.

    Returns: {"checked": int, "dequeued": int, "still_queued": int, "errors": int}
    """
    queue = load_priority_queue()
    pinned = list(queue.get("pinned", []))
    if not pinned:
        return {"checked": 0, "dequeued": 0, "still_queued": 0, "errors": 0}

    cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
    good_enough = cfg.get("good_enough_score", 80)

    funcs = state.get("functions", {})
    by_prog = defaultdict(list)
    missing = []
    for key in pinned:
        func = funcs.get(key)
        if not func:
            missing.append(key)
            continue
        prog = func.get("program")
        addr = func.get("address")
        if not prog or not addr:
            missing.append(key)
            continue
        by_prog[prog].append((key, func, addr))

    checked = 0
    dequeued = 0
    errors = len(missing)
    for prog, items in by_prog.items():
        addresses = [addr for (_, _, addr) in items]
        try:
            score_map = _batch_score(addresses, prog_path=prog)
        except Exception as e:
            print(f"  drain: batch score failed for {prog}: {e}")
            errors += len(items)
            continue
        for key, func, addr in items:
            checked += 1
            info = score_map.get(addr)
            if not info:
                errors += 1
                continue
            # Apply fresh score back into state
            func["score"] = info["score"]
            func["fixable"] = info["fixable"]
            func["has_custom_name"] = info["has_custom_name"]
            func["has_plate_comment"] = info["has_plate_comment"]
            func["is_leaf"] = info["is_leaf"]
            func["classification"] = info["classification"]
            func["deductions"] = info["deductions"]
            func["last_processed"] = func.get("last_processed") or "drained_check"
            if info["score"] >= good_enough:
                if auto_dequeue_if_done(key, info["score"], source="drain_done"):
                    dequeued += 1

    save_state(state)

    queue_after = load_priority_queue()
    still_queued = len(queue_after.get("pinned", []))
    return {
        "checked": checked,
        "dequeued": dequeued,
        "still_queued": still_queued,
        "errors": errors,
    }


def auto_dequeue_if_done(func_key, score, source="completed"):
    """If func_key is currently pinned and score >= good_enough_score, remove
    it from the queue and emit queue_changed. Returns True if dequeued.

    Used by:
    - process_function on successful completion (`source="completed"`)
    - process_function on skip-because-already-done (`source="skipped"`)
    - /api/queue/pin when an immediate score check shows the function is
      already above good_enough (`source="pin_check"`)
    """
    if score is None:
        return False
    try:
        queue = load_priority_queue()
        cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
        good_enough = cfg.get("good_enough_score", 80)
        if func_key not in queue.get("pinned", []):
            return False
        if score < good_enough:
            return False
        queue["pinned"] = [k for k in queue["pinned"] if k != func_key]
        save_priority_queue(queue)
        print(f"  Auto-dequeued (score {score}% >= {good_enough}%, via {source})")
        bus_emit(
            "queue_changed",
            {
                "action": "auto_dequeue",
                "key": func_key,
                "score": score,
                "source": source,
            },
        )
        return True
    except Exception as e:
        print(f"  WARNING: auto-dequeue failed: {e}")
        return False


def _mode_label(mode):
    """Human-readable label for internal mode strings used in console output."""
    return {
        "FULL": "FULL",
        "FULL:recovery": "FULL/pass1 (types+structs)",
        "FULL:comments": "FULL/pass2 (documentation)",
        "FIX": "FIX",
        "VERIFY": "VERIFY",
    }.get(mode, mode)


def _format_mode_banner(mode, selected_model, effective_provider, score, config_snapshot, prompt):
    """Build the per-function mode banner string.

    Steady-state output: `FULL/pass1 (types+structs) | score: 13%`. Mode
    label and score only — the model is in the worker's header sub-line and
    the prompt char count is debug-only noise that hides important signal.

    Deviation output: `HANDOFF:minimax→gemini | gemini-2.5-pro | score: 13%`.
    The model token appears only when `selected_model` differs from what the
    worker's snapshot says it should be using for this provider/mode. That
    way "the model token is present" is itself the visual signal that this
    function ran with something other than the worker's default — a
    deviation worth your attention.

    When no snapshot is present (CLI invocation, legacy callers), we can't
    detect deviation, so we always show the model — matches pre-snapshot
    behavior so existing log scrapers still see what they expect.
    """
    parts = [_mode_label(mode)]
    worker_default_model = None
    if config_snapshot is not None:
        snap_entry = (config_snapshot.get("providers") or {}).get(effective_provider) or {}
        snap_models = snap_entry.get("models") or {}
        lookup_mode = "FULL" if str(mode).startswith("FULL:") else mode
        worker_default_model = snap_models.get(lookup_mode)
    if worker_default_model is None or selected_model != worker_default_model:
        parts.append(str(selected_model))
    parts.append(f"score: {score}%")
    return "  " + " | ".join(parts)


def _emit_handoff(func_key, from_provider, to_provider, reason, count, score=None):
    """Emit a function_mode event so the dashboard pane shows the handoff."""
    bus_emit(
        "function_mode",
        {
            "key": func_key,
            "mode": f"HANDOFF:{from_provider}->{to_provider}",
            "model": to_provider,
            "score": score,
        },
    )
    bus_emit(
        "queue_changed",
        {
            "action": "handoff",
            "key": func_key,
            "from": from_provider,
            "to": to_provider,
            "reason": reason,
            "count": count,
        },
    )


# ---------------------------------------------------------------------------
# Debug logging — per-tool-call JSONL traces for offline analysis
# ---------------------------------------------------------------------------
#
# Uses a contextvars.ContextVar so the per-function context is propagated
# correctly across asyncio task boundaries and thread-pool executor calls.
# Previously used threading.local(), which broke for the Claude Agent SDK
# path: claude_agent_sdk.query() delivers ToolResultBlock messages to
# callbacks that may execute in executor threads, where a thread-local
# set in the worker's main thread is invisible. ContextVar is the Python-
# blessed fix for this exact pattern and works for all provider paths.

_debug_ctx: "contextvars.ContextVar[dict]" = contextvars.ContextVar(
    "_debug_ctx", default={}
)
_debug_log_lock = threading.Lock()


def _normalize_tool_name(tool_name):
    """Normalize provider-specific tool names to a common short name."""
    if not tool_name:
        return ""
    normalized = str(tool_name)
    for prefix in ("mcp_ghidra-mcp_", "mcp__ghidra-mcp__"):
        if normalized.startswith(prefix):
            return normalized.removeprefix(prefix)
    return normalized


def _normalize_debug_status(status):
    """Keep debug JSONL statuses comparable across provider SDKs."""
    normalized = str(status or "").lower()
    if normalized in ("failed", "failure"):
        return "error"
    if normalized in ("ok", "complete", "completed"):
        return "success"
    return normalized or "unknown"


def _debug_set_context(
    func_key,
    func_name,
    program,
    address,
    provider,
    run_id,
    requested_provider=None,
):
    """Set the current function context for debug logging. Called once per
    function at the start of process_function so all tool calls in subsequent
    provider invocations get tagged with the same metadata. Re-reads queue
    config once (avoids per-tool-call disk hits)."""
    ctx = {
        "func_key": func_key,
        "func_name": func_name,
        "program": program,
        "address": address,
        "run_id": run_id,
        "provider": provider,
        "requested_provider": requested_provider or provider,
        "iteration": 0,
        "log_path": None,
    }
    try:
        queue = load_priority_queue()
        cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
        ctx["enabled"] = bool(cfg.get("debug_mode", False))
    except Exception:
        ctx["enabled"] = False
    _debug_ctx.set(ctx)


def _debug_update_context(**fields):
    """Update the active debug context in-place for provider/model handoffs."""
    ctx = dict(_debug_ctx.get())
    if not ctx:
        return
    ctx.update(fields)
    _debug_ctx.set(ctx)


def _debug_get_log_path():
    """Lazy-create the per-function debug log path on first call."""
    ctx = _debug_ctx.get()
    existing = ctx.get("log_path")
    if existing:
        return existing
    try:
        date_dir = LOG_DIR / "debug" / date.today().isoformat()
        date_dir.mkdir(parents=True, exist_ok=True)
        prog = ctx.get("program") or "unknown"
        prog = prog.replace("/", "_").replace("\\", "_").strip("_") or "unknown"
        addr = ctx.get("address") or "unknown"
        provider = ctx.get("requested_provider") or ctx.get("provider") or "unknown"
        run_id = ctx.get("run_id") or "unknown"
        path = date_dir / f"{prog}__{addr}__{provider}__{run_id}.jsonl"
        # ContextVar values are shallow-immutable by convention — rebuild the
        # dict with the cached path so subsequent calls in this context skip
        # the mkdir overhead.
        new_ctx = dict(ctx)
        new_ctx["log_path"] = path
        _debug_ctx.set(new_ctx)
        return path
    except Exception:
        return None


def _debug_summarize_args(args):
    """Compact one-line arg summary for verbose console output."""
    if not isinstance(args, dict):
        s = str(args)
        return s[:80] + ("..." if len(s) > 80 else "")
    parts = []
    for k, v in list(args.items())[:3]:
        try:
            v_str = json.dumps(v, default=str) if not isinstance(v, str) else f'"{v}"'
        except Exception:
            v_str = repr(v)
        if len(v_str) > 30:
            v_str = v_str[:27] + "..."
        parts.append(f"{k}={v_str}")
    if len(args) > 3:
        parts.append(f"+{len(args) - 3} more")
    return ", ".join(parts)


def _debug_log_tool_call(tool, args, result, status, duration_ms=None):
    """Log a single tool call to the per-function JSONL file and verbose console.
    No-op when debug_mode is off. Safe to call from any provider."""
    ctx = _debug_ctx.get()
    if not ctx.get("enabled", False):
        return
    iteration = ctx.get("iteration", 0) + 1
    # Update the iteration counter in-place. ContextVar stores a dict by
    # reference, so mutating it here is visible to subsequent reads in the
    # same context — matches the old threading.local() semantics without
    # the overhead of rebuilding the dict on every tool call.
    ctx["iteration"] = iteration

    result_str = "" if result is None else str(result)
    result_full_size = len(result_str)
    result_preview = result_str[:500]
    normalized_tool = _normalize_tool_name(tool)
    status = _normalize_debug_status(status)

    entry = {
        "ts": datetime.now().isoformat(),
        "run_id": ctx.get("run_id"),
        "function_key": ctx.get("func_key"),
        "function_name": ctx.get("func_name"),
        "provider": ctx.get("provider"),
        "requested_provider": ctx.get("requested_provider"),
        "iteration": iteration,
        "tool": normalized_tool,
        "tool_raw": tool,
        "args": args,
        "result_preview": result_preview,
        "result_full_size": result_full_size,
        "status": status,
        "duration_ms": duration_ms,
    }

    log_path = _debug_get_log_path()
    if log_path is not None:
        try:
            with _debug_log_lock:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            print(f"  [debug log error] {e}", flush=True)

    args_summary = _debug_summarize_args(args)
    duration_str = f", {duration_ms}ms" if duration_ms is not None else ""
    print(
        f"  [debug] #{iteration} {normalized_tool}({args_summary}) -> {status} "
        f"({result_full_size}b{duration_str})",
        flush=True,
    )


def get_select_functions(state, program, address, depth=1):
    """Get functions in the call neighborhood of a selected function."""
    target_key = f"{program}::{address}"
    if target_key not in state["functions"]:
        # Create a temporary entry from live Ghidra data
        func_resp = ghidra_get(
            "/get_function_by_address",
            params={"address": f"0x{address}", "program": program},
        )
        if func_resp:
            func_text = str(func_resp)
            import re

            name_match = re.search(r"Function:\s+(\S+)", func_text)
            func_name = name_match.group(1) if name_match else f"FUN_{address}"
            prog_name = program.split("/")[-1] if "/" in program else program
            state["functions"][target_key] = {
                "program": program,
                "program_name": prog_name,
                "address": address,
                "name": func_name,
                "score": 0,
                "fixable": 0,
                "has_custom_name": not func_name.startswith("FUN_"),
                "has_plate_comment": False,
                "deductions": [],
                "caller_count": 0,
                "is_leaf": False,
                "classification": "unknown",
                "is_thunk": False,
                "is_external": False,
                "last_processed": None,
                "last_result": None,
            }
        else:
            print(f"ERROR: Function not found at 0x{address} in {program}")
            return []

    result = []
    visited = set()
    prog_name = program.split("/")[-1] if "/" in program else program

    def ensure_in_state(addr):
        """Create a temporary state entry for a function not yet in state."""
        key = f"{program}::{addr}"
        if key in state["functions"]:
            return state["functions"][key]
        func_resp = ghidra_get(
            "/get_function_by_address",
            params={"address": f"0x{addr}", "program": program},
        )
        if not func_resp:
            return None
        func_text = str(func_resp)
        import re

        name_match = re.search(r"Function:\s+(\S+)", func_text)
        func_name = name_match.group(1) if name_match else f"FUN_{addr}"
        entry = {
            "program": program,
            "program_name": prog_name,
            "address": addr,
            "name": func_name,
            "score": 0,
            "fixable": 0,
            "has_custom_name": not func_name.startswith("FUN_"),
            "has_plate_comment": False,
            "deductions": [],
            "caller_count": 0,
            "is_leaf": False,
            "classification": "unknown",
            "is_thunk": False,
            "is_external": False,
            "last_processed": None,
            "last_result": None,
        }
        state["functions"][key] = entry
        return entry

    def _parse_func_list_response(resp):
        """Parse a callers/callees response — handles both JSON and plain text formats.
        Plain text format: 'FuncName @ HexAddr' per line.
        JSON format: dict with 'references' or 'callers'/'callees' list."""
        addrs = []
        if not resp:
            return addrs
        if isinstance(resp, dict):
            for ref in resp.get(
                "references", resp.get("callers", resp.get("callees", []))
            ):
                ref_addr = ref.get("address", "") if isinstance(ref, dict) else str(ref)
                ref_addr = ref_addr.replace("0x", "")
                if ref_addr:
                    addrs.append(ref_addr)
        elif isinstance(resp, str):
            # Parse plain text: "FuncName @ HexAddr" per line
            import re

            for line in resp.strip().split("\n"):
                match = re.search(r"@\s*([0-9a-fA-F]+)", line)
                if match:
                    addrs.append(match.group(1))
        return addrs

    def get_callers_callees(func_name_for_lookup):
        """Fetch callers and callees for a function by name."""
        if not func_name_for_lookup:
            return [], []

        callers_resp = ghidra_get(
            "/get_function_callers",
            params={"name": func_name_for_lookup, "program": program, "limit": "20"},
        )
        callees_resp = ghidra_get(
            "/get_function_callees",
            params={"name": func_name_for_lookup, "program": program, "limit": "20"},
        )

        callers = _parse_func_list_response(callers_resp)
        callees = _parse_func_list_response(callees_resp)
        return callers, callees

    def collect(addr, current_depth):
        """Recursively collect functions up to the requested depth."""
        key = f"{program}::{addr}"
        if key in visited or current_depth > depth:
            return
        visited.add(key)

        func = ensure_in_state(addr)
        if not func:
            return

        # Skip thunks and externals
        if func.get("is_thunk") or func.get("is_external"):
            return

        result.append((key, func))

        # Recurse into callers and callees if we haven't hit max depth
        if current_depth < depth:
            func_name_for_lookup = func.get("name", "")
            callers, callees = get_callers_callees(func_name_for_lookup)
            # Callees first (bottom-up ordering)
            for callee_addr in callees:
                collect(callee_addr, current_depth + 1)
            for caller_addr in callers:
                collect(caller_addr, current_depth + 1)

    # Start with the target function
    collect(address, 0)

    # Sort: lowest depth first, callees before callers at same depth
    return result


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def read_module(name):
    """Read a prompt module file."""
    path = MODULE_DIR / name
    if not path.exists():
        print(f"WARNING: Module not found: {path}", file=sys.stderr)
        return f"# Module {name} not found\n"
    return path.read_text(encoding="utf-8")


def _estimate_complexity(completeness):
    """Estimate function complexity from completeness data.

    Returns a tier: 'simple', 'medium', 'complex', or 'massive'.
    Used to gate giant functions into recovery-only mode.
    """
    if not completeness or not isinstance(completeness, dict):
        return "medium"

    breakdown = completeness.get("deduction_breakdown", [])
    fixable_pts = float(completeness.get("fixable_deductions", 0))

    # Count items in key categories from deduction breakdown
    cat_counts = {}
    for d in breakdown:
        cat = d.get("category", "")
        cat_counts[cat] = (
            d.get("count", 0) if isinstance(d.get("count"), (int, float)) else 0
        )

    undefined_vars = cat_counts.get("undefined_variables", 0)
    magic_numbers = cat_counts.get("undocumented_magic_numbers", 0)

    if undefined_vars > 100 or magic_numbers > 50 or fixable_pts > 50:
        return "massive"
    if undefined_vars > 50 or magic_numbers > 25 or fixable_pts > 30:
        return "complex"
    if fixable_pts < 10:
        return "simple"
    return "medium"


def determine_mode(score, deductions=None, completeness=None):
    """Determine processing mode from score.

    >= 100: VERIFY (semantic review only)
    >= 70:  FIX (targeted fixes for specific deductions)
    < 70:   FULL (complete documentation workflow Steps 1-5)
    """
    if score is not None and score >= 100:
        return "VERIFY"
    if score is not None and score >= 70:
        return "FIX"
    return "FULL"


def select_model(mode, user_model=None, provider=None, config_snapshot=None):
    """Auto-select model based on mode and provider, with user override.

    `config_snapshot` is the worker's frozen snapshot. When present, the
    snapshot's per-provider models slice is consulted first — that means
    audit / handoff / recovery passes inside a worker all use the same
    model that was chosen at worker-start, even if the dashboard model
    dropdown moves mid-run.
    """
    if user_model:
        return user_model
    # FULL:recovery, FULL:comments, etc. are sub-modes — use FULL for dashboard lookup
    lookup_mode = "FULL" if str(mode).startswith("FULL:") else mode
    target_provider = provider or AI_PROVIDER

    # Snapshot-first lookup. Only a slice covering the requested provider
    # is captured; if the snapshot doesn't have it (e.g. an unconfigured
    # handoff fired), fall through to the live config like normal.
    if config_snapshot is not None:
        snap_providers = config_snapshot.get("providers") or {}
        snap_entry = snap_providers.get(target_provider) or {}
        snap_models = snap_entry.get("models") or {}
        if snap_models.get(lookup_mode):
            return snap_models[lookup_mode]

    configured_model = get_configured_model(target_provider, lookup_mode)
    if configured_model:
        return configured_model
    raise ValueError(
        f"No model configured for provider '{target_provider}' mode '{str(mode).upper()}'. Set it in the web dashboard."
    )


def _truncate(text, max_chars, label="content"):
    """Truncate text to max_chars with a marker if exceeded."""
    if not text or len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n\n[... {label} truncated at {max_chars} chars ...]"


def _is_error_response(resp):
    """Check if a Ghidra response is an error."""
    if resp is None:
        return True
    if isinstance(resp, dict) and "error" in resp:
        return True
    if isinstance(resp, str) and resp.startswith("Error"):
        return True
    return False


def _variables_for_prompt(variables):
    """Return AI-facing variables with phantom locals omitted by default.

    The raw endpoint intentionally reports stack-frame/decompiler artifacts for
    humans and debugging. Prompting is different: phantom locals are not visible
    in decompiled source and cannot be targeted by set_local_variable_type, so
    showing them in the normal work list mostly creates false work.
    """
    if not isinstance(variables, dict):
        return variables, []

    cleaned = dict(variables)
    locals_in = variables.get("locals")
    omitted = []
    if isinstance(locals_in, list):
        locals_out = []
        for local in locals_in:
            if isinstance(local, dict) and local.get("is_phantom"):
                omitted.append(
                    {
                        "name": local.get("name"),
                        "type": local.get("type"),
                        "storage": local.get("storage"),
                    }
                )
            else:
                locals_out.append(local)
        cleaned["locals"] = locals_out
        cleaned["total_locals"] = len(locals_out)
    if omitted:
        cleaned["omitted_phantom_locals_count"] = len(omitted)
        cleaned["omitted_phantom_locals"] = omitted[:24]
    return cleaned, omitted


def _append_variables_section(sections, variables, *, refresh_note=True):
    sections.append("## Variables (pre-fetched)")
    prompt_vars, omitted = _variables_for_prompt(variables)
    if omitted:
        sections.append(
            f"*Omitted {len(omitted)} phantom local(s) from this AI-facing list. "
            "They exist only as stack-frame/decompiler artifacts, are not visible "
            "in decompiled code, and are not API-settable.*"
        )
    note = (
        "*Variable types may already be resolved by decompiler — check `needs_type` "
        "field before calling `set_local_variable_type`."
    )
    if refresh_note:
        note += " Refresh with `get_function_variables` after any prototype change."
    note += "*"
    sections.append(note)
    sections.append("```json")
    var_str = (
        json.dumps(prompt_vars, indent=None)
        if isinstance(prompt_vars, (dict, list))
        else str(prompt_vars)
    )
    sections.append(var_str)
    sections.append("```")


def _inject_classification_directives(sections, completeness):
    """Inject classification-specific prompt directives to prevent over/under-documentation.

    Addresses:
    - Wrapper/stub over-documentation (MiniMax adding struct layouts to 9-line wrappers)
    - Phantom variable hints (in_EAX etc. should attempt prototype fix)
    """
    classification = completeness.get("classification", "unknown")
    code_lines = completeness.get("code_line_count", 999)
    phantom_count = completeness.get("phantom_count", 0)

    # Wrapper/stub: prevent over-documentation
    if classification in ("wrapper", "stub") or code_lines <= 10:
        sections.append("## ⚠ Classification: Wrapper/Stub Function")
        sections.append("")
        sections.append(
            f"This function is classified as **{classification}** ({code_lines} code lines). "
            "Apply minimal documentation:"
        )
        sections.append(
            "- Plate comment: ≤8 lines — Summary, Parameters, Returns, Source. "
            "Do NOT add Algorithm, Structure Layout, or Special Cases sections."
        )
        sections.append("- Do NOT add disassembly EOL comments or PRE comments.")
        sections.append("- Do NOT create new structs for this function.")
        sections.append(
            "- Focus: correct name, correct prototype, correct types, minimal plate."
        )
        sections.append("")

    # Phantom variable hint
    if phantom_count and phantom_count > 0:
        phantom_names = []
        for var in completeness.get("variables_detail", []):
            if var.get("is_phantom"):
                phantom_names.append(var.get("name", "?"))
        # Also check the variables data if available
        sections.append("## ⚠ Phantom Variables Detected")
        sections.append("")
        sections.append(
            f"This function has **{phantom_count} phantom variable(s)** "
            "(e.g., `in_EAX`, `in_EDX`, `extraout_*`). "
            "Before documenting, attempt `set_function_prototype` to formally declare "
            "them as parameters. If the calling convention doesn't support it, "
            "document them in the plate comment's Special Cases section."
        )
        sections.append("")


def _extract_work_items(completeness):
    """Extract concrete fix targets from completeness evidence into a concise work list."""
    items = []

    # Globals to rename
    globals_list = completeness.get("unrenamed_globals", [])
    if globals_list:
        items.append("### Globals to rename")
        for g in globals_list[:20]:
            items.append(f"- `{g}`")

    # Labels to rename
    labels_list = completeness.get("unrenamed_labels", [])
    if labels_list:
        items.append("### Labels to rename")
        for lb in labels_list[:20]:
            items.append(f"- `{lb}`")

    # Magic numbers — group by type, pre-filter compiler arithmetic
    # Known compiler magic-division constants (multiply-by-reciprocal patterns)
    COMPILER_MAGIC = {
        "0x92492493",
        "0x66666667",
        "0x55555556",
        "0x2AAAAAAB",
        "0x38E38E39",
        "0xCCCCCCCD",
        "0xAAAAAAAB",
        "0x24924925",
        "0x51EB851F",
        "0x0CCCCCCD",
        "0x80000000",
        "0x7FFFFFFF",
    }
    magic_list = completeness.get("undocumented_magic_numbers", [])
    if magic_list:
        struct_offsets = []
        constants = []
        for m in magic_list[:30]:
            m_str = str(m)
            # Extract the hex value from "0xNN at addr" format
            hex_val = (
                m_str.split(" at ")[0].strip().upper()
                if " at " in m_str
                else m_str.strip().upper()
            )
            # Skip known compiler magic-division constants
            if hex_val in COMPILER_MAGIC:
                continue
            # Also skip shift amounts commonly paired with magic division (0x1F, 0x1E, 0x1D)
            if (
                hex_val in ("0X1F", "0X1E", "0X1D", "0X1C", "0X1B")
                and "sar" in m_str.lower()
            ):
                continue
            if any(prefix in m_str.lower() for prefix in ["+0x", "offset"]):
                struct_offsets.append(m_str)
            else:
                constants.append(m_str)
        if constants:
            items.append("### Magic numbers to document (EOL comments)")
            items.append(
                "*Group by meaning: sentinels, type IDs, flags, sizes. Struct offsets → document in plate comment Structure Layout.*"
            )
            items.append(
                "**BATCH RULE**: Collect ALL addresses below, then submit them in ONE `batch_set_comments` call "
                "with `comment_type='EOL_COMMENT'`. Do NOT call `set_disassembly_comment` individually — "
                "each call wastes a full API turn."
            )
            for c in constants[:20]:
                items.append(f"- `{c}`")
        if struct_offsets:
            items.append(
                "### Struct offsets (document in plate comment Structure Layout)"
            )
            for s in struct_offsets[:15]:
                items.append(f"- `{s}`")

    # Struct accesses — include base pointer hint if parseable
    struct_list = completeness.get("unresolved_struct_accesses", [])
    if struct_list:
        items.append("### Unresolved struct accesses")
        items.append(
            "*Identify which parameter/variable is the base pointer for each offset.*"
        )
        for s in struct_list[:15]:
            items.append(f"- `{s}`")

    # Ordinals to document
    ordinal_list = completeness.get("undocumented_ordinals", [])
    if ordinal_list:
        items.append("### Undocumented ordinals")
        for o in ordinal_list[:10]:
            items.append(f"- `{o}`")

    # Fixable deduction summary (actionable items from the scorer)
    fixable_items = []
    fixable_pts = 0
    for d in completeness.get("deduction_breakdown", []):
        if d.get("fixable", False):
            fixable_pts += d.get("points", 0)
            fixable_items.append(
                f"- {d.get('category', '?')}: ~{d.get('points', 0):.0f}pts ({d.get('count', '?')} items)"
            )
    if fixable_items:
        items.append(f"### Fixable Deductions (~{fixable_pts:.0f}pts)")
        items.extend(fixable_items)

    # Expected unfixable deductions
    structural_pts = 0
    structural_items = []
    for d in completeness.get("deduction_breakdown", []):
        if not d.get("fixable", True):
            structural_pts += d.get("points", 0)
            structural_items.append(
                f"- {d.get('category', '?')}: ~{d.get('points', 0):.0f}pts ({d.get('count', '?')} items)"
            )
    if structural_items:
        ceiling = max(0, 100 - structural_pts)
        items.append(
            f"### Expected Unfixable Deductions (~{structural_pts:.0f}pts, ceiling ~{ceiling:.0f}%)"
        )
        items.append("*Do not attempt to fix these — they are structural.*")
        items.extend(structural_items)

    if not items:
        return None
    return "\n".join(items)


def build_fix_prompt(func_name, address, ghidra_data, program=None):
    """Assemble a fix-mode prompt from modules + inline data."""
    sections = [read_module("core.md"), ""]

    # Inject known module prefixes
    prefixes_block = _load_prefixes_block()
    if prefixes_block:
        sections.append(prefixes_block)

    # Fix #1 + #6: Program path up front
    sections.append("## Current State")
    if program:
        sections.append(f"Program: {program}")
    sections.append(f"Function: {func_name} at 0x{address}")
    sections.append("")

    sections.append(
        f"## Decompiled Source ({program or 'unknown program'}, pre-fetched, do NOT re-fetch)"
    )
    sections.append("```")
    decomp = ghidra_data.get("decompiled")
    if decomp and not _is_error_response(decomp):
        sections.append(str(decomp))
    else:
        sections.append(f"ERROR: decompilation failed: {decomp}")
    sections.append("```")
    sections.append("")

    variables = ghidra_data.get("variables")
    if variables and not _is_error_response(variables):
        _append_variables_section(sections, variables, refresh_note=True)
    elif variables:
        sections.append(
            f"## Variables: FETCH FAILED — call `get_function_variables` in Step 3"
        )
    sections.append("")

    completeness = ghidra_data.get("completeness")
    sections.append("## Completeness Analysis")
    if completeness and not _is_error_response(completeness):
        sections.append("```json")
        # Build set of unfixable deduction categories
        unfixable_cats = set()
        for d in completeness.get("deduction_breakdown", []):
            if not d.get("fixable", True):
                unfixable_cats.add(d.get("category", ""))
        # Strip estimated_gain from remediation actions whose category is unfixable
        remediation = completeness.get("remediation_actions", [])
        if remediation and unfixable_cats:
            cleaned = []
            for action in remediation:
                if isinstance(action, dict):
                    issue_type = action.get("issue_type", "")
                    if issue_type in unfixable_cats or any(
                        uc in issue_type for uc in unfixable_cats
                    ):
                        action = dict(action)
                        action["estimated_gain"] = 0
                        action["note"] = "structural/unfixable"
                    cleaned.append(action)
                else:
                    cleaned.append(action)
            remediation = cleaned
        trimmed = {
            "function_name": completeness.get("function_name"),
            "completeness_score": completeness.get("completeness_score"),
            "effective_score": completeness.get("effective_score"),
            "deduction_breakdown": completeness.get("deduction_breakdown"),
            "remediation_actions": remediation,
        }
        sections.append(json.dumps(trimmed, indent=None))
        sections.append("```")
    else:
        sections.append(
            f"FETCH FAILED: {completeness} — call `analyze_function_completeness` first"
        )
    sections.append("")

    # Exact work items: extract concrete targets from completeness evidence
    if completeness and not _is_error_response(completeness):
        work_items = _extract_work_items(completeness)
        if work_items:
            sections.append("## Exact Work Items (apply these specific corrections)")
            sections.append("")
            sections.append(work_items)
            sections.append("")

    # Fix #4: Already lazy-loading in FIX mode
    included = set()
    for cat in ghidra_data["fixable_categories"]:
        mod_file = CATEGORY_TO_MODULE.get(cat)
        if mod_file and mod_file not in included:
            sections.append(read_module(mod_file))
            sections.append("")
            included.add(mod_file)

    sections.append("## Opportunistic Checks (while you're here)")
    sections.append("")
    sections.append(
        "While applying the fixes above, also check these. Fix if you spot a clear issue; skip if fine."
    )
    sections.append("")
    sections.append(
        "- **Function name**: Does it accurately describe behavior? Is it missing a module prefix it should have (check Source: line, callee family, behavior domain — 2+ signals = must prefix)? If rename needed, `rename_function_by_address` with the full prefixed name."
    )
    sections.append(
        "- **Prototype**: Are parameter types correct? Is calling convention right? If wrong, `set_function_prototype`."
    )
    sections.append(
        "- **Plate comment**: Is it missing sections (Algorithm, Parameters, Returns, Source)? Is the summary accurate? If issues, update via `batch_set_comments`."
    )
    sections.append(
        "- **Variable names**: Any obviously wrong Hungarian prefixes on already-typed variables? Fix via `rename_variables`."
    )
    sections.append(
        "- **Consistency**: If function was renamed, does the plate comment summary/returns/parameters still match the new name? Stale terminology in plate comments is a fixable issue."
    )
    sections.append("")

    sections.append("## Instructions")
    if program:
        sections.append(f"All tool calls should use `program` = `{program}`.")
    sections.append(
        "1. **Types and structs first.** If `unresolved_struct_accesses`, `undefined_variables`, or `hungarian_notation_violations` "
        "appear in the work items, resolve ALL of them BEFORE writing or updating any plate comment or inline comments. "
        "Better types improve the decompilation for everyone — comments only help at the point they're written."
    )
    sections.append("2. Apply remaining fixes from the recipes above.")
    sections.append("3. Check the opportunistic items and fix anything clearly wrong.")
    sections.append(
        "4. Report DONE with consistency status. Scoring is handled externally."
    )

    return "\n".join(sections)


def build_full_doc_prompt(func_name, address, ghidra_data, program=None):
    """Assemble a full documentation prompt from modules + inline data."""
    sections = [read_module("core.md"), ""]

    # Inject known module prefixes
    prefixes_block = _load_prefixes_block()
    if prefixes_block:
        sections.append(prefixes_block)

    # Fix #1 + #6: Program path up front
    sections.append("## Target Function")
    if program:
        sections.append(f"Program: {program}")
    sections.append(f"Function: {func_name} at 0x{address}")
    sections.append("")

    # Fix #5 + #6: Flag failed pre-fetches clearly, no contradiction
    afd = ghidra_data.get("analyze_for_doc")
    if afd and not _is_error_response(afd):
        sections.append("## Full Analysis (pre-fetched, do NOT re-fetch)")
        sections.append("```")
        # Strip remediation_actions (already extracted into work items section)
        if isinstance(afd, dict):
            afd_trimmed = {k: v for k, v in afd.items() if k != "remediation_actions"}
            afd_str = json.dumps(afd_trimmed, indent=2)
        else:
            afd_str = str(afd)
        sections.append(afd_str)
        sections.append("```")
    elif afd:
        sections.append("## Full Analysis: FETCH FAILED")
        sections.append(
            f"Error: {json.dumps(afd) if isinstance(afd, dict) else str(afd)}"
        )
        sections.append(
            "Call `analyze_for_documentation` in Step 1. Decompiled source is still provided inline below."
        )
    sections.append("")

    sections.append(
        f"## Decompiled Source ({program or 'unknown program'}, pre-fetched, do NOT re-fetch)"
    )
    sections.append("```")
    decomp = ghidra_data.get("decompiled")
    if decomp and not _is_error_response(decomp):
        sections.append(str(decomp))
    else:
        sections.append(f"ERROR: decompilation failed: {decomp}")
    sections.append("```")
    sections.append("")

    # Fix #7: Variable staleness warning
    variables = ghidra_data.get("variables")
    if variables and not _is_error_response(variables):
        _append_variables_section(sections, variables, refresh_note=True)
    elif variables:
        sections.append(
            "## Variables: FETCH FAILED — call `get_function_variables` in Step 3"
        )
    sections.append("")

    # Exact work items from completeness evidence
    completeness = ghidra_data.get("completeness")
    if completeness and not _is_error_response(completeness):
        work_items = _extract_work_items(completeness)
        if work_items:
            sections.append("## Exact Work Items (apply these specific corrections)")
            sections.append("")
            sections.append(work_items)
            sections.append("")

    # Classification-based directives
    if completeness and not _is_error_response(completeness):
        _inject_classification_directives(sections, completeness)

    # Step modules
    for step in [
        "step-classify.md",
        "step-prototype.md",
        "step-type-audit.md",
        "step-comments.md",
        "step-verify.md",
    ]:
        sections.append(read_module(step))
        sections.append("")

    # Fix #4: Lazy-load only fix modules matching actual deductions (was: all modules every time)
    fixable_categories = ghidra_data.get("fixable_categories", [])
    included = set()
    for cat in fixable_categories:
        mod_file = CATEGORY_TO_MODULE.get(cat)
        if mod_file and mod_file not in included:
            included.add(mod_file)

    if included:
        sections.append("---")
        sections.append(
            "## Remediation Recipes (reference for fixing specific deduction categories)"
        )
        sections.append("")
        for mod_file in sorted(included):
            sections.append(read_module(mod_file))
            sections.append("")
    else:
        sections.append("---")
        sections.append(
            "## Remediation Recipes: none needed (no fixable deductions detected)"
        )
        sections.append("")

    sections.append("## Instructions")
    if program:
        sections.append(f"All tool calls should use `program` = `{program}`.")
    sections.append(
        "Document the function above following Steps 1-4, then report DONE in Step 5."
    )
    sections.append("All analysis data is provided inline - do NOT re-fetch it.")
    sections.append("Report: DONE: FunctionName, Changes: [summary], Score: N%")
    sections.append("")

    return "\n".join(sections)


def build_recovery_prompt(func_name, address, ghidra_data, program=None):
    """Build pass-1 prompt for complex functions: type/struct recovery only, no comments.

    This is the first half of a two-pass workflow for high-complexity functions.
    It includes classify, prototype, and type-audit steps plus struct/type fix modules,
    but explicitly excludes comment steps and plate comment modules.
    """
    sections = [read_module("core.md"), ""]

    prefixes_block = _load_prefixes_block()
    if prefixes_block:
        sections.append(prefixes_block)

    sections.append("## Target Function (Recovery Pass — types and structs only)")
    if program:
        sections.append(f"Program: {program}")
    sections.append(f"Function: {func_name} at 0x{address}")
    sections.append("")

    # Full analysis
    afd = ghidra_data.get("analyze_for_doc")
    if afd and not _is_error_response(afd):
        sections.append("## Full Analysis (pre-fetched, do NOT re-fetch)")
        sections.append("```")
        if isinstance(afd, dict):
            afd_trimmed = {k: v for k, v in afd.items() if k != "remediation_actions"}
            afd_str = json.dumps(afd_trimmed, indent=2)
        else:
            afd_str = str(afd)
        sections.append(afd_str)
        sections.append("```")
    sections.append("")

    # Decompiled source
    sections.append(
        f"## Decompiled Source ({program or 'unknown program'}, pre-fetched, do NOT re-fetch)"
    )
    sections.append("```")
    decomp = ghidra_data.get("decompiled")
    if decomp and not _is_error_response(decomp):
        sections.append(str(decomp))
    else:
        sections.append(f"ERROR: decompilation failed: {decomp}")
    sections.append("```")
    sections.append("")

    # Variables
    variables = ghidra_data.get("variables")
    if variables and not _is_error_response(variables):
        _append_variables_section(sections, variables, refresh_note=False)
    sections.append("")

    # Work items
    completeness = ghidra_data.get("completeness")
    if completeness and not _is_error_response(completeness):
        work_items = _extract_work_items(completeness)
        if work_items:
            sections.append("## Exact Work Items (apply these specific corrections)")
            sections.append("")
            sections.append(work_items)
            sections.append("")

    # Classification-based directives
    if completeness and not _is_error_response(completeness):
        _inject_classification_directives(sections, completeness)

    # Only structural steps — no comment steps
    for step in ["step-classify.md", "step-prototype.md", "step-type-audit.md"]:
        sections.append(read_module(step))
        sections.append("")

    # Only type/struct fix modules
    RECOVERY_CATEGORIES = {
        "unresolved_struct_accesses",
        "undefined_variables",
        "hungarian_notation_violations",
        "missing_prototype",
        "return_type_unresolved",
        "address_suffix_name",
    }
    fixable_categories = ghidra_data.get("fixable_categories", [])
    included = set()
    for cat in fixable_categories:
        if cat in RECOVERY_CATEGORIES:
            mod_file = CATEGORY_TO_MODULE.get(cat)
            if mod_file and mod_file not in included:
                included.add(mod_file)

    if included:
        sections.append("---")
        sections.append("## Remediation Recipes (type/struct recovery only)")
        sections.append("")
        for mod_file in sorted(included):
            sections.append(read_module(mod_file))
            sections.append("")

    sections.append("## Instructions — Recovery Pass")
    if program:
        sections.append(f"All tool calls should use `program` = `{program}`.")
    sections.append("This is pass 1 of 2 for a complex function. Focus ONLY on:")
    sections.append("1. Classify and verify function boundaries (Step 1)")
    sections.append(
        "2. Set correct function name and prototype with caller verification (Step 2)"
    )
    sections.append(
        "3. Resolve ALL undefined types, Hungarian violations, and struct accesses (Step 3)"
    )
    sections.append("")
    sections.append(
        "Do NOT write plate comments, inline comments, or rename globals/labels in this pass."
    )
    sections.append("A second pass will handle comments after types are stable.")
    sections.append("")
    sections.append(
        "Report: DONE: FunctionName, Changes: [type/struct changes applied]"
    )
    sections.append("")

    return "\n".join(sections)


def build_verify_prompt(func_name, address, ghidra_data, program=None):
    """Assemble a verify-mode prompt."""
    sections = []
    sections.append("Quick semantic review of a fully-documented function in Ghidra.")
    sections.append(
        "This function scored 100% on structural completeness. Verify the documentation is semantically correct - do not redo it."
    )
    if program:
        sections.append(f"Program: {program}")
        sections.append(f"All tool calls should use `program` = `{program}`.")
    sections.append("")
    sections.append(f"## Decompiled Source ({program or 'unknown program'})")
    sections.append("```")
    sections.append(
        str(ghidra_data.get("decompiled") or "ERROR: decompilation unavailable")
    )
    sections.append("```")
    sections.append("")
    sections.append("Check:")
    sections.append("")
    sections.append(
        "1. Name accuracy: Does the PascalCase verb-first name describe what the function ACTUALLY does?"
    )
    sections.append(
        "2. Hungarian prefix consistency: Do prefixes match types? (p=pointer, dw=uint, n=int, b=byte, f=bool, sz=char*, w=ushort)"
    )
    sections.append(
        "3. Plate comment accuracy: Does the one-line summary match the decompiled behavior?"
    )
    sections.append(
        "4. Quick fixes: If obvious issues found, fix directly using rename_function_by_address, rename_variables, or batch_set_comments."
    )
    sections.append("")
    sections.append("Report one of:")
    sections.append("- VERIFIED OK: FunctionName - no issues found")
    sections.append("- QUICK FIX: FunctionName - what you fixed")
    sections.append(
        "- NEEDS REDO: FunctionName - reason (do NOT attempt a full redo, just flag it)"
    )

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# AI CLI invocation (Claude or Codex)
# ---------------------------------------------------------------------------


def _find_cli(name):
    """Find a CLI executable by name."""
    import shutil

    path = shutil.which(name)
    if path:
        return path
    # Common Windows locations
    for candidate in [
        os.path.expanduser(f"~/.claude/local/{name}.exe"),
        os.path.expanduser(f"~/AppData/Roaming/npm/{name}.cmd"),
        os.path.expanduser(f"~/AppData/Local/npm/{name}.cmd"),
    ]:
        if os.path.exists(candidate):
            return candidate
    return None


def find_claude_cli():
    return _find_cli("claude")


def _wrap_result(result):
    """Normalize AI provider return to (text, metadata) tuple."""
    if isinstance(result, tuple):
        return result
    return (
        result,
        {"tool_calls": -1, "tool_calls_known": False},
    )  # -1 = unknown (provider doesn't track)


def _provider_timeout_seconds(provider, complexity_tier=None):
    env_key = f"FUNDOC_{str(provider or AI_PROVIDER).upper()}_TIMEOUT_SECS"
    raw_timeout = os.environ.get(env_key) or os.environ.get(
        "FUNDOC_PROVIDER_TIMEOUT_SECS", "900"
    )
    try:
        timeout_secs = max(60, int(raw_timeout))
    except (TypeError, ValueError):
        timeout_secs = 900

    if complexity_tier == "massive":
        timeout_secs += 600
    elif complexity_tier == "complex":
        timeout_secs += 300
    return timeout_secs


def _terminate_process_tree(pid):
    if not pid:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return

    try:
        import signal

        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass


# Registry mapping worker_id -> set of live multiprocessing.Process objects.
# The stall watchdog in WorkerManager uses this to kill the actual spawned
# provider subprocesses when a worker thread has been wedged past the stall
# threshold. Without this, setting stop_flag alone cannot unwedge a thread
# blocked inside _invoke_provider_with_watchdog's result_queue.get().
_subprocess_registry_lock = threading.Lock()
_subprocess_registry: dict = {}


def register_worker_subprocess(worker_id, proc):
    if not worker_id or proc is None:
        return
    with _subprocess_registry_lock:
        _subprocess_registry.setdefault(worker_id, set()).add(proc)


def unregister_worker_subprocess(worker_id, proc):
    if not worker_id or proc is None:
        return
    with _subprocess_registry_lock:
        procs = _subprocess_registry.get(worker_id)
        if procs is not None:
            procs.discard(proc)
            if not procs:
                _subprocess_registry.pop(worker_id, None)


def kill_worker_subprocesses(worker_id):
    """Force-terminate every live subprocess tied to worker_id.

    Returns the count of processes killed. Safe to call even if the
    worker has no live subprocesses.
    """
    if not worker_id:
        return 0
    with _subprocess_registry_lock:
        procs = list(_subprocess_registry.get(worker_id, []))
    killed = 0
    for p in procs:
        try:
            if p.is_alive():
                _terminate_process_tree(p.pid)
                killed += 1
        except Exception:
            pass
    return killed


def _tool_error_preview(result, limit=500):
    """Return a compact error string from a tool result, if one is present."""
    if result is None:
        return None
    if isinstance(result, str):
        result_str = result
    else:
        result_str = str(result)
    try:
        parsed = json.loads(result_str)
        if isinstance(parsed, dict):
            for key in ("error", "message", "status"):
                value = parsed.get(key)
                if value and (key == "error" or parsed.get("status") == "error"):
                    text = str(value)
                    return text[:limit]
    except Exception:
        pass
    if '"error"' in result_str[:100] or result_str.lower().startswith("error"):
        return result_str[:limit]
    return None


def _invoke_provider_direct(
    prompt, model=None, max_turns=25, provider=None, complexity_tier=None
):
    effective_provider = provider or AI_PROVIDER
    selected_model = _require_model_name(model, effective_provider)

    # Pre-call quota-pause gate (Q1 + Q9): if (provider, model) is currently
    # walled, short-circuit before hitting the API. Synthesize a quota_paused
    # result so the caller can log it and the worker can pause.
    from provider_pause import (
        detect_quota_wall,
        get_default_manager,
        QUOTA_PAUSE_THRESHOLD_SECONDS,
    )

    pause_mgr = get_default_manager()
    paused_until = pause_mgr.wait_until(effective_provider, selected_model)
    if paused_until is not None:
        reason = pause_mgr.reason(effective_provider, selected_model) or "quota wall"
        print(
            f"  [{effective_provider}] quota wall active — paused until "
            f"{paused_until.isoformat()} ({reason})",
            flush=True,
        )
        return (
            None,
            {
                "tool_calls": 0,
                "tool_calls_known": True,
                "provider_error": f"quota_paused: {reason}",
                "provider_error_type": "QuotaPaused",
                "quota_paused": True,
                "quota_paused_until": paused_until.isoformat(),
                "quota_paused_reason": reason,
            },
        )

    if effective_provider == "minimax":
        result = _invoke_minimax(
            prompt, selected_model, max_turns, complexity_tier=complexity_tier
        )
    elif effective_provider == "codex":
        result = _wrap_result(_invoke_codex(prompt, selected_model, max_turns))
    elif effective_provider == "gemini":
        # Gemini's wrapper already integrates quota-wall detection inline so
        # it can break out of its retry loop — return its result directly.
        return _invoke_gemini(prompt, selected_model, max_turns)
    else:
        result = _wrap_result(_invoke_claude(prompt, selected_model, max_turns))

    # Post-call detection (Q6) for claude/codex/minimax: if the call returned
    # an error string, run the per-provider detector. Above-threshold matches
    # install a pause so the next worker on the same model short-circuits.
    text, meta = result
    err_str = (meta or {}).get("provider_error") or ""
    http_status = (meta or {}).get("provider_http_status")
    if err_str:
        wall = detect_quota_wall(effective_provider, err_str, http_status=http_status)
        if wall is not None and wall.raw_seconds >= QUOTA_PAUSE_THRESHOLD_SECONDS:
            until = pause_mgr.install(effective_provider, selected_model, wall)
            print(
                f"  [{effective_provider}] quota wall — paused until "
                f"{until.isoformat()} ({wall.reason})",
                flush=True,
            )
            meta = dict(meta or {})
            meta["provider_error_type"] = "QuotaPaused"
            meta["quota_paused"] = True
            meta["quota_paused_until"] = until.isoformat()
            meta["quota_paused_reason"] = wall.reason
            return (text, meta)

    return result


def _restore_debug_context_for_worker(debug_ctx=None, log_dir=None):
    """Restore parent debug logging state inside a spawned provider worker."""
    global LOG_DIR
    if log_dir:
        LOG_DIR = Path(log_dir)
    if debug_ctx:
        _debug_ctx.set(dict(debug_ctx))


def _provider_worker_entry(
    result_queue,
    prompt,
    model,
    max_turns,
    provider,
    complexity_tier,
    debug_ctx=None,
    log_dir=None,
    events_queue=None,
    worker_id=None,
):
    _restore_debug_context_for_worker(debug_ctx, log_dir)
    # Wire up cross-process event propagation. Every bus_emit in this
    # subprocess will now be put on events_queue; the parent drains
    # and re-emits on its own bus so the dashboard bridge forwards
    # tool_call/tool_result to SocketIO.
    if events_queue is not None:
        try:
            from event_bus import set_cross_process_queue

            set_cross_process_queue(events_queue, worker_id=worker_id)
        except Exception:
            pass
    try:
        result_queue.put(
            {
                "ok": True,
                "result": _invoke_provider_direct(
                    prompt,
                    model=model,
                    max_turns=max_turns,
                    provider=provider,
                    complexity_tier=complexity_tier,
                ),
            }
        )
    except Exception as exc:
        result_queue.put(
            {
                "ok": False,
                "error": repr(exc),
                "error_type": type(exc).__name__,
                "traceback": traceback.format_exc(),
            }
        )


def _invoke_provider_with_watchdog(
    prompt, model=None, max_turns=25, provider=None, complexity_tier=None
):
    effective_provider = provider or AI_PROVIDER
    timeout_secs = _provider_timeout_seconds(effective_provider, complexity_tier)
    debug_ctx = dict(_debug_ctx.get())
    ctx = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue(maxsize=1)

    # Cross-process event queue: the subprocess's bus_emit pushes events
    # here; a drain thread in this (parent) process reads and re-emits
    # them on the parent bus. Bounded size prevents memory blow-up if
    # the drain thread can't keep up with a chatty provider; put_nowait
    # drops on full so the subprocess never blocks.
    events_queue = ctx.Queue(maxsize=10000)
    drain_stop = threading.Event()
    parent_worker_id = get_worker_id()

    def _drain_events():
        # Stops when the stop flag is set AND the queue is fully drained.
        # Emits on the parent's bus so the dashboard bridge forwards to
        # SocketIO. Each event from the subprocess already carries
        # worker_id (pinned via set_cross_process_queue), so the event
        # shape matches what in-process emits produce.
        while not drain_stop.is_set():
            try:
                event = events_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            except (ValueError, OSError):
                # Queue was closed under us — nothing more to drain.
                return
            try:
                event_type, data = event
                get_bus().emit(event_type, data)
            except Exception:
                pass  # never let one bad event kill the drain loop
        # Final drain after stop signal — flush whatever the subprocess
        # emitted right before exit.
        try:
            while True:
                event_type, data = events_queue.get_nowait()
                try:
                    get_bus().emit(event_type, data)
                except Exception:
                    pass
        except (queue.Empty, ValueError, OSError):
            pass

    drain_thread = threading.Thread(
        target=_drain_events, daemon=True, name=f"event-drain-{effective_provider}"
    )
    drain_thread.start()

    worker = ctx.Process(
        target=_provider_worker_entry,
        args=(
            result_queue,
            prompt,
            model,
            max_turns,
            effective_provider,
            complexity_tier,
            debug_ctx,
            str(LOG_DIR),
            events_queue,
            parent_worker_id,
        ),
    )
    worker.start()
    # Register with the stall-watchdog so it can force-kill this subprocess
    # when the parent worker thread has been wedged past the threshold.
    register_worker_subprocess(parent_worker_id, worker)

    result_msg = None
    deadline = time.time() + timeout_secs
    try:
        while time.time() < deadline:
            try:
                result_msg = result_queue.get(timeout=1)
                break
            except queue.Empty:
                if not worker.is_alive():
                    break

        if result_msg is None and worker.is_alive():
            timeout_message = (
                f"{effective_provider} session hard timeout after {timeout_secs}s"
            )
            print(
                f"  [{effective_provider}] hard timeout after {timeout_secs}s — terminating stalled session",
                flush=True,
            )
            bus_emit(
                "provider_timeout",
                {
                    "provider": effective_provider,
                    "timeout_secs": timeout_secs,
                    "message": timeout_message,
                    "session_killed": True,
                },
            )
            _terminate_process_tree(worker.pid)
            worker.join(timeout=10)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=5)
            return (
                f"BLOCKED: {timeout_message}",
                {
                    "tool_calls": 0,
                    "tool_calls_known": True,
                    "timed_out": True,
                    "timeout_provider": effective_provider,
                    "timeout_secs": timeout_secs,
                },
            )

        worker.join(timeout=5)
        if result_msg is None:
            if worker.exitcode not in (0, None):
                print(
                    f"ERROR: {effective_provider} worker exited with code {worker.exitcode}",
                    flush=True,
                )
            return (None, {"tool_calls": 0, "tool_calls_known": True})

        if not result_msg.get("ok"):
            tb = result_msg.get("traceback")
            print(
                f"ERROR: {effective_provider} worker failed: {result_msg.get('error')}",
                flush=True,
            )
            if tb:
                print(tb.rstrip(), flush=True)
            return (
                None,
                {
                    "tool_calls": 0,
                    "tool_calls_known": True,
                    "provider_error": result_msg.get("error"),
                    "provider_error_type": result_msg.get("error_type"),
                    "provider_traceback": tb,
                },
            )

        return _wrap_result(result_msg.get("result"))
    finally:
        try:
            result_queue.close()
            result_queue.join_thread()
        except Exception:
            pass
        if worker.is_alive():
            _terminate_process_tree(worker.pid)
            worker.join(timeout=5)
        unregister_worker_subprocess(parent_worker_id, worker)
        # Stop the drain thread and close the events queue. The drain
        # loop does a final flush before exiting so no events-on-the-wire
        # get dropped between the subprocess's last emit and shutdown.
        # Order matters: join the drain thread BEFORE closing the queue,
        # otherwise the final get_nowait() flush races with close() and
        # raises ValueError: Queue is closed.
        drain_stop.set()
        drain_thread.join(timeout=2)
        try:
            events_queue.close()
            events_queue.join_thread()
        except Exception:
            pass


def invoke_claude(
    prompt, model=None, max_turns=25, provider=None, complexity_tier=None
):
    """Invoke the configured AI provider."""
    return _invoke_provider_with_watchdog(
        prompt,
        model=model,
        max_turns=max_turns,
        provider=provider,
        complexity_tier=complexity_tier,
    )


def _invoke_codex(prompt, model=None, max_turns=25):
    """Invoke Codex via the Python SDK with MCP tool support."""
    import asyncio

    model = _require_model_name(model, "codex")

    try:
        from openai_codex_sdk import Codex
        from openai_codex_sdk.types import CodexOptions, ThreadOptions
    except ImportError:
        print(
            "ERROR: openai-codex-sdk not installed. Run: pip install openai-codex-sdk",
            file=sys.stderr,
        )
        return None

    # Sanitize prompt
    prompt = prompt.encode("ascii", errors="replace").decode("ascii")

    codex_path = _find_cli("codex")

    async def run():
        options = (
            CodexOptions(codex_path_override=codex_path)
            if codex_path
            else CodexOptions()
        )
        codex = Codex(options=options)
        thread_opts = ThreadOptions(
            model=model,
            working_directory=str(REPO_ROOT),
        )
        thread = codex.start_thread(options=thread_opts)

        # Use streamed mode to show progress
        streamed = await thread.run_streamed(prompt)
        output_parts = []
        tool_call_count = 0
        async for event in streamed.events:
            event_type = getattr(event, "type", "")
            if event_type == "item.completed":
                item = event.item
                item_type = type(item).__name__
                if item_type == "AgentMessageItem":
                    text = getattr(item, "text", getattr(item, "content", str(item)))
                    print(text)
                    output_parts.append(str(text))
                elif item_type == "McpToolCallItem":
                    tool_call_count += 1
                    tool = getattr(
                        item,
                        "tool",
                        getattr(item, "tool_name", getattr(item, "name", "?")),
                    )
                    normalized_tool = _normalize_tool_name(tool)
                    server = getattr(item, "server", "")
                    raw_status = getattr(item, "status", "?")
                    status = "error" if raw_status in ("failed", "error") else "success"

                    # Best-effort args/result extraction. Codex SDK item shapes
                    # vary by version, so try a few common attribute names.
                    args = (
                        getattr(item, "arguments", None)
                        or getattr(item, "args", None)
                        or getattr(item, "input", None)
                        or {}
                    )
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except (json.JSONDecodeError, ValueError):
                            pass
                    result_obj = (
                        getattr(item, "result", None)
                        or getattr(item, "output", None)
                        or getattr(item, "response", None)
                    )
                    if result_obj is not None and hasattr(result_obj, "content"):
                        result_obj = result_obj.content
                    error_preview = (
                        _tool_error_preview(result_obj) if status == "error" else None
                    )
                    print(f"  [mcp] {normalized_tool}: calling", flush=True)
                    print(
                        f"  [mcp] {normalized_tool}: {status}"
                        + (f" - {error_preview}" if error_preview else ""),
                        flush=True,
                    )
                    bus_emit(
                        "tool_call",
                        {
                            "tool": normalized_tool,
                            "raw_tool": tool,
                            "status": "calling",
                        },
                    )
                    payload = {
                        "tool": normalized_tool,
                        "raw_tool": tool,
                        "status": status,
                    }
                    if error_preview:
                        payload["error"] = error_preview
                    bus_emit("tool_result", payload)
                    # Codex doesn't expose start/end times on the item, leave duration None
                    _debug_log_tool_call(tool, args, result_obj, status, None)
            elif event_type == "turn.completed":
                usage = getattr(event, "usage", None)
                if usage:
                    tokens = getattr(usage, "total_tokens", "?")
                    print(f"  [tokens: {tokens}]", flush=True)

        return (
            "\n".join(output_parts) if output_parts else None,
            {"tool_calls": tool_call_count, "tool_calls_known": True},
        )

    # Retry transient Codex CLI crashes (exit code 1 with "Reading prompt from stdin")
    last_err = None
    for _attempt in range(3):
        try:
            return asyncio.run(run())
        except Exception as e:
            last_err = e
            err_str = str(e)
            if "exited with code" in err_str and _attempt < 2:
                wait = (2**_attempt) * 5  # 5s, 10s
                print(
                    f"  [codex] transient failure (attempt {_attempt + 1}/3), "
                    f"retrying in {wait}s: {err_str[:120]}",
                    flush=True,
                )
                time.sleep(wait)
            else:
                break
    print(f"ERROR: Codex SDK failed: {last_err}", file=sys.stderr)
    return None


def _invoke_gemini(prompt, model=None, max_turns=25):
    """Invoke Gemini via the gemini-cli-sdk with native MCP tool support."""
    import asyncio

    model = _require_model_name(model, "gemini")

    try:
        from gemini_cli_sdk import GeminiCli, GeminiOptions
        from gemini_cli_sdk.events import (
            InitEvent,
            MessageEvent,
            ToolUseEvent,
            ToolResultEvent,
            ErrorEvent,
            ResultEvent,
        )
    except ImportError:
        print(
            "ERROR: gemini-cli-sdk not installed. Run: pip install gemini-cli-sdk",
            file=sys.stderr,
        )
        return None

    # Sanitize prompt
    prompt = prompt.encode("ascii", errors="replace").decode("ascii")

    async def run():
        options = GeminiOptions(
            model=model,
            approval_mode="yolo",
            allowed_mcp_servers=["ghidra-mcp"],
            cwd=str(SCRIPT_DIR),
            timeout=600.0,
        )
        cli = GeminiCli(options)

        output_parts = []
        tool_call_count = 0
        event_count = 0
        fatal_error_message = None
        bus_emit(
            "provider_turn",
            {
                "provider": "gemini",
                "model": model,
                "status": "request_start",
                "max_turns": max_turns,
            },
        )

        async for event in cli.run(prompt):
            event_count += 1
            if isinstance(event, InitEvent):
                print(
                    f"  [gemini] session={event.session_id} model={event.model}",
                    flush=True,
                )
                bus_emit(
                    "provider_turn",
                    {
                        "provider": "gemini",
                        "model": event.model,
                        "status": "session_start",
                        "session_id": event.session_id,
                    },
                )
            elif isinstance(event, MessageEvent):
                if event.role == "assistant" and event.content:
                    print(event.content)
                    output_parts.append(event.content)
            elif isinstance(event, ToolUseEvent):
                tool_call_count += 1
                short_name = _normalize_tool_name(event.name)
                print(f"  [mcp] {short_name}: calling", flush=True)
                bus_emit(
                    "tool_call",
                    {"tool": short_name, "raw_tool": event.name, "status": "calling"},
                )
                _debug_log_tool_call(event.name, event.arguments, None, "calling", None)
            elif isinstance(event, ToolResultEvent):
                status = "error" if event.is_error else "success"
                short_name = _normalize_tool_name(event.name)
                print(f"  [mcp] {short_name}: {status}", flush=True)
                error_preview = (
                    _tool_error_preview(event.output) if event.is_error else None
                )
                bus_emit(
                    "tool_result",
                    {
                        "tool": short_name,
                        "raw_tool": event.name,
                        "status": status,
                        **({"error": error_preview} if error_preview else {}),
                    },
                )
                _debug_log_tool_call(event.name, {}, event.output, status, None)
            elif isinstance(event, ErrorEvent):
                print(f"  [gemini error] {event.message}", flush=True)
                bus_emit(
                    "provider_turn",
                    {
                        "provider": "gemini",
                        "model": model,
                        "status": "error",
                        "fatal": bool(event.fatal),
                        "error": str(event.message)[:300],
                    },
                )
                if event.fatal:
                    fatal_error_message = str(event.message)
                    break
            elif isinstance(event, ResultEvent):
                if event.response:
                    output_parts.append(event.response)
                if event.input_tokens or event.output_tokens:
                    print(
                        f"  [tokens: in={event.input_tokens} out={event.output_tokens}]",
                        flush=True,
                    )
                bus_emit(
                    "provider_turn",
                    {
                        "provider": "gemini",
                        "model": model,
                        "status": "result",
                        "tool_calls_so_far": tool_call_count,
                        "input_tokens": event.input_tokens,
                        "output_tokens": event.output_tokens,
                    },
                )

        text = "\n".join(output_parts) if output_parts else None
        bus_emit(
            "provider_turn",
            {
                "provider": "gemini",
                "model": model,
                "status": "complete",
                "events": event_count,
                "tool_calls": tool_call_count,
                "has_output": bool(text),
            },
        )
        if not text and event_count == 0:
            print(
                "  [gemini] WARNING: CLI produced 0 events — session may have "
                "failed to start or timed out",
                flush=True,
            )
        elif not text:
            print(
                f"  [gemini] WARNING: {event_count} events but no output text "
                f"(tool_calls={tool_call_count})",
                flush=True,
            )
        if fatal_error_message and tool_call_count == 0 and not text:
            raise RuntimeError(fatal_error_message)
        return (text, {"tool_calls": tool_call_count, "tool_calls_known": True})

    # Retry on transient Gemini capacity/rate-limit errors.
    # Quota walls (Q9: detect on first failure when unambiguous) skip the
    # retry chain entirely and install a pause entry — those retries would
    # just re-discover the same wall in 90s of wasted time.
    from provider_pause import (
        detect_quota_wall,
        get_default_manager,
        QUOTA_PAUSE_THRESHOLD_SECONDS,
    )

    last_err = None
    pause_info = None
    for _attempt in range(3):
        try:
            return asyncio.run(run())
        except Exception as e:
            last_err = e
            err_str = str(e)
            # Q9: unambiguous quota wall -> immediate pause, no retries.
            wall = detect_quota_wall("gemini", err_str)
            if wall and wall.raw_seconds >= QUOTA_PAUSE_THRESHOLD_SECONDS:
                pause_info = wall
                break
            is_transient = any(
                k in err_str
                for k in ("429", "RESOURCE_EXHAUSTED", "capacity", "rateLimitExceeded")
            )
            if is_transient and _attempt < 2:
                wait = (2**_attempt) * 30  # 30s, 60s — longer than CLI's own backoff
                print(
                    f"  [gemini] capacity exhausted (attempt {_attempt + 1}/3), "
                    f"retrying in {wait}s...",
                    flush=True,
                )
                time.sleep(wait)
            else:
                break

    # Quota wall reached: install pause so other workers on this model
    # short-circuit immediately, and surface a "quota_paused" provider_error
    # so the run record & dashboard explain the silence.
    if pause_info is not None:
        until = get_default_manager().install("gemini", model, pause_info)
        print(
            f"  [gemini] quota wall — paused until {until.isoformat()} "
            f"({pause_info.reason})",
            flush=True,
        )
        return (
            None,
            {
                "tool_calls": 0,
                "tool_calls_known": True,
                "provider_error": str(last_err)[:500],
                "provider_error_type": "QuotaPaused",
                "quota_paused": True,
                "quota_paused_until": until.isoformat(),
                "quota_paused_reason": pause_info.reason,
            },
        )

    # Non-quota failure — surface the error so the dashboard/runs.jsonl shows
    # why this run was empty (previously: silent tool_calls=0, output=null).
    err_str_for_log = str(last_err) if last_err is not None else "unknown"
    print(f"ERROR: Gemini CLI failed: {err_str_for_log}", file=sys.stderr)
    return (
        None,
        {
            "tool_calls": 0,
            "tool_calls_known": True,
            "provider_error": err_str_for_log[:500],
            "provider_error_type": (
                type(last_err).__name__ if last_err is not None else "Unknown"
            ),
        },
    )


# Tools MiniMax actually uses for RE documentation (empirically derived from 194
# runs / 8,134 tool calls). Filtering from 171 → 62 tools cuts schema payload
# by ~60%, saving ~20k tokens × every API turn = hundreds of thousands of tokens
# per run. Tools not in this set exist in the Ghidra schema but are never called
# (debugger, emulation, BSim, project-management, etc.).
_MINIMAX_DOC_TOOL_ALLOWLIST = {
    # ── Read / analysis ──────────────────────────────────────────────────
    "decompile_function",
    "disassemble_function",
    "disassemble_bytes",
    "force_decompile",
    "get_function_variables",
    "get_function_signature",
    "get_function_callers",
    "get_function_callees",
    "get_function_by_address",
    "get_function_documentation",
    "get_function_xrefs",
    "get_function_jump_targets",
    "get_plate_comment",
    "get_assembly_context",
    "get_xrefs_from",
    "get_xrefs_to",
    "get_bulk_xrefs",
    "get_struct_layout",
    "get_type_size",
    "get_current_program_info",
    "inspect_memory_content",
    "read_memory",
    "search_data_types",
    "search_functions",
    "search_strings",
    "search_byte_patterns",
    "list_globals",
    "list_functions",
    "list_data_types",
    "list_data_type_categories",
    "list_calling_conventions",
    "list_external_locations",
    "list_bookmarks",
    "validate_data_type_exists",
    "get_valid_data_types",
    "analyze_function_complete",
    "analyze_function_completeness",
    "analyze_data_region",
    "analyze_dataflow",
    "analyze_struct_field_usage",
    "analyze_for_documentation",
    # ── Write ─────────────────────────────────────────────────────────────
    "rename_function_by_address",
    "rename_variables",
    "rename_variable",
    "rename_or_label",
    "rename_label",
    "rename_global_variable",
    "batch_rename_function_components",
    "batch_create_labels",
    "set_function_prototype",
    "set_local_variable_type",
    "set_parameter_type",
    "set_variables",
    "set_plate_comment",
    "batch_set_comments",
    "set_disassembly_comment",
    "set_decompiler_comment",
    "apply_data_type",
    # ── Data types ────────────────────────────────────────────────────────
    "create_struct",
    "add_struct_field",
    "modify_struct_field",
    "remove_struct_field",
    "create_array_type",
    "create_pointer_type",
    "create_typedef",
    "create_function_signature",
    "delete_data_type",
}


def _invoke_minimax(prompt, model=None, max_turns=25, complexity_tier=None):
    """Invoke MiniMax via OpenAI-compatible API with tool-calling agent loop.

    Fetches Ghidra MCP tool schemas, converts them to OpenAI function definitions,
    and runs a multi-turn conversation loop where the model can call tools and
    receive results until it produces a final text response.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print(
            "ERROR: openai not installed. Run: pip install openai",
            file=sys.stderr,
        )
        return None

    model = _require_model_name(model, "minimax")

    api_key = os.environ.get("MINIMAX_API_KEY")
    if not api_key:
        print(
            "ERROR: MINIMAX_API_KEY environment variable not set. "
            "Get a key at https://platform.minimax.io",
            file=sys.stderr,
        )
        return None

    # --- Build OpenAI function schemas from Ghidra MCP schema ---
    schema = ghidra_get("/mcp/schema", timeout=10)
    tools_openai = []
    tool_endpoint_map = {}  # tool_name -> {path, method, params}

    if schema and isinstance(schema, dict):
        endpoints = schema.get("tools", schema.get("endpoints", []))
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            path = ep.get("path", "")
            name = path.lstrip("/")
            if not name:
                continue
            # Skip tools outside the documentation allowlist. This reduces schema
            # payload from ~171 tools (130 kB) to ~62 tools (~47 kB), saving
            # tens of thousands of tokens on every API turn.
            if name not in _MINIMAX_DOC_TOOL_ALLOWLIST:
                continue
            method = ep.get("method", "GET").upper()
            description = ep.get("description", name)
            params = ep.get("params", [])

            # Build JSON schema for parameters.
            # Parameter descriptions are omitted — they add ~14kB to an already
            # 60kB schema and models infer param meaning from the name + tool
            # description. Dropping them saves ~5,900 tokens per API turn
            # (~41k tokens per 7-turn run).
            properties = {}
            required = []
            for p in params:
                pname = p.get("name", "")
                if not pname:
                    continue
                ptype = p.get("type", "string")
                json_type = {
                    "string": "string",
                    "integer": "integer",
                    "int": "integer",
                    "boolean": "boolean",
                    "bool": "boolean",
                    "number": "number",
                    "float": "number",
                }.get(ptype, "string")
                prop = {"type": json_type}
                # Omit param descriptions to keep schema compact
                properties[pname] = prop
                if p.get("required", False) and pname != "program":
                    required.append(pname)

            tool_def = {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                    },
                },
            }
            if required:
                tool_def["function"]["parameters"]["required"] = required

            tools_openai.append(tool_def)
            tool_endpoint_map[name] = {
                "path": path,
                "method": method,
                "params": params,
            }

    if not tools_openai:
        print("  WARNING: No tools from /mcp/schema, running without tools", flush=True)

    # Per-session decompile cache. decompile_function is called 3.2× per run on
    # average; subsequent calls for the same address return the same pseudocode.
    # Caching saves Ghidra HTTP round-trips (~280 ms each) and prevents duplicate
    # decompile results from being appended to the conversation history, which
    # would grow context size quadratically.
    _decompile_cache: dict[str, str] = {}

    # --- Execute tool calls against Ghidra HTTP API ---
    def execute_tool_call(name, arguments):
        """Execute a tool call against the Ghidra HTTP server."""
        ep = tool_endpoint_map.get(name)
        if not ep:
            return json.dumps({"error": f"Unknown tool: {name}"})

        path = ep["path"]
        method = ep["method"]
        params_spec = ep["params"]

        # Split arguments into query params and body params based on schema
        query_params = {}
        body_params = {}
        for p in params_spec:
            pname = p.get("name", "")
            source = p.get("source", "query")
            if pname in arguments:
                if source == "body" and method == "POST":
                    body_params[pname] = arguments[pname]
                else:
                    query_params[pname] = arguments[pname]

        # program param always goes as query param (CLAUDE.md convention)
        if "program" in arguments and "program" not in query_params:
            query_params["program"] = arguments["program"]
            body_params.pop("program", None)

        # Decompile cache: keyed by (address, program) so multi-binary sessions
        # don't collide. Returns cached result immediately without hitting Ghidra.
        if name == "decompile_function":
            cache_key = (
                str(query_params.get("address", "")),
                str(query_params.get("program", "")),
            )
            if cache_key in _decompile_cache:
                print(
                    f"  [mcp] decompile_function: cache hit ({cache_key[0]})",
                    flush=True,
                )
                return _decompile_cache[cache_key]

        try:
            if method == "POST":
                result = ghidra_post(
                    path, data=body_params or None, params=query_params or None
                )
            else:
                all_params = {**query_params, **body_params}
                result = ghidra_get(path, params=all_params or None)

            if result is None:
                return json.dumps({"error": f"Ghidra {method} {path} returned no data"})
            if isinstance(result, (dict, list)):
                result_str = json.dumps(result, default=str)
            else:
                result_str = str(result)

            # Populate decompile cache on first successful call
            if name == "decompile_function" and '"error"' not in result_str[:100]:
                _decompile_cache[cache_key] = result_str

            return result_str
        except Exception as e:
            return json.dumps({"error": f"Tool execution failed: {str(e)}"})

    # --- Conversation loop ---
    # 180s timeout: MiniMax occasionally hangs indefinitely under load (6 concurrent
    # workers). Without a timeout the thread blocks forever with no output or retry.
    client = OpenAI(
        api_key=api_key,
        base_url="https://api.minimax.io/v1",
        timeout=180.0,
    )

    messages = [
        {
            "role": "system",
            "content": (
                "You are a reverse engineering assistant with access to Ghidra MCP tools. "
                "Call tools to analyze and document functions. Be thorough and precise.\n\n"
                "CRITICAL EFFICIENCY RULE: Never call `set_disassembly_comment` more than once. "
                "Always batch ALL disassembly/EOL comments into a SINGLE `batch_set_comments` call "
                "with comment_type='EOL_COMMENT'. Each separate API call costs a full round-trip. "
                "Collect all addresses that need EOL comments first, then submit them together."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    output_parts = []
    total_input_tokens = 0
    total_output_tokens = 0
    tool_call_count = 0

    # Dynamic max_tokens: bump for complex/massive functions
    if complexity_tier in ("complex", "massive"):
        max_output_tokens = 32768
    else:
        max_output_tokens = 16384

    # Context compression constants. After COMPRESS_AFTER tool exchanges the
    # conversation history balloons (each Ghidra response can be 5-20 kB).
    # We keep the last KEEP_RECENT exchanges verbatim and trim older tool
    # *results* to a short stub — the model can still see what calls it made
    # and what actions it took, but not re-read the full Ghidra output again.
    COMPRESS_AFTER = 8  # start compressing once history exceeds this many exchanges
    KEEP_RECENT = 6  # always keep these many recent exchanges uncompressed
    TRIM_RESULT_TO = 300  # chars to keep from old tool results

    def _compress_messages(msgs):
        """Trim old tool-result content to reduce quadratic context growth."""
        # Identify tool-result messages: role=="tool" (OpenAI format)
        tool_result_indices = [
            i
            for i, m in enumerate(msgs)
            if isinstance(m, dict) and m.get("role") == "tool"
        ]
        # Keep the most recent KEEP_RECENT result messages uncompressed
        to_trim = tool_result_indices[: max(0, len(tool_result_indices) - KEEP_RECENT)]
        for i in to_trim:
            m = msgs[i]
            content = m.get("content", "")
            if isinstance(content, str) and len(content) > TRIM_RESULT_TO:
                msgs[i] = dict(m, content=content[:TRIM_RESULT_TO] + "…[trimmed]")
        return msgs

    for turn in range(max_turns):
        # Compress history before building the next API request
        if tool_call_count >= COMPRESS_AFTER:
            messages = _compress_messages(messages)

        try:
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": 1.0,  # MiniMax recommends 1.0
                "max_tokens": max_output_tokens,
            }
            if tools_openai:
                kwargs["tools"] = tools_openai
                # Sequential tool calls: prevents the model from issuing parallel
                # reads before processing earlier results, which causes it to miss
                # context from tool responses and repeat the same calls.
                kwargs["parallel_tool_calls"] = False

            # Retry transient errors (429 rate limit, 529 overloaded, 5xx server,
            # and read/connect timeouts from the 180s client timeout above).
            #
            # The OpenAI-compatible MiniMax call is non-streaming, so no tool-call
            # events can be emitted until the API returns an assistant message.
            # Emit provider_turn wait events while the request is in flight so a
            # quiet dashboard means "waiting on MiniMax", not "worker lost".
            response = None
            for _attempt in range(4):
                try:
                    import concurrent.futures

                    started = time.perf_counter()
                    bus_emit(
                        "provider_turn",
                        {
                            "provider": "minimax",
                            "model": model,
                            "turn": turn + 1,
                            "attempt": _attempt + 1,
                            "status": "request_start",
                            "tool_calls_so_far": tool_call_count,
                            "messages": len(messages),
                            "max_tokens": max_output_tokens,
                        },
                    )
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=1
                    ) as executor:
                        future = executor.submit(
                            client.chat.completions.create, **kwargs
                        )
                        last_emit = 0
                        while True:
                            try:
                                response = future.result(timeout=5)
                                break
                            except concurrent.futures.TimeoutError:
                                elapsed = int(time.perf_counter() - started)
                                if elapsed - last_emit >= 15:
                                    last_emit = elapsed
                                    bus_emit(
                                        "provider_turn",
                                        {
                                            "provider": "minimax",
                                            "model": model,
                                            "turn": turn + 1,
                                            "attempt": _attempt + 1,
                                            "status": "waiting",
                                            "elapsed_sec": elapsed,
                                            "tool_calls_so_far": tool_call_count,
                                        },
                                    )
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    bus_emit(
                        "provider_turn",
                        {
                            "provider": "minimax",
                            "model": model,
                            "turn": turn + 1,
                            "attempt": _attempt + 1,
                            "status": "response",
                            "elapsed_ms": elapsed_ms,
                            "tool_calls_so_far": tool_call_count,
                        },
                    )
                    break
                except Exception as api_err:
                    elapsed_ms = (
                        int((time.perf_counter() - started) * 1000)
                        if "started" in locals()
                        else None
                    )
                    bus_emit(
                        "provider_turn",
                        {
                            "provider": "minimax",
                            "model": model,
                            "turn": turn + 1,
                            "attempt": _attempt + 1,
                            "status": "error",
                            "elapsed_ms": elapsed_ms,
                            "error": str(api_err)[:300],
                        },
                    )
                    err_str = str(api_err)
                    retryable = any(
                        code in err_str
                        for code in (
                            "429",
                            "529",
                            "500",
                            "502",
                            "503",
                            "Timeout",
                            "timeout",
                            "timed out",
                            "ReadTimeout",
                            "ConnectTimeout",
                        )
                    )
                    if retryable and _attempt < 3:
                        wait = (2**_attempt) * 5  # 5s, 10s, 20s
                        print(
                            f"  [minimax] transient error (attempt {_attempt + 1}/4), "
                            f"retrying in {wait}s: {err_str[:120]}",
                            flush=True,
                        )
                        time.sleep(wait)
                    else:
                        raise
            if response is None:
                break
        except Exception as e:
            print(f"  [minimax] API error: {e}", file=sys.stderr)
            break

        if not response.choices:
            # Log the full response for debugging
            print(
                f"  [minimax] Empty response (no choices). Model: {response.model}, id: {response.id}",
                file=sys.stderr,
            )
            if hasattr(response, "usage") and response.usage:
                print(
                    f"  [minimax] Usage before failure: {response.usage.prompt_tokens} prompt + {response.usage.completion_tokens} completion tokens",
                    file=sys.stderr,
                )
            break
        choice = response.choices[0]
        message = choice.message

        # Track usage
        if response.usage:
            total_input_tokens += response.usage.prompt_tokens or 0
            total_output_tokens += response.usage.completion_tokens or 0

        # Append assistant message to conversation history
        # Preserve full message including <think> blocks for reasoning continuity
        messages.append(message.model_dump())

        # Check for tool calls
        if message.tool_calls:
            for tc in message.tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}

                tool_call_count += 1
                # Hard cap: stop runaway tool call loops (e.g., 90+ set_local_variable_type)
                if tool_call_count > 50:
                    print(
                        f"  [minimax] Tool call cap reached ({tool_call_count}), stopping",
                        flush=True,
                    )
                    output_parts.append(
                        f"BLOCKED: Tool call cap reached after {tool_call_count} calls"
                    )
                    break
                print(f"  [mcp] {fn_name}: calling", flush=True)
                bus_emit("tool_call", {"tool": fn_name, "status": "calling"})
                _t0 = time.perf_counter()
                result_str = execute_tool_call(fn_name, fn_args)
                duration_ms = int((time.perf_counter() - _t0) * 1000)

                # Truncate very large results to avoid blowing context
                if len(result_str) > 50000:
                    result_str = result_str[:50000] + "\n... (truncated)"

                status = "error" if '"error"' in result_str[:100] else "success"
                error_preview = (
                    _tool_error_preview(result_str) if status == "error" else None
                )
                print(f"  [mcp] {fn_name}: {status}", flush=True)
                bus_emit(
                    "tool_result",
                    {
                        "tool": fn_name,
                        "status": status,
                        **({"error": error_preview} if error_preview else {}),
                    },
                )
                _debug_log_tool_call(fn_name, fn_args, result_str, status, duration_ms)

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_str,
                    }
                )
            continue  # Next turn — model needs to process tool results

        # No tool calls — this is the final text response
        if message.content:
            # Strip <think>...</think> reasoning blocks — keep only user-facing text
            import re

            cleaned = re.sub(r"<think>[\s\S]*?</think>", "", message.content).strip()
            if cleaned:
                safe_text = cleaned.encode("ascii", errors="replace").decode("ascii")
                print(safe_text)
                output_parts.append(cleaned)
                bus_emit("model_text", {"text": cleaned[:500]})
            else:
                # All content was think-tags — model reasoning only, no actionable output
                print(f"  [minimax] (reasoning only, no output text)", flush=True)
        else:
            print(
                f"  [minimax] (empty content, finish_reason={choice.finish_reason})",
                flush=True,
            )

        if choice.finish_reason in ("stop", "end_turn", None):
            break

    if total_input_tokens or total_output_tokens:
        print(
            f"  [tokens: {total_input_tokens} in + {total_output_tokens} out | tools: {tool_call_count}]",
            flush=True,
        )

    text = "\n".join(output_parts) if output_parts else None
    return (
        text,
        {
            "tool_calls": tool_call_count,
            "input_tokens": total_input_tokens,
            "output_tokens": total_output_tokens,
        },
    )


def _invoke_claude(prompt, model=None, max_turns=25):
    """Invoke Claude Code via the Python SDK with MCP tool support."""
    import asyncio

    model = _require_model_name(model, "claude")

    try:
        from claude_agent_sdk import query, ClaudeAgentOptions
    except ImportError:
        print(
            "ERROR: claude-agent-sdk not installed. Run: pip install claude-agent-sdk",
            flush=True,
        )
        return None

    async def run():
        options = ClaudeAgentOptions(
            model=model,
            permission_mode="bypassPermissions",
            max_turns=max_turns,
            cwd=str(REPO_ROOT),
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                # ghidra-mcp tools are statically registered via ~/.claude.json
                # mcpServers.ghidra and are immediately callable — they are NOT
                # deferred tools, so ToolSearch cannot find them and returns
                # empty results. Previously this append told claude to use
                # ToolSearch first, which produced a false "BLOCKED: tools
                # not available" rate of ~5% (observed 11 runs out of 213
                # on 2026-04-15). Now we tell claude to call them directly.
                "append": (
                    "The ghidra-mcp MCP tools are already registered and "
                    "immediately callable. Invoke them directly by either "
                    "the short name (e.g. `set_local_variable_type`, "
                    "`rename_variables`, `batch_set_comments`, "
                    "`get_function_variables`, `set_function_prototype`, "
                    "`decompile_function`) or the fully-qualified form "
                    "`mcp__ghidra-mcp__<tool_name>`. Do NOT use ToolSearch "
                    "to look them up — they are not deferred tools.\n\n"
                    "EFFICIENCY RULE: When adding disassembly/EOL comments, "
                    "batch ALL of them into ONE `batch_set_comments` call with "
                    "comment_type='EOL_COMMENT'. Never call `set_disassembly_comment` "
                    "more than once per run."
                ),
            },
        )

        output_parts = []
        tool_id_to_name = {}
        tool_call_count = 0
        # Pending tool-use info awaiting its matching tool-result block. Claude
        # Agent SDK delivers ToolUseBlock in AssistantMessage.content and the
        # corresponding ToolResultBlock in UserMessage.content (per the
        # Anthropic API convention — the "user" sends tool results back).
        # Correlation is by tool_use_id.
        pending_calls = {}  # tool_id -> {"name", "input", "start_time"}
        mcp_init_failed = False  # Tracks if ghidra-mcp tools failed to register
        try:
            async for msg in query(prompt=prompt, options=options):
                msg_type = type(msg).__name__

                # Both AssistantMessage and UserMessage carry content blocks.
                # Per claude_agent_sdk._internal.message_parser:
                #   AssistantMessage.content can contain: TextBlock,
                #     ThinkingBlock, ToolUseBlock, ToolResultBlock
                #   UserMessage.content can contain: TextBlock, ToolUseBlock,
                #     ToolResultBlock
                # ToolResultBlock specifically arrives in UserMessage in
                # practice, so we must iterate UserMessage content too —
                # otherwise _debug_log_tool_call is never invoked and claude's
                # per-function debug JSONL files stay empty.
                if msg_type not in ("AssistantMessage", "UserMessage"):
                    # ResultMessage, SystemMessage, RateLimitEvent, etc. are
                    # not structured content carriers — skip.
                    continue

                content = getattr(msg, "content", None)
                if not content:
                    continue

                for block in content if isinstance(content, list) else [content]:
                    block_type = type(block).__name__

                    if block_type == "TextBlock":
                        # Only capture assistant text as "model output".
                        # UserMessage TextBlock is the prompt we sent (or a
                        # tool-result formatted as text), not model reasoning.
                        if msg_type == "AssistantMessage":
                            text = getattr(block, "text", str(block))
                            print(text)
                            output_parts.append(text)
                            bus_emit("model_text", {"text": text})

                    elif block_type == "ToolUseBlock":
                        tool_name = getattr(block, "name", "?")
                        tool_call_count += 1
                        tool_id = getattr(block, "id", "")
                        tool_input = getattr(block, "input", None) or {}
                        tool_id_to_name[tool_id] = tool_name
                        pending_calls[tool_id] = {
                            "name": tool_name,
                            "input": tool_input,
                            "start_time": time.perf_counter(),
                        }
                        normalized_tool = _normalize_tool_name(tool_name)
                        print(
                            f"  [mcp] {normalized_tool}: calling",
                            flush=True,
                        )
                        bus_emit(
                            "tool_call",
                            {
                                "tool": normalized_tool,
                                "raw_tool": tool_name,
                                "status": "calling",
                                "id": tool_id,
                            },
                        )

                    elif block_type == "ToolResultBlock":
                        is_error = getattr(block, "is_error", False)
                        status = "error" if is_error else "success"
                        tool_id = getattr(block, "tool_use_id", "")
                        tool_name = tool_id_to_name.get(tool_id, tool_id[:12])
                        # Extract result content (string or list of content blocks)
                        result_content = getattr(block, "content", None)
                        if isinstance(result_content, list):
                            parts = []
                            for c in result_content:
                                parts.append(getattr(c, "text", str(c)))
                            result_text = "".join(parts)
                        else:
                            result_text = (
                                "" if result_content is None else str(result_content)
                            )
                        # Correlate with pending call for args + duration
                        call_info = pending_calls.pop(tool_id, None)
                        args = call_info.get("input", {}) if call_info else {}
                        duration_ms = (
                            int((time.perf_counter() - call_info["start_time"]) * 1000)
                            if call_info
                            else None
                        )
                        normalized_tool = _normalize_tool_name(tool_name)
                        error_preview = (
                            _tool_error_preview(result_text) if is_error else None
                        )
                        print(
                            f"  [mcp] {normalized_tool}: {status}"
                            + (f" - {error_preview}" if error_preview else ""),
                            flush=True,
                        )
                        payload = {
                            "tool": normalized_tool,
                            "raw_tool": tool_name,
                            "status": status,
                            "id": tool_id,
                        }
                        if error_preview:
                            payload["error"] = error_preview
                        bus_emit("tool_result", payload)
                        _debug_log_tool_call(
                            tool_name,
                            args,
                            result_text,
                            status,
                            duration_ms,
                        )

                        # Detect MCP init failure: the claude_agent_sdk sometimes
                        # starts a session before the ghidra-mcp MCP subprocess
                        # has finished registering its tools. When this happens,
                        # EVERY ghidra-mcp tool call returns "No such tool
                        # available" — the error is per-session, not per-call.
                        # Abort early and retry the whole session (outer loop).
                        if (
                            is_error
                            and result_text
                            and "No such tool available" in result_text
                            and (
                                "ghidra" in result_text.lower()
                                or "ghidra" in (tool_name or "").lower()
                            )
                        ):
                            mcp_init_failed = True
                            print(
                                f"  [claude sdk] MCP init failure — ghidra-mcp tools "
                                f"not registered in this session. Aborting for retry.",
                                flush=True,
                            )
                            break  # Exit the block loop
                    elif block_type == "ThinkingBlock":
                        pass  # Skip thinking blocks
                if mcp_init_failed:
                    break  # Exit the message loop
        except Exception as e:
            err_str = str(e)
            if "not found" in err_str.lower():
                raise
            # Print all errors to stdout because some host terminals may hide stderr.
            print(f"  [claude sdk error] {err_str}", flush=True)

        if mcp_init_failed:
            return "__MCP_INIT_FAILED__"

        return (
            "\n".join(output_parts) if output_parts else None,
            {"tool_calls": tool_call_count, "tool_calls_known": True},
        )

    # Retry on transient errors:
    #   - "not found": intermittent when previous Claude Code process is still exiting
    #   - "__MCP_INIT_FAILED__": the ghidra-mcp MCP subprocess didn't finish
    #     registering tools before the session started. Observed as ~5-17% of
    #     sessions in the v5.3.2 test run (2026-04-15). A 5s delay between
    #     retries gives the subprocess time to finish init. Up to 3 attempts.
    for attempt in range(3):
        try:
            result = asyncio.run(run())
            if result == "__MCP_INIT_FAILED__":
                if attempt < 2:
                    print(
                        f"  [claude sdk] MCP init failed — retrying in 5s "
                        f"(attempt {attempt + 2}/3)...",
                        flush=True,
                    )
                    time.sleep(5)
                    continue
                print(
                    f"  [claude sdk] MCP init failed after 3 attempts — "
                    f"ghidra-mcp tools never registered.",
                    flush=True,
                )
                return None
            return result
        except Exception as e:
            err_str = str(e)
            if "not found" in err_str and attempt < 2:
                print(f"  [claude sdk] Retrying in 3s ({err_str})...", flush=True)
                time.sleep(3)
                continue
            print(f"ERROR: Claude SDK failed: {e}", file=sys.stderr)
            return None


# ---------------------------------------------------------------------------
# Terminal dashboard
# ---------------------------------------------------------------------------


def print_status(state):
    """Print terminal status dashboard."""
    funcs = state.get("functions", {})
    total = len(funcs)
    if total == 0:
        print("No functions in state. Run --scan first.")
        return

    done = sum(1 for f in funcs.values() if f["score"] >= 90)
    fixable = sum(1 for f in funcs.values() if 70 <= f["score"] < 90)
    needs_work = sum(1 for f in funcs.values() if f["score"] < 70)
    pct = (done / total * 100) if total > 0 else 0

    # Score distribution
    buckets = {
        "100": 0,
        "90-99": 0,
        "80-89": 0,
        "70-79": 0,
        "60-69": 0,
        "50-59": 0,
        "40-49": 0,
        "30-39": 0,
        "20-29": 0,
        "10-19": 0,
        "0-9": 0,
    }
    for f in funcs.values():
        s = f["score"]
        if s >= 100:
            buckets["100"] += 1
        elif s >= 90:
            buckets["90-99"] += 1
        elif s >= 80:
            buckets["80-89"] += 1
        elif s >= 70:
            buckets["70-79"] += 1
        elif s >= 60:
            buckets["60-69"] += 1
        elif s >= 50:
            buckets["50-59"] += 1
        elif s >= 40:
            buckets["40-49"] += 1
        elif s >= 30:
            buckets["30-39"] += 1
        elif s >= 20:
            buckets["20-29"] += 1
        elif s >= 10:
            buckets["10-19"] += 1
        else:
            buckets["0-9"] += 1

    # Programs breakdown
    by_program = defaultdict(lambda: {"total": 0, "done": 0})
    for f in funcs.values():
        prog = f.get("program_name", "unknown")
        by_program[prog]["total"] += 1
        if f["score"] >= 90:
            by_program[prog]["done"] += 1

    folder = state.get("project_folder", "unknown")
    last_scan = state.get("last_scan", "never")

    print(f"\n{'=' * 60}")
    print(f"  Fun-Doc Progress Dashboard")
    print(f"  Project: {folder}")
    print(f"  Last scan: {last_scan}")
    print(f"{'=' * 60}")
    print(
        f"\n  Total: {total}  |  Done: {done} ({pct:.1f}%)  |  Fix: {fixable}  |  Remaining: {needs_work}"
    )
    print()

    # Progress bar
    bar_width = 40
    filled = int(bar_width * pct / 100)
    bar = "#" * filled + "-" * (bar_width - filled)
    print(f"  [{bar}] {pct:.1f}%")
    print()

    # Score distribution
    print("  Score Distribution:")
    for bucket in [
        "100",
        "90-99",
        "80-89",
        "70-79",
        "60-69",
        "50-59",
        "40-49",
        "30-39",
        "20-29",
        "10-19",
        "0-9",
    ]:
        count = buckets[bucket]
        if count > 0:
            bar = "#" * min(count // 5 + 1, 40)
            print(f"    {bucket:>5}: {count:>4}  {bar}")
    print()

    # Per-program breakdown
    print("  Per Binary:")
    for prog in sorted(by_program.keys()):
        info = by_program[prog]
        prog_pct = (info["done"] / info["total"] * 100) if info["total"] > 0 else 0
        remaining = info["total"] - info["done"]
        print(
            f"    {prog:<25} {info['done']:>4}/{info['total']:<4} ({prog_pct:>5.1f}%)  {remaining} remaining"
        )
    print()

    # Session history
    sessions = state.get("sessions", [])
    if sessions:
        print("  Recent Sessions:")
        for s in sessions[-5:]:
            partial_str = (
                f", {s.get('partial', 0)} partial" if s.get("partial", 0) else ""
            )
            print(
                f"    {s.get('date', '?')}: +{s.get('completed', 0)} completed, {s.get('skipped', 0)} skipped, {s.get('failed', 0)} failed{partial_str}"
            )
        print()

    # Next targets
    next_funcs = get_next_functions(state, count=5)
    if next_funcs:
        print("  Next Targets (highest priority):")
        for key, func in next_funcs:
            leaf_tag = " [leaf]" if func.get("is_leaf") else ""
            print(
                f"    {func['name']:<35} @ 0x{func['address']}  score={func['score']}%  callers={func['caller_count']}{leaf_tag}"
            )
    print()


# ---------------------------------------------------------------------------
# Processing loop
# ---------------------------------------------------------------------------


def _sync_func_state(func, completeness, score=None, deductions=None):
    """Sync all completeness fields from live data into the function state dict.

    Always sets last_processed to the current time when a valid score or
    completeness is applied — the cold-start lane treats last_processed=None
    as "never analyzed," so leaving it unset causes infinite re-picking of
    functions that were successfully scored but only went through a skip path.
    """
    if score is not None:
        func["score"] = score
        func["last_processed"] = datetime.now().isoformat()
    if deductions is not None:
        func["deductions"] = deductions
    if completeness and isinstance(completeness, dict) and "error" not in completeness:
        func["last_processed"] = datetime.now().isoformat()
        func["has_custom_name"] = completeness.get(
            "has_custom_name", func.get("has_custom_name", False)
        )
        func["has_plate_comment"] = completeness.get(
            "has_plate_comment", func.get("has_plate_comment", False)
        )
        func["classification"] = completeness.get(
            "classification", func.get("classification", "unknown")
        )
        func["fixable"] = float(
            completeness.get("fixable_deductions", func.get("fixable", 0))
        )
        func["is_leaf"] = completeness.get(
            "is_leaf", completeness.get("classification") == "leaf"
        )
        # Update name if it changed in Ghidra
        new_name = completeness.get("function_name")
        if new_name and not new_name.startswith("FUN_"):
            func["name"] = new_name


# ---------------------------------------------------------------------------
# Post-pass Hungarian audit (Guard #4)
# ---------------------------------------------------------------------------

# Canonical prefix→type mapping for mechanical validation
_HUNGARIAN_PREFIX_TO_TYPES = {
    "p": {"void *", "char *", "wchar_t *"},  # Also any pointer type — checked specially
    "pp": set(),  # pointer-to-pointer — checked specially
    "dw": {"uint", "dword", "ulong", "unsigned int", "unsigned long"},
    "n": {"int", "short", "long", "signed int"},
    "i": {"int", "signed int"},
    "b": {"byte", "uchar", "unsigned char", "bool"},
    "by": {"byte", "uchar", "unsigned char"},
    "f": {"bool", "BOOL"},
    "w": {"ushort", "unsigned short", "word", "wchar_t"},
    "sz": {"char *"},
    "lpsz": {"char *"},
    "wsz": {"wchar_t *"},
    "ll": {"longlong", "long long", "int64_t", "__int64"},
    "qw": {"ulonglong", "unsigned long long", "uint64_t"},
    "fl": {"float"},
    "d": {"double"},
    "ab": set(),  # byte arrays — checked specially
    "aw": set(),  # ushort arrays — checked specially
    "ad": set(),  # uint arrays — checked specially
    "c": {"char", "signed char"},
    "ch": {"char", "signed char"},
    "l": {"long", "signed long"},
}


def _extract_hungarian_prefix(name):
    """Extract the Hungarian prefix from a variable name.

    Returns (prefix, base_name) or (None, name) if no prefix found.
    """
    if not name or len(name) < 2:
        return None, name
    # Strip g_ for globals
    work = name[2:] if name.startswith("g_") else name
    if not work:
        return None, name
    # Try two-char prefixes first, then single-char
    for plen in (4, 3, 2):
        candidate = work[:plen]
        if candidate in _HUNGARIAN_PREFIX_TO_TYPES:
            # Prefix must be followed by an uppercase letter
            rest = work[plen:]
            if rest and rest[0].isupper():
                return candidate, rest
    # Single-char prefixes
    if work[0] in _HUNGARIAN_PREFIX_TO_TYPES and len(work) > 1 and work[1].isupper():
        return work[0], work[1:]
    return None, name


def _is_type_pointer(type_str):
    """Check if a Ghidra type string represents a pointer."""
    return type_str.rstrip().endswith("*")


def _is_generic_varname(name):
    """Check if a variable name is Ghidra's auto-generated default."""
    import re

    return bool(
        re.match(r"^(local_|[a-z]{1,2}Var\d+$|param_|in_|unaff_|extraout_)", name)
    )


def _audit_hungarian_compliance(address, program):
    """Fetch variables and check for Hungarian prefix/type mismatches.

    Returns a list of issue dicts:
      [{"var": name, "type": type, "prefix": prefix, "issue": description}, ...]
    Also returns count of remaining generic-named variables.
    """
    vars_data = ghidra_get(
        "/get_function_variables",
        params={"function_name": f"FUN_{address}", "program": program},
    )
    # Try address-based lookup if name-based fails
    if not vars_data:
        vars_data = ghidra_get(
            "/get_function_variables",
            params={"function_name": f"0x{address}", "program": program},
        )
    if not vars_data or not isinstance(vars_data, dict):
        return [], 0

    issues = []
    generic_count = 0
    all_vars = vars_data.get("parameters", []) + vars_data.get("locals", [])

    for v in all_vars:
        name = v.get("name", "")
        vtype = v.get("type", "")
        is_phantom = v.get("is_phantom", False)

        # Skip phantoms — can't be fixed
        if is_phantom:
            continue

        # Count generic names (variables the model didn't rename)
        if _is_generic_varname(name):
            generic_count += 1
            continue

        # Check Hungarian prefix consistency
        prefix, _ = _extract_hungarian_prefix(name)
        if not prefix:
            continue  # No prefix to validate

        # Special pointer checks
        if prefix in ("p", "pp"):
            if not _is_type_pointer(vtype):
                issues.append(
                    {
                        "var": name,
                        "type": vtype,
                        "prefix": prefix,
                        "issue": f"'{prefix}' prefix requires pointer type, got '{vtype}'",
                    }
                )
            continue

        # Standard prefix check
        valid_types = _HUNGARIAN_PREFIX_TO_TYPES.get(prefix, set())
        if valid_types and vtype.lower().strip() not in {
            t.lower() for t in valid_types
        }:
            # Don't flag pointer types with 'p' prefix that are correctly typed
            if _is_type_pointer(vtype) and prefix == "p":
                continue
            issues.append(
                {
                    "var": name,
                    "type": vtype,
                    "prefix": prefix,
                    "issue": f"'{prefix}' prefix expects {valid_types}, got '{vtype}'",
                }
            )

    return issues, generic_count


def _rescore_and_sync(func, address, program):
    """Re-fetch completeness from Ghidra and sync all fields.

    Returns (new_score, completeness_dict) or (None, None).
    """
    fresh = ghidra_get(
        "/analyze_function_completeness",
        params={"function_address": f"0x{address}", "program": program},
    )
    if fresh and isinstance(fresh, dict) and "error" not in fresh:
        new_score = int(
            fresh.get("effective_score", fresh.get("completeness_score", 0))
        )
        deductions = fresh.get("deduction_breakdown", [])
        _sync_func_state(func, fresh, new_score, deductions)
        return new_score, fresh
    return None, None


def _append_run_log(entry):
    """Append a single JSONL entry to the run log. Thread-safe."""
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with _state_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        bus_emit("run_logged", entry)
        # Also emit a structured event so the canonical audit trail
        # captures every run attempt. Mirrors the key fields only —
        # the full row is still in runs.jsonl.
        try:
            from event_log import log_event

            log_event(
                "run.logged",
                run_id=entry.get("run_id"),
                worker_id=entry.get("worker_id"),
                program=entry.get("program"),
                address=entry.get("address"),
                function=entry.get("function"),
                provider=entry.get("provider"),
                mode=entry.get("mode"),
                result=entry.get("result"),
                score_before=entry.get("score_before"),
                score_after=entry.get("score_after"),
                score_delta=entry.get("score_delta"),
                tool_calls=entry.get("tool_calls"),
                input_tokens=entry.get("input_tokens"),
                output_tokens=entry.get("output_tokens"),
                missing_artifacts=entry.get("missing_artifacts"),
            )
        except Exception:
            pass  # never let event logging break run logging

        # Update per-function cost history for thrashing detection.
        # Best-effort — failures do not block run logging.
        try:
            _update_function_cost_history(entry)
        except Exception:
            pass
    except Exception as e:
        print(f"  WARNING: Failed to write run log: {e}", flush=True)
        try:
            from event_log import log_event

            log_event("run.log_failed", error=str(e), error_type=type(e).__name__)
        except Exception:
            pass


def _update_function_cost_history(entry):
    """Append run metrics to the per-function attempts[] history.

    Maintains cumulative cost counters per function so the dashboard can
    surface thrashing (high spend, low delta). Keeps only the last 5
    attempts to bound state.json growth. Uses update_function_state for
    atomic RMW — safe under concurrent workers.

    Thrashing criteria (is_thrashing=True when both hold):
        - >= 2 attempts
        - cost_per_point > 50_000 input tokens per +1 score_delta
    """
    program = entry.get("program")
    address = entry.get("address")
    if not program or not address:
        return
    result = entry.get("result")
    # Only count runs that actually ran the model. Skipped/timed-out
    # runs have no meaningful cost or delta and would skew the ratio.
    if result not in ("completed", "partial", "failed", "needs_redo"):
        return
    in_tok = entry.get("input_tokens") or 0
    out_tok = entry.get("output_tokens") or 0
    sb = entry.get("score_before")
    sa = entry.get("score_after")
    delta = (
        (sa - sb)
        if isinstance(sa, (int, float)) and isinstance(sb, (int, float))
        else 0
    )

    func_key = f"{program}::{address}"
    # Re-read from state to pick up concurrent updates
    latest = load_state()
    func = (latest.get("functions") or {}).get(func_key)
    if not func:
        return  # function not yet in state — skip

    attempts = list(func.get("attempts") or [])
    attempts.append(
        {
            "ts": entry.get("timestamp"),
            "provider": entry.get("provider"),
            "mode": entry.get("mode"),
            "result": result,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "tool_calls": entry.get("tool_calls"),
            "score_before": sb,
            "score_after": sa,
            "delta": delta,
        }
    )
    # Keep only last 5 to bound state size
    attempts = attempts[-5:]

    total_input = sum(a.get("input_tokens", 0) or 0 for a in attempts)
    total_output = sum(a.get("output_tokens", 0) or 0 for a in attempts)
    net_delta = sum(a.get("delta", 0) or 0 for a in attempts)
    cost_per_point = (total_input / net_delta) if net_delta > 0 else None

    is_thrashing = (
        len(attempts) >= 2 and cost_per_point is not None and cost_per_point > 50_000
    )

    func["attempts"] = attempts
    func["total_input_tokens"] = total_input
    func["total_output_tokens"] = total_output
    func["net_delta"] = net_delta
    func["cost_per_point"] = (
        round(cost_per_point, 0) if cost_per_point is not None else None
    )
    func["is_thrashing"] = is_thrashing

    update_function_state(func_key, func)

    # Emit structured event on the regression+thrashing inflection points
    # so they're trivially findable later without joining runs.jsonl to state.
    try:
        from event_log import log_event

        if delta < 0:
            log_event(
                "run.regression",
                program=program,
                address=address,
                function=entry.get("function"),
                provider=entry.get("provider"),
                delta=delta,
                input_tokens=in_tok,
                score_before=sb,
                score_after=sa,
            )
        if is_thrashing and not func.get("_thrashing_alerted"):
            log_event(
                "function.thrashing",
                program=program,
                address=address,
                function=entry.get("function"),
                attempts=len(attempts),
                total_input_tokens=total_input,
                net_delta=net_delta,
                cost_per_point=int(cost_per_point or 0),
            )
            # Mark alerted so we don't spam on every subsequent attempt
            func["_thrashing_alerted"] = True
            update_function_state(func_key, func)
    except Exception:
        pass


def _inject_tool_block(prompt):
    """Append available MCP tool list to a prompt."""
    available_tools = fetch_available_tools()
    if not available_tools:
        return prompt
    RELEVANT_TOOLS = {
        "analyze_for_documentation",
        "get_function_variables",
        "get_plate_comment",
        "set_variables",
        "rename_function_by_address",
        "set_function_prototype",
        "set_local_variable_type",
        "set_parameter_type",
        "batch_set_variable_types",
        "rename_variable",
        "rename_variables",
        "batch_set_comments",
        "rename_or_label",
        "apply_data_type",
        "search_data_types",
        "get_struct_layout",
        "create_struct",
        "modify_struct_field",
        "add_struct_field",
        "create_function",
        "get_function_callers",
        "decompile_function",
    }
    registered = [t for t in available_tools if t in RELEVANT_TOOLS]
    missing = RELEVANT_TOOLS - set(available_tools)
    tool_block = "\n## Available MCP Tools (verified registered)\n"
    tool_block += ", ".join(f"`{t}`" for t in sorted(registered))
    if missing:
        tool_block += f"\n\n**NOT registered** (do NOT call): {', '.join(f'`{t}`' for t in sorted(missing))}"
    tool_block += (
        "\n\n**Batching rule**: Use `batch_set_comments` with `comment_type='EOL_COMMENT'` "
        "for ALL disassembly comments in a single call. Never call `set_disassembly_comment` "
        "more than once per run — batch every address together.\n"
    )
    return prompt + "\n" + tool_block


def process_function(
    func_key,
    func,
    state,
    model=None,
    manual=False,
    dry_run=False,
    provider=None,
    stop_flag=None,
    config_snapshot=None,
):
    """Process a single function: fetch data, build prompt, invoke AI provider.

    `config_snapshot` is an optional frozen view of queue.config captured at
    worker start (see build_worker_config_snapshot). When present, fields that
    affect this worker's policy — max_turns, audit_provider, audit_min_delta,
    complexity_handoff_provider, complexity_handoff_max, good_enough_score,
    and per-provider model/turn slices — are read from the snapshot instead of
    a live load_priority_queue() call. This makes worker behavior consistent
    across the worker's lifetime even if someone edits the config dropdown
    mid-run. CLI invocations and legacy callers that don't have a worker
    context pass None and fall through to live reads (pre-snapshot behavior).
    """
    if stop_flag and stop_flag.is_set():
        return "stopped"

    address = func["address"]
    program = func["program"]
    name = func["name"]
    requested_provider = provider or AI_PROVIDER
    requested_model = model
    effective_provider = requested_provider
    provider_chain = [requested_provider]
    run_id = uuid.uuid4().hex[:12]

    # Set debug-logging context for any tool calls in this function's processing.
    # No-op when debug_mode is off; otherwise tool calls go to logs/debug/...
    _debug_set_context(
        func_key,
        name,
        program,
        address,
        requested_provider,
        run_id,
        requested_provider=requested_provider,
    )

    mode = None
    selected_model = None
    func_name = name
    live_score = None
    new_score = None
    prompt = ""
    output = None
    meta = {}
    tool_calls_made = None
    tool_calls_known = None
    complexity_tier = None
    missing_artifacts = []
    audit_provider = None
    audit_outcome = None
    audit_score_before = None
    audit_score_after = None
    audit_tool_calls = None
    audit_tool_calls_known = None
    run_log_written = False

    def _log_run_once(logged_result, *, score_after=None, reason=None, error=None):
        nonlocal run_log_written
        if run_log_written:
            return
        run_log_written = True
        final_score = new_score if score_after is None else score_after
        score_delta = (
            (final_score - live_score)
            if (final_score is not None and live_score is not None)
            else None
        )
        debug_path = None
        if _debug_ctx.get().get("enabled", False):
            path = _debug_get_log_path()
            debug_path = str(path) if path else None
        entry = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "program": program,
            "address": address,
            "function": func_name,
            "mode": mode,
            "model": selected_model,
            "provider": effective_provider,
            "requested_provider": requested_provider,
            "requested_model": requested_model,
            "provider_chain": provider_chain,
            "score_before": live_score,
            "score_after": final_score,
            "score_delta": score_delta,
            "result": logged_result,
            "tool_calls": tool_calls_made,
            "tool_calls_known": tool_calls_known,
            "complexity_tier": complexity_tier,
            "prompt_chars": len(prompt) if prompt else 0,
            "debug_log": debug_path,
            "missing_artifacts": missing_artifacts if missing_artifacts else None,
            "audit_provider": (
                audit_provider
                if (audit_provider and logged_result in ("completed", "partial"))
                else None
            ),
            "audit_outcome": audit_outcome,
            "audit_score_before": audit_score_before,
            "audit_score_after": audit_score_after,
            "audit_tool_calls": audit_tool_calls,
            "audit_tool_calls_known": audit_tool_calls_known,
            "input_tokens": meta.get("input_tokens"),
            "output_tokens": meta.get("output_tokens"),
            "output": output[:5000] if output else None,
            "reason": reason,
            "error": error,
            "provider_error": meta.get("provider_error"),
            "provider_error_type": meta.get("provider_error_type"),
            "provider_traceback": meta.get("provider_traceback"),
        }
        _append_run_log(entry)

    def _finish(
        return_value, *, logged_result=None, score_after=None, reason=None, error=None
    ):
        _log_run_once(
            logged_result or return_value,
            score_after=score_after,
            reason=reason,
            error=error,
        )
        return return_value

    bus_emit(
        "function_started",
        {
            "key": func_key,
            "name": name,
            "address": address,
            "program": func.get("program_name", ""),
        },
    )
    print(f"\n  {name} @ 0x{address} ({func['program_name']})")
    print(f"  {'-' * 50}")

    # Pre-flight: verify Ghidra is reachable before burning model tokens.
    # On first offline detection, attempt to auto-launch Ghidra and wait for
    # it to come back. If it stays offline, skip immediately.
    if not check_ghidra_online():
        print(
            f"  GHIDRA OFFLINE \u2014 server not reachable at {GHIDRA_URL}", flush=True
        )
        launched = try_launch_ghidra()
        if launched:
            came_online = wait_for_ghidra(timeout_secs=120, poll_interval=5)
            if came_online:
                print("  Ghidra is back online. Resuming...", flush=True)
            else:
                print(
                    "  Ghidra did not come online within 120s. Skipping function.",
                    flush=True,
                )
                func["last_result"] = "ghidra_offline"
                func["last_processed"] = datetime.now().isoformat()
                update_function_state(func_key, func)
                bus_emit(
                    "function_complete",
                    {"key": func_key, "result": "ghidra_offline", "score": None},
                )
                return _finish(
                    "failed",
                    logged_result="ghidra_offline",
                    reason="Ghidra did not come online within 120s",
                )
        else:
            func["last_result"] = "ghidra_offline"
            func["last_processed"] = datetime.now().isoformat()
            update_function_state(func_key, func)
            bus_emit(
                "function_complete",
                {"key": func_key, "result": "ghidra_offline", "score": None},
            )
            return _finish(
                "failed",
                logged_result="ghidra_offline",
                reason=f"server not reachable at {GHIDRA_URL}",
            )

    # Determine mode from current score (with smart promotion from cached state)
    mode = determine_mode(func.get("score"), func.get("deductions"), func)

    # Fetch live data from Ghidra
    print(f"  Fetching data...", end=" ", flush=True)
    data = fetch_function_data(program, address, mode=mode)
    live_score = data.get("score")
    print(f"done")

    # Defensive one-shot blacklist: if any decompile-heavy endpoint hit a
    # read timeout while fetching, the function is pathological (decompile
    # takes longer than the scoring path allows). Mark it and bail so the
    # selector stops re-picking it. Cleared by explicit refresh, same as
    # recovery_pass_done.
    if data.get("ghidra_offline"):
        print(
            f"  GHIDRA OFFLINE — cannot fetch function data. Skipping until Ghidra is reachable.",
            flush=True,
        )
        func["last_result"] = "ghidra_offline"
        func["last_processed"] = datetime.now().isoformat()
        update_function_state(func_key, func)
        bus_emit(
            "function_complete",
            {
                "key": func_key,
                "result": "ghidra_offline",
                "score": live_score,
            },
        )
        return _finish(
            "failed",
            logged_result="ghidra_offline",
            score_after=live_score,
            reason="cannot fetch function data",
        )

    if data.get("decompile_timeout"):
        func["decompile_timeout"] = True
        func["decompile_timeout_at"] = datetime.now().isoformat()
        func["last_processed"] = datetime.now().isoformat()
        func["last_result"] = "decompile_timeout"
        print(
            f"  DECOMPILE TIMEOUT — marking pathological and skipping. "
            f"Will be excluded from selector until next refresh. "
            f"(Pin the function to force a retry.)",
            flush=True,
        )
        update_function_state(func_key, func)
        bus_emit(
            "function_complete",
            {
                "key": func_key,
                "result": "decompile_timeout",
                "score": live_score,
            },
        )
        return _finish(
            "decompile_timeout",
            score_after=live_score,
            reason="decompile-heavy endpoint hit read timeout",
        )

    # Refine mode based on live score and completeness context
    mode = determine_mode(live_score, data.get("deductions"), data.get("completeness"))

    # Capture the PRE-sync cached score so the skip message and stale-skip
    # counter can compare against the real stale value instead of the live
    # value (_sync_func_state overwrites func["score"] with live_score below).
    original_cached_score = func.get("score")

    # Sync point 1: update state.json with live data from Ghidra (pre-work).
    # Uses update_function_state() so concurrent workers don't clobber each
    # other's unrelated function updates via whole-state save.
    _sync_func_state(func, data.get("completeness"), live_score, data.get("deductions"))
    update_function_state(func_key, func)

    # Capture pre-work artifact snapshot for post-run validation
    pre_completeness = data.get("completeness") or {}
    pre_has_plate = pre_completeness.get("has_plate_comment", False)
    pre_has_custom_name = pre_completeness.get("has_custom_name", False)
    pre_fixable_cats = set(
        d.get("category")
        for d in pre_completeness.get("deduction_breakdown", [])
        if d.get("fixable", False)
    )

    # Short-circuit: skip well-documented functions in auto mode only
    # Manual mode always builds a prompt (for review/audit)
    if not manual:
        completeness = data.get("completeness")
        fixable_pts = (
            float(completeness.get("fixable_deductions", 999)) if completeness else 999
        )

        # Re-check the "good enough" threshold against the freshly fetched live
        # score. State.json scores can drift stale; without this gate, a function
        # the selector picked at (cached) 76% but is live 93% still burns tokens.
        # Pinned functions bypass the gate (user explicitly queued them).
        # `good_enough_score` is read from the worker's frozen snapshot when one
        # was supplied, so two workers started at different times under
        # different thresholds don't get their behavior altered mid-run by
        # someone moving the slider in the dashboard.
        queue = load_priority_queue()
        cfg = queue.get("config") or DEFAULT_QUEUE_CONFIG
        if config_snapshot is not None:
            good_enough = int(config_snapshot.get("good_enough_score", 80))
        else:
            good_enough = cfg.get("good_enough_score", 80)
        is_pinned = func_key in set(queue.get("pinned", []))

        # Pinned functions used to bypass this gate so the user could force
        # processing. New behavior: still run the gate for pinned items, but
        # auto-dequeue them when they hit it. That way "I queued this once" no
        # longer means "polish this forever after it's already done."
        if live_score is not None and live_score >= good_enough:
            if original_cached_score is None or original_cached_score == 0:
                cached_label = "unscored"
            else:
                cached_label = f"{original_cached_score}%"
            reason = (
                f"live score {live_score}% >= good_enough {good_enough}% "
                f"(cached was {cached_label})"
            )
            print(f"  SKIP: {reason}")
            func["last_result"] = "skipped_above_threshold"
            func["last_processed"] = datetime.now().isoformat()
            update_function_state(func_key, func)
            if (
                isinstance(original_cached_score, (int, float))
                and abs(live_score - original_cached_score) >= 5
            ):
                _increment_stale_skip_counter()
            auto_dequeue_if_done(func_key, live_score, source="skipped_above_threshold")
            _emit_skip(func_key, "above_threshold", reason, live_score)
            return _finish(
                "skipped",
                logged_result="skipped_above_threshold",
                score_after=live_score,
                reason=reason,
            )

        # FIX mode only: skip if there's almost nothing fixable regardless of score
        if mode == "FIX" and fixable_pts < 3:
            reason = f"FIX mode but only {fixable_pts:.1f} fixable pts remaining"
            print(f"  SKIP: {reason}")
            func["last_result"] = "skipped_complete"
            func["last_processed"] = datetime.now().isoformat()
            update_function_state(func_key, func)
            auto_dequeue_if_done(func_key, live_score, source="skipped_no_fixable")
            _emit_skip(func_key, "no_fixable", reason, live_score)
            return _finish(
                "skipped",
                logged_result="skipped_complete",
                score_after=live_score,
                reason=reason,
            )

        if mode == "VERIFY":
            reason = "100% complete"
            print(f"  SKIP: {reason}")
            func["last_result"] = "skipped_complete"
            func["last_processed"] = datetime.now().isoformat()
            update_function_state(func_key, func)
            auto_dequeue_if_done(func_key, live_score, source="skipped_verify")
            _emit_skip(func_key, "verify_complete", reason, live_score)
            return _finish(
                "skipped",
                logged_result="skipped_complete",
                score_after=live_score,
                reason=reason,
            )

    # Select model
    try:
        selected_model = select_model(mode, model, provider=provider, config_snapshot=config_snapshot)
    except ValueError as e:
        reason = str(e)
        print(f"  CONFIG ERROR: {reason}", flush=True)
        func["last_result"] = "config_error"
        func["last_processed"] = datetime.now().isoformat()
        update_function_state(func_key, func)
        bus_emit(
            "function_complete",
            {
                "key": func_key,
                "result": "config_error",
                "score": live_score,
                "error": reason,
            },
        )
        return _finish(
            "failed",
            logged_result="config_error",
            score_after=live_score,
            error=reason,
        )

    # Build prompt
    func_name = (
        data["completeness"].get("function_name", name)
        if data["completeness"]
        else name
    )

    if mode == "VERIFY" and manual:
        # Manual mode: use FIX prompt with opportunistic checks for review
        mode = "FIX"
        prompt = build_fix_prompt(func_name, address, data, program=program)
    elif mode == "VERIFY":
        prompt = build_verify_prompt(func_name, address, data, program=program)
    elif mode == "FIX":
        prompt = build_fix_prompt(func_name, address, data, program=program)
    else:
        # Need full analysis if not already fetched
        if not data["analyze_for_doc"]:
            print(f"  Fetching full analysis...", end=" ", flush=True)
            data["analyze_for_doc"] = ghidra_get(
                "/analyze_for_documentation",
                params={"function_address": f"0x{address}", "program": program},
                timeout=60,
            )
            print("done")
        prompt = build_full_doc_prompt(func_name, address, data, program=program)

    # Gemini has native MCP discovery — skip injecting tool block
    effective_provider_for_tools = effective_provider
    if effective_provider_for_tools != "gemini":
        prompt = _inject_tool_block(prompt)

    # Pre-flight complexity gate
    complexity_tier = _estimate_complexity(data.get("completeness"))
    complexity_forced_recovery = False

    # Risk-based two-pass decision (replaces crude prompt-length heuristic)
    use_two_pass = False
    if mode == "FULL" and not manual:
        completeness = data.get("completeness")
        if completeness and isinstance(completeness, dict):
            fixable_pts = float(completeness.get("fixable_deductions", 0))
            _score = data.get("score", 100)
            deduction_cats = {
                d.get("category")
                for d in completeness.get("deduction_breakdown", [])
                if d.get("fixable", False)
            }
            has_struct_work = "unresolved_struct_accesses" in deduction_cats
            has_plate_work = not completeness.get("has_plate_comment", True)
            # Two-pass when: lots of fixable work, struct+comment combo, or very low score
            if (
                fixable_pts > 30
                or (has_struct_work and has_plate_work)
                or (_score is not None and _score < 30)
            ):
                use_two_pass = True

        # Massive functions: still use two-pass but NO LONGER force recovery-only.
        # The original reason for skipping Pass 2 on massive functions was EDT
        # saturation from long-running decompiles — that's been fixed by the 12s
        # decompile timeout (v5.3.1). With Pass 2 running, massive functions can
        # now reach good_enough_score in one attempt (Pass 1 types/names + Pass 2
        # comments). Without this change, recovery_pass_done blocked them forever.
        if complexity_tier == "massive":
            use_two_pass = True
            print(f"  COMPLEXITY: {complexity_tier} — two-pass mode")
    if use_two_pass:
        recovery_prompt = build_recovery_prompt(
            func_name, address, data, program=program
        )
        # Tool block injection is deferred until after provider finalization (handoff
        # may switch effective_provider to gemini, which uses native MCP discovery
        # and must NOT receive an injected tool block — doing so causes 0 tool calls).
        # Swap: run recovery prompt first, then re-fetch and build FIX prompt for pass 2
        prompt = recovery_prompt
        mode = "FULL:recovery"

    # Complexity gate: skip functions too complex for MiniMax
    if effective_provider == "minimax" and mode in ("FULL", "FULL:recovery"):
        completeness = data.get("completeness")
        if completeness and isinstance(completeness, dict):
            fixable_pts = float(completeness.get("fixable_deductions", 0))
            deduction_cats = {
                d.get("category")
                for d in completeness.get("deduction_breakdown", [])
                if d.get("fixable", False)
            }
            has_struct_work = "unresolved_struct_accesses" in deduction_cats
            has_many_undefined = len(completeness.get("undefined_variables", [])) > 8
            # MiniMax struggles with: high structural complexity + many undefined vars
            if fixable_pts > 40 and (has_struct_work and has_many_undefined):
                undef_count = len(completeness.get("undefined_variables", []))
                detail = f"fixable={fixable_pts:.0f}, structs+{undef_count} undef vars"

                # Check whether auto-handoff is enabled
                queue_now = load_priority_queue()
                cfg_now = queue_now.get("config") or DEFAULT_QUEUE_CONFIG
                handoff_provider = cfg_now.get("complexity_handoff_provider") or None
                handoff_max = int(cfg_now.get("complexity_handoff_max", 0) or 0)
                handoff_count = int(
                    (queue_now.get("meta") or {}).get("handoffs_this_session", 0)
                )
                cap_reached = handoff_max > 0 and handoff_count >= handoff_max

                # Q10: don't hand off to a walled provider — primary keeps
                # the function. The handoff target's model is what matters
                # for the wall, so resolve it before the gate check.
                handoff_target_walled = False
                if handoff_provider and handoff_provider != effective_provider:
                    try:
                        from provider_pause import get_default_manager as _get_pm

                        _handoff_model = select_model(
                            mode, provider=handoff_provider, config_snapshot=config_snapshot
                        )
                        if _handoff_model and _get_pm().is_paused(
                            handoff_provider, _handoff_model
                        ):
                            handoff_target_walled = True
                            print(
                                f"  [handoff] skipped — {handoff_provider}/"
                                f"{_handoff_model} walled; primary continues",
                                flush=True,
                            )
                    except Exception:  # noqa: BLE001 — don't let pause check break handoff
                        pass

                can_handoff = (
                    handoff_provider
                    and handoff_provider != effective_provider
                    and not cap_reached
                    and not handoff_target_walled
                )

                if can_handoff:
                    new_count = _bump_handoff_counter()
                    handoff_reason = f"{detail} — handoff #{new_count}"
                    # The mode banner that prints next includes the new
                    # provider's model when it deviates from the worker's
                    # snapshot, which IS the handoff signal. The standalone
                    # banner here was redundant with that — the deviation
                    # in the mode banner tells you handoff fired and where
                    # to. We still emit the function_mode bus event so the
                    # dashboard pane shows HANDOFF:from->to.
                    _emit_handoff(
                        func_key,
                        effective_provider,
                        handoff_provider,
                        handoff_reason,
                        new_count,
                        score=live_score,
                    )
                    # Stamp per-function escalation tracking
                    func["escalation_count"] = func.get("escalation_count", 0) + 1
                    func["last_escalated"] = datetime.now().isoformat()
                    func["last_escalation_from"] = effective_provider
                    func["last_escalation_to"] = handoff_provider
                    update_function_state(func_key, func)
                    # Swap provider for the rest of this function's processing
                    provider = handoff_provider
                    effective_provider = handoff_provider
                    provider_chain.append(handoff_provider)
                    _debug_update_context(provider=effective_provider)
                    # Re-select the model for the new provider.
                    # FULL:recovery and FULL:comments are sub-modes of FULL — use the
                    # FULL dashboard config for model lookup after a handoff.
                    lookup_mode = "FULL" if str(mode).startswith("FULL:") else mode
                    try:
                        selected_model = select_model(
                            lookup_mode, model, provider=provider,
                            config_snapshot=config_snapshot,
                        )
                    except ValueError as e:
                        reason = str(e)
                        print(f"  CONFIG ERROR: {reason}", flush=True)
                        func["last_result"] = "config_error"
                        func["last_processed"] = datetime.now().isoformat()
                        update_function_state(func_key, func)
                        _emit_skip(func_key, "config_error", reason, live_score)
                        return _finish(
                            "failed",
                            logged_result="config_error",
                            score_after=live_score,
                            error=reason,
                        )
                    # Fall through to invoke_claude — do NOT return
                else:
                    # Handoff isn't available (none configured / cap reached /
                    # target walled). Previously this skipped the function and
                    # bumped consecutive_fails. That's wrong: if the user chose
                    # not to configure a handoff, or the cap is reached, or the
                    # target is temporarily walled, the right behavior is to
                    # let the primary provider try the function with its own
                    # model. Worst case the score doesn't improve and the
                    # function naturally moves on; we don't penalize it for
                    # something that's a deployment / config decision rather
                    # than a quality signal.
                    if handoff_provider and cap_reached:
                        note = (
                            f"Complex function ({detail}) — handoff cap "
                            f"{handoff_max} reached, primary continues"
                        )
                    elif handoff_target_walled:
                        note = (
                            f"Complex function ({detail}) — handoff target "
                            f"{handoff_provider} walled, primary continues"
                        )
                    else:
                        note = (
                            f"Complex function ({detail}) — no handoff configured, "
                            f"primary continues"
                        )
                    print(f"  NOTE: {note}", flush=True)
                    # Intentionally fall through with current provider/model.

    # Inject tool block for recovery pass now that the final provider is known.
    # Gemini uses native MCP tool discovery — injecting a tool list into its prompt
    # causes it to make 0 tool calls. All other providers need the injection.
    if use_two_pass and effective_provider != "gemini":
        prompt = _inject_tool_block(prompt)

    bus_emit(
        "function_mode",
        {"key": func_key, "mode": mode, "model": selected_model, "score": live_score},
    )
    _debug_update_context(provider=effective_provider)
    print(_format_mode_banner(mode, selected_model, effective_provider, live_score, config_snapshot, prompt))

    if dry_run:
        print(
            f"  DRY RUN: Would invoke {'pass 1 (recovery)' if use_two_pass else 'Claude'}"
        )
        return _finish("dry_run", score_after=live_score)

    # Manual mode
    if manual:
        try:
            import pyperclip

            has_pyperclip = True
        except ImportError:
            has_pyperclip = False

        # Copy prompt to clipboard
        if has_pyperclip:
            pyperclip.copy(prompt)
            print(f"\n  Prompt copied to clipboard ({len(prompt)} chars)")
        else:
            try:
                subprocess.run(
                    ["clip.exe"], input=prompt.encode("utf-16-le"), check=True
                )
                print(
                    f"\n  Prompt copied to clipboard via clip.exe ({len(prompt)} chars)"
                )
            except Exception:
                print(f"\n  Prompt ready ({len(prompt)} chars)")

        print(f"  Press any key to continue, [q] to quit...")

        key = _read_single_key()
        func["last_result"] = "manual_prompt_generated"
        func["last_processed"] = datetime.now().isoformat()
        new_score, _ = _rescore_and_sync(func, address, program)
        if new_score is not None:
            delta = ""
            if live_score is not None:
                diff = new_score - live_score
                delta = f" ({'+' if diff >= 0 else ''}{diff:.0f}%)"
            print(f"  Score after: {new_score}%{delta}")
        update_function_state(func_key, func)
        if key == "q":
            return _finish("quit", score_after=new_score)
        return _finish("manual_prompt_generated", score_after=new_score)

    # Per-provider max_turns. Snapshot wins when present (frozen for the
    # worker's life), falling through to live config for legacy/CLI invocations
    # that don't have a worker context.
    if config_snapshot is not None:
        snap_providers = config_snapshot.get("providers") or {}
        snap_entry = snap_providers.get(effective_provider) or {}
        if snap_entry:
            worker_max_turns = int(snap_entry.get("max_turns", 25))
        else:
            # Snapshot exists but didn't capture this provider — happens when
            # an unconfigured-at-start escalation/handoff target gets invoked.
            # Fall through to live config rather than guessing wrong.
            _pmt = cfg.get("provider_max_turns") or {}
            worker_max_turns = int(_pmt.get(effective_provider, 25))
    else:
        _pmt = cfg.get("provider_max_turns") or {}
        worker_max_turns = int(_pmt.get(effective_provider, 25))

    # Auto mode: invoke AI (provider based on AI_PROVIDER)
    print()
    output, meta = invoke_claude(
        prompt,
        model=selected_model,
        provider=provider,
        complexity_tier=complexity_tier,
        max_turns=worker_max_turns,
    )
    tool_calls_made = meta.get("tool_calls", -1)
    tool_calls_known = bool(meta.get("tool_calls_known", tool_calls_made != -1))

    # Quota wall short-circuit (Q2): the provider returned `quota_paused`
    # because (provider, model) is currently walled. Log the run as
    # `quota_paused` so it appears in runs.jsonl for diagnostics, but DO
    # NOT bump consecutive_fails — the wall is an account-wide transient
    # condition, not a per-function quality signal. The worker loop will
    # see the pause on its next iteration and yield until reset.
    if meta.get("quota_paused"):
        result = "quota_paused"
        func["last_processed"] = datetime.now().isoformat()
        func["last_result"] = result
        # consecutive_fails counter intentionally untouched (Q2).
        until_iso = meta.get("quota_paused_until")
        reason = meta.get("quota_paused_reason") or "quota wall"
        print(
            f"  Quota wall: {provider}/{selected_model} paused until "
            f"{until_iso} — function deferred ({reason})",
            flush=True,
        )
        return _finish(
            "quota_paused",
            logged_result="quota_paused",
            score_after=live_score,
            reason=f"quota_paused until {until_iso}",
        )

    # Two-pass: if recovery pass made tool calls, run pass 2 (comments) with fresh data
    # Don't gate on "DONE:" text — the model may produce think-only output or empty response
    # Skip pass 2 for massive functions — they need multiple sessions
    #
    # tool_calls_made can be:
    #   > 0: provider reported N tool calls (minimax)
    #   == 0: provider reported zero tool calls (model made none)
    #   == -1: provider doesn't report tool counts (codex, claude) — treat as "trust the run"
    #
    # Using `!= 0` (instead of `> 0`) lets codex/claude runs proceed to Pass 2.
    # Without this, codex runs on functions that trigger use_two_pass (fixable_pts > 30)
    # stall at Pass 1 score forever because Pass 2 (comments) is what typically pushes
    # the score past good_enough_score. Observed as an infinite re-pick loop on
    # GetUnitSoundId @ 0x6fad2430: 7 runs in 2 hours, never reaching Pass 2, score
    # oscillating 57-61% below the 80% threshold.
    if use_two_pass and tool_calls_made != 0 and not complexity_forced_recovery:
        print(
            f"\n  Pass 1 (recovery) complete. Re-fetching data for pass 2 (comments)..."
        )
        data2 = fetch_function_data(program, address, mode="FIX")
        mid_score = data2.get("score")
        func_name2 = (
            data2["completeness"].get("function_name", func_name)
            if data2.get("completeness")
            else func_name
        )
        prompt2 = build_fix_prompt(func_name2, address, data2, program=program)
        if effective_provider != "gemini":
            prompt2 = _inject_tool_block(prompt2)
        mode = "FULL:comments"
        print(_format_mode_banner(mode, selected_model, effective_provider, mid_score, config_snapshot, prompt2))
        print()
        output2, meta2 = invoke_claude(
            prompt2,
            model=selected_model,
            provider=provider,
            complexity_tier=complexity_tier,
            max_turns=worker_max_turns,
        )
        # Merge results: use pass 2 output for final parsing, sum tool calls.
        # Sentinel -1 means "unknown" — don't let -1 + -1 = -2 break
        # downstream guards that check for -1 specifically.
        if output2:
            output = output2
        tc2 = meta2.get("tool_calls", 0)
        tc2_known = bool(meta2.get("tool_calls_known", tc2 != -1))
        if tool_calls_made == -1 and tc2 == -1:
            tool_calls_made = -1  # still unknown
        elif tool_calls_made == -1:
            tool_calls_made = tc2  # use the known value
        elif tc2 != -1:
            tool_calls_made += tc2  # both known, sum normally
        tool_calls_known = tool_calls_known or tc2_known

    # Parse result
    result = "completed"
    if output:
        # Check success markers FIRST — models sometimes mention rate limits,
        # blocked states, etc. in their reasoning text while ultimately
        # succeeding. DONE/VERIFIED OK take absolute priority.
        rate_limit_phrases = [
            "hit your limit",
            "rate limit",
            "resets ",
            "usage limit",
            "try again at",
        ]
        if "DONE:" in output:
            result = "completed"
        elif "VERIFIED OK:" in output or "QUICK FIX:" in output:
            result = "completed"
        elif any(phrase in output.lower() for phrase in rate_limit_phrases):
            # Only fire when no DONE marker — this is a real API rate limit,
            # not the model discussing "rate limiting" in game code analysis.
            print(f"  RATE LIMITED on this function", flush=True)
            result = "rate_limited"
        elif "BLOCKED:" in output:
            # Check BLOCKED after DONE — models sometimes mention a previous
            # BLOCKED attempt in their reasoning text before ultimately
            # succeeding with a DONE marker. DONE takes priority.
            result = "blocked"
        elif "NEEDS REDO:" in output:
            result = "needs_redo"
    elif tool_calls_made >= 1 or tool_calls_made == -1:
        # Empty output (no final text block) but the model made tool calls
        # (or the provider doesn't report tool counts, i.e. -1). The writes
        # already hit Ghidra. Trust the work initially; downstream guards
        # catch real problems:
        #   Guard #2b: score regression → downgrade to partial
        #   stagnation_runs: 3+ no-progress completions → selector excludion
        #
        # Previously required >= 5 tools, which missed minimax Pass-2 runs
        # that typically make 2-5 tool calls (set_function_prototype,
        # batch_set_comments, rename_variables). The _fseek case had 3
        # successful Ghidra writes but was marked failed at the old threshold.
        print(
            f"  NOTE: empty output with {tool_calls_made} tool calls — "
            f"trusting work, score delta will verify",
            flush=True,
        )
        result = "completed"
    else:
        result = "failed"

    # Guard #1: no tool actions = not a real completion
    if (
        result == "completed"
        and tool_calls_made == 0
        and mode not in ("VERIFY", "FULL:comments")
    ):
        print(
            f"  WARNING: Model reported DONE but made 0 tool calls — downgrading to needs_redo"
        )
        result = "needs_redo"

    # Update state
    func["last_processed"] = datetime.now().isoformat()
    func["last_result"] = result

    # Track consecutive failures for cooldown logic (atomic read-modify-write)
    # Reload the specific function entry to avoid stale overwrites from parallel workers
    fresh_state = load_state()
    fresh_func = fresh_state.get("functions", {}).get(func_key, func)
    if result in ("failed", "needs_redo", "rate_limited", "blocked"):
        fresh_func["consecutive_fails"] = fresh_func.get("consecutive_fails", 0) + 1
        func["consecutive_fails"] = fresh_func["consecutive_fails"]
    elif result == "completed":
        fresh_func["consecutive_fails"] = 0
        func["consecutive_fails"] = 0
    # Copy the updated counter back to our state dict
    if func_key in state.get("functions", {}):
        state["functions"][func_key]["consecutive_fails"] = func["consecutive_fails"]

    # Sync point 2: re-score after auto-mode completion
    new_score, post_completeness = _rescore_and_sync(func, address, program)
    missing_artifacts = []  # Track what the model failed to deliver
    if new_score is not None:
        delta = ""
        if live_score is not None:
            diff = new_score - live_score
            delta = f" ({'+' if diff >= 0 else ''}{diff:.0f}%)"

        # Guard #2: score didn't improve AND no write tools called = needs redo
        # A +0% with actual write operations (batch_set_comments, rename, set_type)
        # is valid — the scorer may round to the same integer after minor fixes.
        # tool_calls_made == -1 means "unknown" (Claude SDK doesn't track) — don't penalize
        if (
            result == "completed"
            and live_score is not None
            and diff <= 0
            and tool_calls_made
            == 0  # Only downgrade when we KNOW zero tools were called
            and mode in ("FULL", "FIX", "FULL:recovery", "FULL:comments")
        ):
            print(
                f"\n  Score after: {new_score}%{delta} | no improvement and no tool calls — downgrading to needs_redo"
            )
            result = "needs_redo"
            func["last_result"] = result
        else:
            print(f"\n  Score after: {new_score}%{delta} | Result: {result}")

        # Guard #2b: score regression detection
        # If score dropped significantly and model claimed completion, downgrade
        if result == "completed" and live_score is not None and diff < -5:
            print(
                f"  WARNING: Score regressed by {abs(diff):.0f}% — downgrading to partial"
            )
            missing_artifacts.append("score_regression")
            result = "partial"
            func["last_result"] = result

        # Guard #3: artifact-based completion validation
        # Check that high-value artifacts the model should have produced actually exist.
        # This catches models that claim DONE but skip key deliverables (e.g. plate comment).
        if (
            result == "completed"
            and post_completeness
            and mode not in ("VERIFY", "FULL:recovery")
        ):
            post_has_plate = post_completeness.get("has_plate_comment", False)
            post_has_custom_name = post_completeness.get("has_custom_name", False)
            post_fixable_cats = set(
                d.get("category")
                for d in post_completeness.get("deduction_breakdown", [])
                if d.get("fixable", False)
            )

            # Check: plate comment should exist after FULL or FIX with plate deduction
            if not post_has_plate and (
                mode == "FULL"
                or mode == "FULL:comments"
                or "missing_plate_comment" in pre_fixable_cats
            ):
                missing_artifacts.append("plate_comment")

            # Check: plate comment has Source section (non-wrapper/stub functions)
            post_plate_issues = post_completeness.get("plate_issues", 0)
            post_classification = post_completeness.get("classification", "unknown")
            if (
                post_has_plate
                and post_plate_issues > 0
                and post_classification not in ("stub", "thunk")
                and mode in ("FULL", "FULL:comments", "FIX")
            ):
                print(
                    f"  WARNING: Plate comment has {post_plate_issues} structural issue(s) (likely missing Source section)"
                )
                missing_artifacts.append("plate_incomplete")

            # Check: function should have a custom name after FULL mode
            if not post_has_custom_name and mode in ("FULL", "FULL:comments"):
                missing_artifacts.append("custom_name")

            # Identity check: warn if function name didn't change when it should have
            post_func_name = post_completeness.get("function_name", "")
            if (
                post_func_name
                and post_func_name == func_name
                and not pre_has_custom_name
                and mode in ("FULL", "FULL:comments")
            ):
                print(
                    f"  WARNING: Function still has original name '{func_name}' after FULL mode"
                )

            # Check: fixable deductions that were present before but not resolved
            # Only flag high-value categories that the prompt explicitly asked to fix
            HIGH_VALUE_CATS = {
                "missing_plate_comment",
                "address_suffix_name",
                "missing_prototype",
                "return_type_unresolved",
                "plate_comment_stub",
                "plate_comment_incomplete",
            }
            still_present = pre_fixable_cats & post_fixable_cats & HIGH_VALUE_CATS
            for cat in still_present:
                if cat not in ("missing_plate_comment",):  # Already checked above
                    missing_artifacts.append(cat)

            if missing_artifacts:
                print(
                    f"  WARNING: Model claimed DONE but missing artifacts: {', '.join(missing_artifacts)}"
                    f" — downgrading to partial"
                )
                result = "partial"
                func["last_result"] = result

        # Guard #4: post-pass Hungarian audit
        # Mechanical check: verify renamed variables have correct prefix for their type.
        # Also count leftover generic-named variables the model didn't rename.
        if result in ("completed", "partial") and tool_calls_made > 0:
            hungarian_issues, generic_remaining = _audit_hungarian_compliance(
                address, program
            )
            if hungarian_issues:
                issue_summary = "; ".join(
                    f"{i['var']}({i['prefix']}→{i['type']})"
                    for i in hungarian_issues[:5]
                )
                print(
                    f"  HUNGARIAN AUDIT: {len(hungarian_issues)} prefix/type mismatch(es): {issue_summary}"
                )
                if result == "completed" and len(hungarian_issues) >= 2:
                    missing_artifacts.append("hungarian_mismatches")
                    result = "partial"
                    func["last_result"] = result
                    print(
                        f"  — downgrading to partial ({len(hungarian_issues)} mismatches)"
                    )
            if generic_remaining > 0:
                print(
                    f"  VARIABLE AUDIT: {generic_remaining} generic-named variable(s) remaining"
                )
                if (
                    result == "completed"
                    and generic_remaining >= 3
                    and mode in ("FULL", "FULL:recovery", "FULL:comments")
                ):
                    missing_artifacts.append("generic_variables")
                    result = "partial"
                    func["last_result"] = result
                    print(
                        f"  — downgrading to partial ({generic_remaining} unrenamed variables)"
                    )

        # Guard #5: magic number EOL comment reconciliation
        # If the scorer reports undocumented magic numbers, the model skipped EOL comments.
        # Flag for requeue rather than accepting incomplete documentation.
        if (
            result == "completed"
            and post_completeness
            and mode not in ("VERIFY", "FULL:recovery")
        ):
            magic_undoc = post_completeness.get("magic_numbers_undocumented", 0)
            post_classification = post_completeness.get("classification", "unknown")
            if magic_undoc >= 2 and post_classification not in ("wrapper", "stub"):
                print(
                    f"  MAGIC NUMBER AUDIT: {magic_undoc} undocumented magic number(s) — "
                    "model wrote plate comment but skipped EOL comments at usage sites"
                )
                missing_artifacts.append("magic_numbers_undocumented")
                result = "partial"
                func["last_result"] = result
    else:
        print(f"\n  Result: {result} | Score: unavailable")

    # ── Audit stage ─────────────────────────────────────────────────────
    # If configured, run a second provider to review and fix gaps.
    # Only fires when: audit_provider is set, worker result was usable,
    # score gain was below the min-delta threshold, and the function isn't
    # already at the good-enough score.
    audit_score_before = None
    audit_score_after = None
    audit_outcome = None  # "skipped_good_enough", "skipped_delta", "ran", or None
    audit_tool_calls = None
    audit_tool_calls_known = None
    if config_snapshot is not None:
        # Frozen snapshot: audit policy was decided at worker start. Even if
        # the dashboard dropdown moves mid-run, this worker keeps its original
        # audit configuration for every function it processes.
        audit_provider = config_snapshot.get("audit_provider")
        audit_min_delta = int(config_snapshot.get("audit_min_delta", 5))
    else:
        audit_cfg = (
            cfg
            if "audit_provider" in cfg
            else ((load_priority_queue().get("config") or DEFAULT_QUEUE_CONFIG))
        )
        audit_provider = audit_cfg.get("audit_provider")
        audit_min_delta = audit_cfg.get("audit_min_delta", 5)

    if (
        audit_provider
        and result in ("completed", "partial")
        and new_score is not None
        and live_score is not None
        and mode not in ("VERIFY", "FULL:recovery")
    ):
        worker_diff = new_score - live_score
        # Use the snapshot's good_enough when present so an audit decision
        # is consistent with the gate decision earlier in this same function.
        if config_snapshot is not None:
            good_enough = int(config_snapshot.get("good_enough_score", 80))
        else:
            good_enough = audit_cfg.get("good_enough_score", 80)

        if new_score >= good_enough:
            audit_outcome = "skipped_good_enough"
            print(
                f"  [audit] skipped — score {new_score}% already >= good_enough {good_enough}%"
            )
        elif worker_diff >= audit_min_delta:
            audit_outcome = "skipped_delta"
            print(
                f"  [audit] skipped — worker gained {worker_diff:.0f}% (>= minΔ {audit_min_delta})"
            )
        else:
            print(
                f"\n  [audit] {audit_provider}: reviewing (worker Δ{worker_diff:.0f}% < minΔ {audit_min_delta})"
            )
            bus_emit(
                "audit_start",
                {
                    "key": func_key,
                    "provider": audit_provider,
                    "worker_delta": worker_diff,
                },
            )

            # Fetch fresh data for the FIX-mode audit pass
            audit_data = fetch_function_data(program, address, mode="FIX")
            audit_func_name = (
                audit_data["completeness"].get("function_name", func_name)
                if audit_data.get("completeness")
                else func_name
            )
            audit_prompt = build_fix_prompt(
                audit_func_name, address, audit_data, program=program
            )
            # Inject tool block for non-Gemini providers
            if audit_provider != "gemini":
                audit_prompt = _inject_tool_block(audit_prompt)

            audit_score_before = new_score
            try:
                audit_model = select_model(
                    "FIX", provider=audit_provider, config_snapshot=config_snapshot
                )
            except ValueError as e:
                audit_outcome = "config_error"
                print(f"  [audit] skipped — {e}")
                bus_emit(
                    "audit_complete",
                    {
                        "key": func_key,
                        "provider": audit_provider,
                        "score_before": audit_score_before,
                        "score_after": None,
                    },
                )
            else:
                audit_outcome = "ran"
                print(
                    f"  [audit] FIX | {audit_provider} | {len(audit_prompt):,} chars | score: {new_score}%"
                )
                print()
                audit_output, audit_meta = invoke_claude(
                    audit_prompt,
                    model=audit_model,
                    provider=audit_provider,
                    max_turns=15,
                )
                # Q10: when audit's provider+model is walled, skip silently.
                # Audit is a quality second-pass; a missed audit is harmless,
                # we don't want to log it as a failure or count it against
                # any threshold. The function keeps the primary worker's
                # score and moves on.
                if audit_meta.get("quota_paused"):
                    audit_outcome = "quota_paused"
                    audit_score_after = audit_score_before
                    audit_tool_calls = 0
                    audit_tool_calls_known = True
                    print(
                        f"  [audit] skipped — {audit_provider} walled until "
                        f"{audit_meta.get('quota_paused_until')}",
                        flush=True,
                    )
                    bus_emit(
                        "audit_complete",
                        {
                            "key": func_key,
                            "provider": audit_provider,
                            "score_before": audit_score_before,
                            "score_after": audit_score_before,
                            "outcome": "quota_paused",
                        },
                    )
                else:
                    audit_tool_calls = audit_meta.get("tool_calls", -1)
                    audit_tool_calls_known = bool(
                        audit_meta.get("tool_calls_known", audit_tool_calls != -1)
                    )

                # Skip rescore when audit was quota-paused — the call never
                # touched Ghidra so the score can't have changed.
                if audit_outcome == "quota_paused":
                    audit_new_score, audit_completeness = None, None
                else:
                    # Rescore after audit
                    audit_new_score, audit_completeness = _rescore_and_sync(
                        func, address, program
                    )
                if audit_new_score is not None:
                    audit_score_after = audit_new_score
                    audit_diff = audit_new_score - audit_score_before
                    print(
                        f"\n  [audit] {audit_provider}: done — "
                        f"{audit_score_before}% -> {audit_new_score}% "
                        f"({'+' if audit_diff >= 0 else ''}{audit_diff:.0f}%), "
                        f"{audit_tool_calls} tool calls"
                    )
                    # Update tracked values for downstream logging
                    new_score = audit_new_score
                    post_completeness = audit_completeness
                    tool_calls_made += audit_tool_calls if audit_tool_calls > 0 else 0
                    # Upgrade partial to completed if audit pushed past issues
                    if result == "partial" and audit_diff > 0:
                        result = "completed"
                        func["last_result"] = result
                else:
                    print(f"\n  [audit] {audit_provider}: done — score unavailable")

                bus_emit(
                    "audit_complete",
                    {
                        "key": func_key,
                        "provider": audit_provider,
                        "score_before": audit_score_before,
                        "score_after": audit_new_score,
                    },
                )

                # Save program after audit writes
                if audit_tool_calls != 0:
                    ghidra_post("/save_program", params={"program": program})

                # Stamp per-function audit tracking
                func["audit_count"] = func.get("audit_count", 0) + 1
                func["last_audited"] = datetime.now().isoformat()
                func["last_audit_provider"] = audit_provider
                func["last_audit_delta"] = (
                    audit_diff if audit_new_score is not None else 0
                )
                update_function_state(func_key, func)

    # Track partial_runs for requeue deprioritization
    if result == "partial":
        func["partial_runs"] = func.get("partial_runs", 0) + 1

    # Log this run for audit trail. Early exits use the same helper so
    # runs.jsonl explains skips/config/offline failures too.
    _log_run_once(result)

    bus_emit(
        "score_update",
        {
            "key": func_key,
            "score_before": live_score,
            "score_after": new_score,
            "result": result,
        },
    )
    # Look up the post-rescore name so the dashboard's function-block
    # footer can show the renamed function (the model often calls
    # rename_function_by_address during documentation). State has been
    # synced via _rescore_and_sync above, so it's the source of truth.
    fresh_name_for_event = func.get("name")
    try:
        _fresh_state = load_state()
        _entry = (_fresh_state.get("functions") or {}).get(func_key)
        if _entry and _entry.get("name"):
            fresh_name_for_event = _entry["name"]
    except Exception:
        pass
    bus_emit(
        "function_complete",
        {
            "key": func_key,
            "result": result,
            "score": new_score,
            "name": fresh_name_for_event,
            "address": address,
        },
    )

    # Save program to persist changes in Ghidra
    if result in ("completed", "needs_redo", "partial") and tool_calls_made > 0:
        ghidra_post("/save_program", params={"program": program})

    # Auto-dequeue on successful completion if the user explicitly queued this
    # function and it reached the good-enough threshold.
    if result == "completed":
        auto_dequeue_if_done(func_key, new_score, source="completed")

    # Recovery-pass one-shot: mark functions that finished a complexity-forced
    # recovery pass so the selector doesn't re-pick them on every cycle. These
    # massive functions legitimately can't reach good_enough_score in one pass
    # — re-queuing burns extra provider budget for marginal improvement. The
    # flag clears on `--scan --refresh` or `refresh_candidate_scores`, or can
    # be bypassed by pinning the function explicitly.
    # Don't flag leaf functions — they're self-contained and should always
    # get another chance via the normal stagnation guard. The "massive"
    # classifier triggers on fixable_pts > 50 regardless of function size,
    # so a 10-line leaf with many undefined variables gets incorrectly
    # forced into recovery-only mode and stuck forever.
    is_leaf_func = not func.get("callees")
    if (
        complexity_forced_recovery
        and mode == "FULL:recovery"
        and result in ("completed", "partial")
        and not is_leaf_func
    ):
        func["recovery_pass_done"] = True
        func["recovery_pass_score"] = new_score
        func["recovery_pass_at"] = datetime.now().isoformat()

    # Stagnation tracking: count consecutive runs that made no meaningful
    # progress. This is a general safety net that catches infinite re-pick
    # loops for any provider/function combination the other guards miss.
    #
    # Real-world trigger: codex runs on use_two_pass-eligible functions where
    # Pass 2 was previously gated out (fixed separately), producing score
    # deltas of +0% across many runs. Without this guard nothing would blacklist
    # the function and the worker would re-pick it forever.
    #
    # Semantics:
    #   - Increment on any completed/partial/blocked run with delta <= 1 (no progress
    #     OR regression). -1% dropped via Guard #2b to "partial" still counts.
    #     Blocked runs always count (delta is always 0 when the model narrates
    #     instead of calling tools).
    #   - Reset to 0 on meaningful positive progress (delta >= 5).
    #   - Not touched by failed/needs_redo/rate_limited (consecutive_fails
    #     already covers those).
    #   - Selector skips funcs with stagnation_runs >= 3 (see select_candidates).
    #   - Cleared by refresh_candidate_scores and full --scan --refresh, same
    #     as the other one-shot flags.
    if (
        result in ("completed", "partial", "blocked")
        and new_score is not None
        and live_score is not None
    ):
        _diff = new_score - live_score
        if _diff <= 1:
            func["stagnation_runs"] = func.get("stagnation_runs", 0) + 1
        elif _diff >= 5:
            func["stagnation_runs"] = 0

    # Atomic per-function save: only write THIS function's entry, re-reading
    # disk state inside the lock so other workers' concurrent updates to
    # different functions are preserved instead of clobbered.
    update_function_state(func_key, func)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Fun-Doc: Intelligent function documentation engine"
    )
    parser.add_argument(
        "--auto", action="store_true", help="Auto-mode: document next best functions"
    )
    parser.add_argument(
        "--count",
        "-n",
        type=int,
        default=1,
        help="Number of functions to process (default: 1)",
    )
    parser.add_argument(
        "-s",
        "--select",
        action="store_true",
        help="Select mode: document current function + neighbors",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=0,
        help="Call graph depth for select mode (default: 0, just the selected function)",
    )
    parser.add_argument(
        "-m",
        "--manual",
        action="store_true",
        help="Manual mode: copy prompts to clipboard",
    )
    parser.add_argument("--status", action="store_true", help="Show progress dashboard")
    parser.add_argument(
        "--scan", action="store_true", help="Scan Ghidra and update state (incremental)"
    )
    parser.add_argument(
        "--refresh", action="store_true", help="Force full rescan (use with --scan)"
    )
    parser.add_argument("--web", action="store_true", help="Start web dashboard")
    parser.add_argument(
        "--web-port", type=int, default=5000, help="Web dashboard port (default: 5000)"
    )
    parser.add_argument(
        "--provider",
        choices=["claude", "codex", "minimax", "gemini"],
        default=None,
        help="AI provider override (default: use dashboard/default provider selection)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override model selection for this run",
    )
    parser.add_argument(
        "--max-turns", type=int, default=25, help="Max Claude turns (default: 25)"
    )
    parser.add_argument(
        "--folder", default=None, help="Ghidra project folder (default: /Mods/PD2-S12)"
    )
    parser.add_argument(
        "--binary",
        default=None,
        help="Focus on a specific binary (e.g., D2Common.dll). Persisted to state.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without invoking Claude",
    )
    parser.add_argument(
        "--address", default=None, help="Specific function address for select mode"
    )
    parser.add_argument(
        "--program", default=None, help="Specific program path for select mode"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable auto-start of web dashboard (default: dashboard starts in background)",
    )
    parser.add_argument(
        "--state-file",
        default=None,
        help="Path to state JSON file (default: state.json next to this script)",
    )

    args = parser.parse_args()

    # Override AI provider if specified via CLI
    global AI_PROVIDER, STATE_FILE
    if args.provider:
        AI_PROVIDER = args.provider

    if args.state_file:
        STATE_FILE = Path(args.state_file)
        if not STATE_FILE.is_absolute():
            STATE_FILE = Path.cwd() / STATE_FILE

    state = load_state()

    # Override folder/binary if specified
    if args.folder:
        state["project_folder"] = args.folder
        save_state(state)
    if args.binary:
        state["active_binary"] = args.binary
        save_state(state)
    elif args.binary == "":
        # --binary "" clears the filter
        state.pop("active_binary", None)
        save_state(state)

    project_folder = state.get("project_folder", "/Mods/PD2-S12")
    active_binary = state.get("active_binary")  # None = all binaries

    # --web: start Flask dashboard (standalone, blocking)
    if args.web:
        from web import create_app
        from event_bus import get_bus

        bus = get_bus()
        app, socketio = create_app(STATE_FILE, event_bus=bus)
        dashboard_url = f"http://127.0.0.1:{args.web_port}"
        print(f"Starting web dashboard at {dashboard_url}")
        import webbrowser

        webbrowser.open(dashboard_url)
        socketio.run(app, host="127.0.0.1", port=args.web_port, debug=False)
        return

    # Auto-start dashboard in background (unless disabled)
    dashboard_enabled = (
        not args.no_dashboard
        and os.environ.get("FUNDOC_DASHBOARD", "true").lower() != "false"
    )
    if dashboard_enabled:
        import threading
        import tempfile
        import socket

        dash_port = args.web_port

        # Single-instance check. Only the process that owns the port can
        # serve the browser; any second fun_doc that silently binds the
        # same port would answer some requests and drop others. Skipping
        # the whole dashboard setup here keeps every subsequent
        # `python fun_doc.py ...` invocation a clean CLI command that
        # defers to the already-running dashboard.
        port_already_owned = False
        try:
            with socket.create_connection(("127.0.0.1", dash_port), timeout=0.3):
                port_already_owned = True
        except (ConnectionRefusedError, OSError):
            port_already_owned = False

        if port_already_owned:
            print(
                f"  Dashboard already running at http://127.0.0.1:{dash_port} "
                f"— skipping dashboard + WorkerManager in this process"
            )
            dashboard_enabled = False

    if dashboard_enabled:
        try:
            from web import create_app
            from event_bus import get_bus

            bus = get_bus()
            dash_app, dash_socketio = create_app(STATE_FILE, event_bus=bus)
            dashboard_url = f"http://127.0.0.1:{dash_port}"

            # Run Flask-SocketIO in a daemon thread (auto-exits when main process exits)
            def _run_dashboard():
                try:
                    dash_socketio.run(
                        dash_app,
                        host="127.0.0.1",
                        port=dash_port,
                        debug=False,
                        use_reloader=False,
                        allow_unsafe_werkzeug=True,
                    )
                except Exception as e:
                    print(f"  Dashboard error: {e}", flush=True)

            dash_thread = threading.Thread(target=_run_dashboard, daemon=True)
            dash_thread.start()

            # Wait for Flask to actually bind the port (up to 3 seconds)
            for _ in range(30):
                time.sleep(0.1)
                try:
                    with socket.create_connection(
                        ("127.0.0.1", dash_port), timeout=0.5
                    ):
                        break
                except (ConnectionRefusedError, OSError):
                    continue

            # Auto-open browser on first run (track via temp file to avoid repeat opens)
            sentinel = (
                Path(tempfile.gettempdir()) / f"fundoc_dashboard_{dash_port}.lock"
            )
            if not sentinel.exists():
                import webbrowser

                webbrowser.open(dashboard_url)
                sentinel.write_text(str(os.getpid()))
                print(f"  Dashboard opened: {dashboard_url}")
            else:
                print(f"  Dashboard: {dashboard_url}")

            # Phase 1 audit loop: start the report-only watcher alongside
            # the dashboard. Reads rules from audit/rules.yaml, subscribes
            # to the shared event bus, records matches to audit/queue.jsonl.
            # No agent drains the queue yet (Phase 3).
            try:
                from audit.registry import AuditRegistry
                from audit.watcher import AuditWatcher, load_rules_from_yaml
                import requests as _audit_requests

                audit_dir = SCRIPT_DIR / "audit"
                rules_path = audit_dir / "rules.yaml"
                if rules_path.is_file():
                    audit_registry = AuditRegistry(audit_dir / "registry.json")

                    def _fetch_bridge_counters():
                        try:
                            r = _audit_requests.get(
                                f"http://127.0.0.1:{dash_port}/api/_diag_bridge",
                                timeout=2,
                            )
                            return (r.json() or {}).get("bridge_counters", {}) or {}
                        except Exception:
                            return {}

                    audit_watcher = AuditWatcher(
                        bus=bus,
                        registry=audit_registry,
                        rules=load_rules_from_yaml(rules_path),
                        queue_path=audit_dir / "queue.jsonl",
                        bridge_counters_fetcher=_fetch_bridge_counters,
                    )
                    audit_watcher.start()
                    print(
                        f"  Audit watcher: {len(audit_watcher._rules)} rule(s) "
                        f"loaded (Phase 1, report-only)"
                    )
                else:
                    print("  Audit watcher: rules.yaml not found; skipping")
            except ImportError as _audit_exc:
                print(f"  Audit watcher: import failed ({_audit_exc}); skipping")
            except Exception as _audit_exc:
                print(
                    f"  Audit watcher: startup failed "
                    f"({type(_audit_exc).__name__}: {_audit_exc})"
                )
        except ImportError:
            print(f"  Dashboard requires flask: pip install flask")
        except Exception as e:
            print(f"  Dashboard failed to start: {e}")

    # --status: terminal dashboard
    if args.status:
        print_status(state)
        return

    # --scan: update state from Ghidra (incremental by default, --refresh for full)
    if args.scan:
        scan_functions(
            state, project_folder, refresh=args.refresh, binary_filter=active_binary
        )
        print_status(state)
        return

    # Validate state
    if not state.get("functions"):
        print("No functions in state. Running initial scan...")
        if not scan_functions(state, project_folder):
            return
        print_status(state)
        print()

    # -s / --select: document current function + neighbors
    if args.select:
        if args.address and args.program:
            address = args.address.replace("0x", "")
            program = args.program
        else:
            # Get current selection from Ghidra
            current = ghidra_get("/get_current_function")
            if not current:
                print(
                    "ERROR: Cannot get current function from Ghidra. Use --address and --program."
                )
                return
            if isinstance(current, str):
                try:
                    current = json.loads(current)
                except (json.JSONDecodeError, TypeError):
                    # Parse plain text response: "Function: Name at ADDR\nSignature: ..."
                    import re

                    match = re.search(r"at\s+([0-9a-fA-F]+)", current)
                    if match:
                        current = {"address": match.group(1)}
                    else:
                        print(f"ERROR: Unexpected response: {current}")
                        return
            address = current.get("address", "").replace("0x", "")
            program = current.get("program", None)
            if not address:
                print("ERROR: No current function selected in Ghidra")
                return
            # Find program: try --program arg, then state lookup, then list_open_programs
            if not program and args.program:
                program = args.program
            if not program:
                for key, func in state["functions"].items():
                    if func["address"] == address:
                        program = func["program"]
                        break
            if not program:
                # Last resort: use the current open program from Ghidra
                programs_resp = ghidra_get("/list_open_programs")
                if programs_resp and isinstance(programs_resp, dict):
                    # Prefer the program marked as current
                    for p in programs_resp.get("programs", []):
                        if p.get("is_current"):
                            program = p["path"]
                            break
                    # Fall back to first matching project folder
                    if not program:
                        for p in programs_resp.get("programs", []):
                            if p.get("path", "").startswith(
                                state.get("project_folder", "")
                            ):
                                program = p["path"]
                                break

        if not program:
            print("ERROR: Could not determine program. Use --program.")
            return

        session = start_session(state)

        # Collect the initial neighborhood
        print(f"\n  Select mode: 0x{address} in {program} (depth={args.depth})")
        targets = get_select_functions(state, program, address, depth=args.depth)

        if not targets:
            print("  No functions to process")
        else:
            print(f"  Found {len(targets)} functions in neighborhood")

            if args.depth > 1 or not args.manual:
                # Depth > 1 or auto mode: process the full collected list
                for key, func in targets:
                    result = process_function(
                        key,
                        func,
                        state,
                        model=args.model,
                        manual=args.manual,
                        dry_run=args.dry_run,
                    )
                    if result == "quit":
                        break
                    elif result == "completed":
                        session["completed"] += 1
                        session["functions"].append(key)
                    elif result == "skipped":
                        session["skipped"] += 1
                    elif result == "failed" or result == "blocked":
                        session["failed"] += 1
                    elif result == "partial":
                        session["partial"] += 1
            else:
                # Manual mode, depth 1: interactive loop re-fetching from CodeBrowser
                while True:
                    key, func = targets[0]
                    result = process_function(
                        key,
                        func,
                        state,
                        model=args.model,
                        manual=args.manual,
                        dry_run=args.dry_run,
                    )
                    if result == "quit":
                        break
                    elif result == "completed":
                        session["completed"] += 1
                        session["functions"].append(key)
                    elif result == "skipped":
                        session["skipped"] += 1
                    elif result == "failed" or result == "blocked":
                        session["failed"] += 1
                    elif result == "partial":
                        session["partial"] += 1

                    # Re-fetch current function from CodeBrowser for next iteration
                    current = ghidra_get("/get_current_function")
                    if current and isinstance(current, str):
                        try:
                            current = json.loads(current)
                        except (json.JSONDecodeError, TypeError):
                            import re

                            match = re.search(r"at\s+([0-9a-fA-F]+)", current)
                            if match:
                                current = {"address": match.group(1)}
                            else:
                                break
                    if current and isinstance(current, dict):
                        address = current.get("address", "").replace("0x", "")
                        new_prog = current.get("program")
                        if new_prog:
                            program = new_prog
                    targets = get_select_functions(state, program, address, depth=1)
                    if not targets:
                        break

        end_session(state)
        save_state(state)
        print_status(state)
        return

    # --auto: process next best functions
    if args.auto or args.manual:
        targets = get_next_functions(state, count=args.count)

        if not targets:
            print("All functions are documented (score >= 90). Nothing to do!")
            return

        print(f"Processing {len(targets)} function(s)")

        session = start_session(state)
        for key, func in targets:
            result = process_function(
                key,
                func,
                state,
                model=args.model,
                manual=args.manual,
                dry_run=args.dry_run,
            )
            if result == "quit":
                break
            elif result == "completed":
                session["completed"] += 1
                session["functions"].append(key)
            elif result == "skipped":
                session["skipped"] += 1
            elif result == "failed" or result == "blocked":
                session["failed"] += 1
            elif result == "partial":
                session["partial"] += 1

        end_session(state)
        save_state(state)
        print_status(state)
        return

    # No mode specified: show status dashboard (terminal + web)
    if not state.get("functions"):
        print("No functions in state. Running initial scan...")
        if not scan_functions(state, project_folder):
            return
    print_status(state)
    if dashboard_enabled:
        print(f"\n  Dashboard running at http://127.0.0.1:{args.web_port}")
        print(f"  Press Ctrl+C to exit.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
