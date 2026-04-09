"""
fun-doc: Intelligent function documentation engine for Ghidra MCP.

Prioritizes functions by call graph impact (bottom-up, leaf-first),
assembles modular V6 prompts, invokes Claude CLI, and tracks state.

Usage:
    python fun_doc.py --auto                  # Auto-mode: document next best function
    python fun_doc.py --auto --count 10       # Document 10 functions
    python fun_doc.py -s                      # Select mode: current function + neighbors
    python fun_doc.py -s --depth 2            # Select mode with depth 2
    python fun_doc.py -m                      # Manual mode: pick/copy prompts
    python fun_doc.py --status                # Show progress dashboard in terminal
    python fun_doc.py --web                   # Start web dashboard (Flask)
    python fun_doc.py --scan                  # Incremental scan (only re-score changed)
    python fun_doc.py --scan --refresh        # Full rescan (re-score everything)
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, date
from pathlib import Path

from event_bus import emit as bus_emit

# Thread safety for state.json access across concurrent workers
_state_lock = threading.Lock()

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
# Switch between "claude" and "codex" here.
# Each provider maps mode -> model name.

AI_PROVIDER = "claude"  # "claude", "codex", or "minimax"

AI_MODELS = {
    "claude": {
        "FULL": "opus",
        "FIX": "sonnet",
        "VERIFY": "sonnet",
    },
    "codex": {
        "FULL": "gpt-5.3-codex",
        "FIX": "gpt-5.3-codex",
        "VERIFY": "gpt-5.3-codex",
    },
    "minimax": {
        "FULL": "MiniMax-M2.7",
        "FIX": "MiniMax-M2.7",
        "VERIFY": "MiniMax-M2.7-highspeed",
    },
}


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


def _parse_response(r):
    """Parse response, trying JSON first then falling back to text."""
    text = r.text
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def ghidra_get(path, params=None, timeout=60):
    """GET request to Ghidra HTTP server."""
    try:
        r = requests.get(f"{GHIDRA_URL}{path}", params=params, timeout=timeout)
        r.raise_for_status()
        return _parse_response(r)
    except requests.RequestException as e:
        print(f"  WARNING: Ghidra GET {path} failed: {e}", file=sys.stderr)
        return None


def ghidra_post(path, data=None, params=None, timeout=60):
    """POST request to Ghidra HTTP server."""
    try:
        r = requests.post(
            f"{GHIDRA_URL}{path}", json=data, params=params, timeout=timeout
        )
        r.raise_for_status()
        return _parse_response(r)
    except requests.RequestException as e:
        print(f"  WARNING: Ghidra POST {path} failed: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


def load_state():
    """Load or create fresh state. Thread-safe."""
    with _state_lock:
        if STATE_FILE.exists():
            with open(STATE_FILE, "r") as f:
                return json.load(f)
    return {
        "project_folder": "/Mods/PD2-S12",
        "last_scan": None,
        "functions": {},
        "sessions": [],
        "current_session": None,
    }


def save_state(state):
    """Persist state to disk. Thread-safe."""
    with _state_lock:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2, default=str)
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
    """Fetch enhanced function list for a program. Returns list or None."""
    funcs_resp = ghidra_get(
        "/list_functions_enhanced", params={"program": prog_path}, timeout=60
    )
    if not funcs_resp:
        return None
    if isinstance(funcs_resp, str):
        try:
            funcs_resp = json.loads(funcs_resp)
        except (json.JSONDecodeError, TypeError):
            return None
    return funcs_resp.get("functions")


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


def _batch_score(addresses, prog_path=None):
    """Score addresses via batch endpoint, falling back to individual calls on failure."""
    score_map = {}
    BATCH_SIZE = 50

    params = {}
    if prog_path:
        params["program"] = prog_path

    # Try batch first
    batch_works = None  # None = untested, True/False after first batch
    for i in range(0, len(addresses), BATCH_SIZE):
        batch = addresses[i : i + BATCH_SIZE]
        scored_so_far = i + len(batch)

        if batch_works is not False:
            # First batch gets longer timeout (Ghidra may need to open the program)
            batch_timeout = 300 if i == 0 else 120
            resp = ghidra_post(
                "/batch_analyze_completeness",
                data={"addresses": batch},
                params=params,
                timeout=batch_timeout,
            )
            if resp and isinstance(resp, dict) and "results" in resp:
                results = resp["results"]
                # Check if first result is an error (batch endpoint doesn't work for this program)
                if results and isinstance(results[0], dict) and "error" in results[0]:
                    if batch_works is None:
                        batch_works = False
                        print(
                            f"    Batch scoring unavailable, falling back to individual scoring...",
                            flush=True,
                        )
                else:
                    batch_works = True
            elif resp is None and batch_works is None:
                # First batch timed out or failed — fall back to individual
                batch_works = False
                print(
                    f"    Batch scoring timed out, falling back to individual scoring...",
                    flush=True,
                )

        if batch_works is False:
            # Individual fallback
            for addr_hex in batch:
                addr = addr_hex.replace("0x", "")
                info = _score_single(addr_hex, prog_path)
                if info:
                    score_map[addr] = info
            # Progress every batch
            print(f"    Scored {scored_so_far}/{len(addresses)}", flush=True)
            continue

        # Progress every 500 for batch mode
        if scored_so_far % 500 < BATCH_SIZE or scored_so_far == len(addresses):
            print(f"    Scored {scored_so_far}/{len(addresses)}", flush=True)

        if resp and isinstance(resp, dict) and "results" in resp:
            for j, result in enumerate(resp["results"]):
                if i + j < len(addresses):
                    addr = addresses[i + j].replace("0x", "")
                    eff = result.get(
                        "effective_score", result.get("completeness_score", 0)
                    )
                    classification = result.get("classification", "unknown")
                    score_map[addr] = {
                        "score": int(eff) if eff is not None else 0,
                        "fixable": float(result.get("fixable_deductions", 0)),
                        "has_custom_name": result.get("has_custom_name", False),
                        "has_plate_comment": result.get("has_plate_comment", False),
                        "is_leaf": classification == "leaf",
                        "classification": classification,
                        "deductions": result.get("deduction_breakdown", []),
                    }

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

    target_programs = _fetch_programs(project_folder)
    if target_programs is None:
        return False

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
            {"program": prog_name, "index": prog_idx, "total": len(target_programs)},
        )
        print(f"\n  {prog_name} ({prog_path})")

        func_list = _fetch_function_list(prog_path)
        if func_list is None:
            print(f"    WARNING: Could not list functions for {prog_path}")
            continue

        non_thunk = [
            f for f in func_list if not f.get("isThunk") and not f.get("isExternal")
        ]
        print(f"    {len(func_list)} functions ({len(non_thunk)} non-thunk)")

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
                f"    {len(needs_scoring)} changed/new, {len(non_thunk) - len(needs_scoring)} cached"
            )
        else:
            needs_scoring_addrs = [f"0x{f['address']}" for f in non_thunk]

        # Score only what's needed
        score_map = {}
        if needs_scoring_addrs:
            print(f"    Scoring {len(needs_scoring_addrs)} functions...")
            score_map = _batch_score(needs_scoring_addrs, prog_path)

        # Build function entries
        for func in func_list:
            addr = func["address"]
            name = func["name"]
            is_thunk = func.get("isThunk", False)
            is_external = func.get("isExternal", False)
            func_key = f"{prog_path}::{addr}"

            # Check if we have a fresh score or should use cached
            if addr in score_map:
                score_info = score_map[addr]
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
                "last_processed": existing.get(func_key, {}).get("last_processed"),
                "last_result": existing.get(func_key, {}).get("last_result"),
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
    """Pre-fetch all Ghidra data needed for prompt assembly."""
    data = {
        "decompiled": None,
        "completeness": None,
        "variables": None,
        "analyze_for_doc": None,
        "score": None,
        "deductions": [],
        "fixable_categories": [],
    }

    # Navigate
    ghidra_post("/tool/goto_address", data={"address": f"0x{address}"})

    # Decompile
    data["decompiled"] = ghidra_get(
        "/decompile_function", params={"address": f"0x{address}", "program": program}
    )

    # Completeness
    raw = ghidra_get(
        "/analyze_function_completeness",
        params={"function_address": f"0x{address}", "program": program},
    )
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

    # Full analysis for FULL mode (retry once on failure)
    if mode == "FULL":
        afd = ghidra_get(
            "/analyze_for_documentation",
            params={"function_address": f"0x{address}", "program": program},
            timeout=60,
        )
        if _is_error_response(afd):
            # Retry once — the first call sometimes fails on cold decompiler cache
            afd = ghidra_get(
                "/analyze_for_documentation",
                params={"function_address": f"0x{address}", "program": program},
                timeout=90,
            )
        data["analyze_for_doc"] = afd

    return data


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


def _load_priority_queue():
    """Load the priority queue file written by the web dashboard."""
    qf = SCRIPT_DIR / "priority_queue.json"
    if qf.exists():
        try:
            with open(qf, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"pinned": [], "skipped": [], "order": []}


def get_next_functions(state, count=1):
    """Get the next N functions to process, sorted by priority.

    Respects the priority queue from the web dashboard:
    - Pinned functions come first (in pin order)
    - Skipped functions are excluded
    - Remaining functions sorted by ROI: fixable * (1 + callers/10)
    """
    queue = _load_priority_queue()
    pinned = set(queue.get("pinned", []))
    skipped = set(queue.get("skipped", []))

    active_binary = state.get("active_binary")

    candidates = []
    for key, func in state["functions"].items():
        if func.get("is_thunk") or func.get("is_external"):
            continue
        if key in skipped:
            continue
        if func.get("score", 0) >= 95 and func.get("fixable", 0) == 0:
            continue
        if active_binary and func.get("program_name") != active_binary:
            continue

        fixable = func.get("fixable", 0)
        callers = func.get("caller_count", 0)
        roi = fixable * (1 + callers / 10)

        # Deprioritize functions that have been partially processed too many times
        partial_runs = func.get("partial_runs", 0)
        if partial_runs >= 3 and key not in pinned:
            roi *= 0.1  # 90% reduction — needs human attention or stronger model

        # Pinned functions get infinite priority
        sort_key = (key in pinned, roi)
        candidates.append((sort_key, key, func))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [(key, func) for _, key, func in candidates[:count]]


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
        cat_counts[cat] = d.get("count", 0) if isinstance(d.get("count"), (int, float)) else 0

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


def select_model(mode, user_model=None, provider=None):
    """Auto-select model based on mode and provider, with user override."""
    if user_model:
        return user_model
    effective_provider = provider or AI_PROVIDER
    provider_models = AI_MODELS.get(effective_provider, AI_MODELS["claude"])
    return provider_models.get(mode, list(provider_models.values())[0])


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
        sections.append("## Variables (pre-fetched)")
        sections.append(
            "*Variable types may already be resolved by decompiler — check `needs_type` field before calling `set_local_variable_type`. Refresh with `get_function_variables` after any prototype change.*"
        )
        sections.append("```json")
        var_str = (
            json.dumps(variables, indent=None)
            if isinstance(variables, (dict, list))
            else str(variables)
        )
        sections.append(var_str)
        sections.append("```")
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
        sections.append("## Variables (pre-fetched)")
        sections.append(
            "*Variable types may already be resolved by decompiler — check `needs_type` field before calling `set_local_variable_type`. Refresh with `get_function_variables` after any prototype change.*"
        )
        sections.append("```json")
        var_str = (
            json.dumps(variables, indent=None)
            if isinstance(variables, (dict, list))
            else str(variables)
        )
        sections.append(var_str)
        sections.append("```")
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
        sections.append("## Variables (pre-fetched)")
        sections.append(
            "*Variable types may already be resolved — check `needs_type` field before calling `set_local_variable_type`.*"
        )
        sections.append("```json")
        var_str = (
            json.dumps(variables, indent=None)
            if isinstance(variables, (dict, list))
            else str(variables)
        )
        sections.append(var_str)
        sections.append("```")
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
    return (result, {"tool_calls": -1})  # -1 = unknown (provider doesn't track)


def invoke_claude(prompt, model="sonnet", max_turns=25, provider=None, complexity_tier=None):
    """Invoke the configured AI provider."""
    effective_provider = provider or AI_PROVIDER
    if effective_provider == "minimax":
        return _invoke_minimax(prompt, model, max_turns, complexity_tier=complexity_tier)
    if effective_provider == "codex":
        return _wrap_result(_invoke_codex(prompt, model, max_turns))

    return _wrap_result(_invoke_claude(prompt, model, max_turns))


def _invoke_codex(prompt, model="gpt-5.3-codex", max_turns=25):
    """Invoke Codex via the Python SDK with MCP tool support."""
    import asyncio

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
                    tool = getattr(
                        item,
                        "tool",
                        getattr(item, "tool_name", getattr(item, "name", "?")),
                    )
                    server = getattr(item, "server", "")
                    status = getattr(item, "status", "?")
                    print(f"  [mcp] {tool}: {status}", flush=True)
            elif event_type == "turn.completed":
                usage = getattr(event, "usage", None)
                if usage:
                    tokens = getattr(usage, "total_tokens", "?")
                    print(f"  [tokens: {tokens}]", flush=True)

        return "\n".join(output_parts) if output_parts else None

    try:
        return asyncio.run(run())
    except Exception as e:
        print(f"ERROR: Codex SDK failed: {e}", file=sys.stderr)
        return None


def _invoke_minimax(prompt, model="MiniMax-M2.7", max_turns=25, complexity_tier=None):
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
            method = ep.get("method", "GET").upper()
            description = ep.get("description", name)
            params = ep.get("params", [])

            # Build JSON schema for parameters
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
                pdesc = p.get("description", "")
                if pdesc:
                    prop["description"] = pdesc
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
                return json.dumps(result, default=str)
            return str(result)
        except Exception as e:
            return json.dumps({"error": f"Tool execution failed: {str(e)}"})

    # --- Conversation loop ---
    client = OpenAI(
        api_key=api_key,
        base_url="https://api.minimax.io/v1",
    )

    messages = [
        {
            "role": "system",
            "content": "You are a reverse engineering assistant with access to Ghidra MCP tools. Call tools to analyze and document functions. Be thorough and precise.",
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

    for turn in range(max_turns):
        try:
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": 1.0,  # MiniMax recommends 1.0
                "max_tokens": max_output_tokens,
            }
            if tools_openai:
                kwargs["tools"] = tools_openai

            response = client.chat.completions.create(**kwargs)
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
                print(f"  [mcp] {fn_name}: calling...", flush=True)
                bus_emit("tool_call", {"tool": fn_name, "status": "calling"})
                result_str = execute_tool_call(fn_name, fn_args)

                # Truncate very large results to avoid blowing context
                if len(result_str) > 50000:
                    result_str = result_str[:50000] + "\n... (truncated)"

                status = "failed" if '"error"' in result_str[:100] else "done"
                print(f"  [mcp] {fn_name}: {status}", flush=True)
                bus_emit("tool_result", {"tool": fn_name, "status": status})

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


def _invoke_claude(prompt, model="sonnet", max_turns=25):
    """Invoke Claude Code via the Python SDK with MCP tool support."""
    import asyncio

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
                "append": "Use ToolSearch to load the ghidra-mcp MCP tools if they are not yet available, then call them directly by name.",
            },
        )

        output_parts = []
        tool_id_to_name = {}
        try:
            async for msg in query(prompt=prompt, options=options):
                msg_type = type(msg).__name__
                if msg_type == "AssistantMessage":
                    content = getattr(msg, "content", None)
                    if content:
                        for block in (
                            content if isinstance(content, list) else [content]
                        ):
                            block_type = type(block).__name__
                            if block_type == "TextBlock":
                                text = getattr(block, "text", str(block))
                                print(text)
                                output_parts.append(text)
                                bus_emit("model_text", {"text": text})
                            elif block_type == "ToolUseBlock":
                                tool_name = getattr(block, "name", "?")
                                tool_id = getattr(block, "id", "")
                                tool_id_to_name[tool_id] = tool_name
                                print(f"  [mcp] {tool_name}: calling...", flush=True)
                                bus_emit(
                                    "tool_call",
                                    {
                                        "tool": tool_name,
                                        "status": "calling",
                                        "id": tool_id,
                                    },
                                )
                            elif block_type == "ToolResultBlock":
                                is_error = getattr(block, "is_error", False)
                                status = "failed" if is_error else "completed"
                                tool_id = getattr(block, "tool_use_id", "")
                                tool_name = tool_id_to_name.get(tool_id, tool_id[:12])
                                print(f"  [mcp] {tool_name}: {status}", flush=True)
                                bus_emit(
                                    "tool_result",
                                    {
                                        "tool": tool_name,
                                        "status": status,
                                        "id": tool_id,
                                    },
                                )
                            elif block_type == "ThinkingBlock":
                                pass  # Skip thinking blocks
                elif msg_type == "ResultMessage":
                    pass  # Final result handled via output_parts
        except Exception as e:
            err_str = str(e)
            if "not found" in err_str.lower():
                raise
            # Print all errors to stdout (stderr may not display in PowerShell)
            print(f"  [claude sdk error] {err_str}", flush=True)

        return "\n".join(output_parts) if output_parts else None

    # Retry once on "not found" errors (intermittent when previous process is still exiting)
    for attempt in range(2):
        try:
            return asyncio.run(run())
        except Exception as e:
            err_str = str(e)
            if "not found" in err_str and attempt == 0:
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
            partial_str = f", {s.get('partial', 0)} partial" if s.get('partial', 0) else ""
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
    """Sync all completeness fields from live data into the function state dict."""
    if score is not None:
        func["score"] = score
    if deductions is not None:
        func["deductions"] = deductions
    if completeness and isinstance(completeness, dict) and "error" not in completeness:
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
    return bool(re.match(r'^(local_|[a-z]{1,2}Var\d+$|param_|in_|unaff_|extraout_)', name))


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
                issues.append({
                    "var": name,
                    "type": vtype,
                    "prefix": prefix,
                    "issue": f"'{prefix}' prefix requires pointer type, got '{vtype}'",
                })
            continue

        # Standard prefix check
        valid_types = _HUNGARIAN_PREFIX_TO_TYPES.get(prefix, set())
        if valid_types and vtype.lower().strip() not in {t.lower() for t in valid_types}:
            # Don't flag pointer types with 'p' prefix that are correctly typed
            if _is_type_pointer(vtype) and prefix == "p":
                continue
            issues.append({
                "var": name,
                "type": vtype,
                "prefix": prefix,
                "issue": f"'{prefix}' prefix expects {valid_types}, got '{vtype}'",
            })

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
    except Exception as e:
        print(f"  WARNING: Failed to write run log: {e}", flush=True)


def _inject_tool_block(prompt):
    """Append available MCP tool list to a prompt."""
    available_tools = fetch_available_tools()
    if not available_tools:
        return prompt
    RELEVANT_TOOLS = {
        "analyze_for_documentation",
        "get_function_variables",
        "set_variables",
        "rename_function_by_address",
        "set_function_prototype",
        "set_local_variable_type",
        "set_parameter_type",
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
    tool_block += "\n"
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
):
    """Process a single function: fetch data, build prompt, invoke AI provider."""
    if stop_flag and stop_flag.is_set():
        return "stopped"

    address = func["address"]
    program = func["program"]
    name = func["name"]

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

    # Determine mode from current score (with smart promotion from cached state)
    mode = determine_mode(func.get("score"), func.get("deductions"), func)

    # Fetch live data from Ghidra
    print(f"  Fetching data...", end=" ", flush=True)
    data = fetch_function_data(program, address, mode=mode)
    live_score = data.get("score")
    print(f"done")

    # Refine mode based on live score and completeness context
    mode = determine_mode(live_score, data.get("deductions"), data.get("completeness"))

    # Sync point 1: update state.json with live data from Ghidra (pre-work)
    _sync_func_state(func, data.get("completeness"), live_score, data.get("deductions"))
    save_state(state)

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
        if live_score is not None and live_score >= 95 and fixable_pts < 3:
            print(f"  SKIP: {live_score}% effective, {fixable_pts:.1f} fixable pts (< 3)")
            func["last_result"] = "skipped_complete"
            save_state(state)
            return "skipped"

        # FIX mode only: skip if there's almost nothing fixable regardless of score
        if mode == "FIX" and fixable_pts < 3:
            print(f"  SKIP: FIX mode but only {fixable_pts:.1f} fixable pts remaining")
            func["last_result"] = "skipped_complete"
            save_state(state)
            return "skipped"

        if mode == "VERIFY":
            print(f"  SKIP: 100% complete")
            func["last_result"] = "skipped_complete"
            save_state(state)
            return "skipped"

    # Select model
    selected_model = select_model(mode, model, provider=provider)

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

        # Massive functions: force recovery-only (skip pass 2)
        if complexity_tier == "massive":
            use_two_pass = True
            complexity_forced_recovery = True
            print(f"  COMPLEXITY: {complexity_tier} — forcing recovery-only mode")
    if use_two_pass:
        recovery_prompt = build_recovery_prompt(
            func_name, address, data, program=program
        )
        recovery_prompt = _inject_tool_block(recovery_prompt)
        # Swap: run recovery prompt first, then re-fetch and build FIX prompt for pass 2
        prompt = recovery_prompt
        mode = "FULL:recovery"

    bus_emit(
        "function_mode",
        {"key": func_key, "mode": mode, "model": selected_model, "score": live_score},
    )
    print(f"  {mode} | {selected_model} | {len(prompt):,} chars | score: {live_score}%")

    if dry_run:
        print(
            f"  DRY RUN: Would invoke {'pass 1 (recovery)' if use_two_pass else 'Claude'}"
        )
        return "dry_run"

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
        save_state(state)
        if key == "q":
            return "quit"
        return "manual_prompt_generated"

    # Auto mode: invoke AI (provider based on AI_PROVIDER)
    print()
    output, meta = invoke_claude(prompt, model=selected_model, provider=provider, complexity_tier=complexity_tier)
    tool_calls_made = meta.get("tool_calls", -1)

    # Two-pass: if recovery pass made tool calls, run pass 2 (comments) with fresh data
    # Don't gate on "DONE:" text — the model may produce think-only output or empty response
    # Skip pass 2 for massive functions — they need multiple sessions
    if use_two_pass and tool_calls_made > 0 and not complexity_forced_recovery:
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
        prompt2 = _inject_tool_block(prompt2)
        mode = "FULL:comments"
        print(
            f"  {mode} | {selected_model} | {len(prompt2):,} chars | score: {mid_score}%"
        )
        print()
        output2, meta2 = invoke_claude(prompt2, model=selected_model, provider=provider, complexity_tier=complexity_tier)
        # Merge results: use pass 2 output for final parsing, sum tool calls
        if output2:
            output = output2
        tool_calls_made += meta2.get("tool_calls", 0)

    # Parse result
    result = "completed"
    if output:
        if "BLOCKED:" in output:
            result = "blocked"
        elif "DONE:" in output:
            result = "completed"
        elif "VERIFIED OK:" in output or "QUICK FIX:" in output:
            result = "completed"
        elif "NEEDS REDO:" in output:
            result = "needs_redo"
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
        if (
            result == "completed"
            and live_score is not None
            and diff < -5
        ):
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
                print(f"  WARNING: Function still has original name '{func_name}' after FULL mode")

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
            hungarian_issues, generic_remaining = _audit_hungarian_compliance(address, program)
            if hungarian_issues:
                issue_summary = "; ".join(
                    f"{i['var']}({i['prefix']}→{i['type']})" for i in hungarian_issues[:5]
                )
                print(
                    f"  HUNGARIAN AUDIT: {len(hungarian_issues)} prefix/type mismatch(es): {issue_summary}"
                )
                if result == "completed" and len(hungarian_issues) >= 2:
                    missing_artifacts.append("hungarian_mismatches")
                    result = "partial"
                    func["last_result"] = result
                    print(f"  — downgrading to partial ({len(hungarian_issues)} mismatches)")
            if generic_remaining > 0:
                print(f"  VARIABLE AUDIT: {generic_remaining} generic-named variable(s) remaining")
                if result == "completed" and generic_remaining >= 3 and mode in ("FULL", "FULL:recovery", "FULL:comments"):
                    missing_artifacts.append("generic_variables")
                    result = "partial"
                    func["last_result"] = result
                    print(f"  — downgrading to partial ({generic_remaining} unrenamed variables)")
    else:
        print(f"\n  Result: {result} | Score: unavailable")

    # Track partial_runs for requeue deprioritization
    if result == "partial":
        func["partial_runs"] = func.get("partial_runs", 0) + 1

    # Log this run for audit trail
    _append_run_log(
        {
            "timestamp": datetime.now().isoformat(),
            "program": program,
            "address": address,
            "function": func_name,
            "mode": mode,
            "model": selected_model,
            "provider": provider or AI_PROVIDER,
            "score_before": live_score,
            "score_after": new_score,
            "score_delta": (new_score - live_score) if (new_score is not None and live_score is not None) else None,
            "result": result,
            "tool_calls": tool_calls_made,
            "complexity_tier": complexity_tier,
            "missing_artifacts": missing_artifacts if missing_artifacts else None,
            "output": output[:5000] if output else None,
        }
    )

    bus_emit(
        "score_update",
        {
            "key": func_key,
            "score_before": live_score,
            "score_after": new_score,
            "result": result,
        },
    )
    bus_emit(
        "function_complete", {"key": func_key, "result": result, "score": new_score}
    )

    # Save program to persist changes in Ghidra
    if result in ("completed", "needs_redo", "partial") and tool_calls_made > 0:
        ghidra_post("/save_program", params={"program": program})

    save_state(state)
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
        choices=["claude", "codex", "minimax"],
        default=None,
        help="AI provider (default: use AI_PROVIDER constant in script)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override model selection (e.g., opus, sonnet, MiniMax-M2.7)",
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

    args = parser.parse_args()

    # Override AI provider if specified via CLI
    global AI_PROVIDER
    if args.provider:
        AI_PROVIDER = args.provider

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

        try:
            from web import create_app
            from event_bus import get_bus

            bus = get_bus()
            dash_app, dash_socketio = create_app(STATE_FILE, event_bus=bus)
            dash_port = args.web_port
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
