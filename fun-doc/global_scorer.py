"""Background global-variable inventory scorer for fun-doc.

Continuously walks every binary in the Ghidra project tree, finds globals
that aren't fully documented per the v5.7.0 four-axis bar (name + type +
bytes formatted + plate comment), and feeds them to the worker pool as
a queue separate from functions. Mirrors the architecture of
`inventory_scorer.py` (idle-time backfill, single-thread, cooperative
pause when doc workers run, session-only blacklist after 3 strikes,
persisted to `fun-doc/global_inventory.json`).

Design (v5.7.0 — Q&A 2026-04-25):
  * Q1 four-axis "documented global" bar — same rules as the validator.
  * Q2 binary-wide bulk scope (this module) + per-function (already in
    DataTypeService.auditGlobalsInFunction).
  * Q4 naming = `g_` + Hungarian + reject auto-gen patterns.
  * Q5 bytes = typed + length matches + ASCII null-runs become strings.
  * Q6 plate = ≥4-word first-line summary.
  * Q8 separate module from inventory_scorer (clone-then-evaluate).

The scorer is *read-only* — it doesn't fix globals itself; it tallies
which ones are incomplete and surfaces them via the dashboard so the
user can decide what to document next. Fixing happens through the
existing doc-worker flow (which now mandates `audit_globals_in_function`
+ `set_global` per `step-globals.md`).
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


GLOBAL_INVENTORY_FILE_NAME = "global_inventory.json"
GLOBAL_INVENTORY_FILE_VERSION = 1

DEFAULT_FAIL_STRIKES = 3
IDLE_SLEEP_SECONDS = 5.0
PROGRAMS_TTL_SECONDS = 300


# ---------- pure functions: ordering, status, persistence ----------


def status_for(rec: dict) -> str:
    """Derive the per-binary global-coverage status from its record.

    Mirrors inventory_scorer.status_for. A binary's globals are "complete"
    when every documentable global has zero issues; "in_progress" while
    some are still flagged; "untouched" until the scorer has visited it.
    """
    total = rec.get("total_documentable", 0) or 0
    fully = rec.get("fully_documented", 0) or 0
    last = rec.get("last_scan")
    if total == 0:
        return "untouched" if last is None else "complete"
    if fully >= total:
        return "complete"
    if fully == 0 and last is None:
        return "untouched"
    return "in_progress"


def _has_pending(rec: dict) -> int:
    """Returns the number of globals still needing documentation for one
    inventory record. Unfetched binaries get a small positive sentinel so
    they sort above fully-complete ones."""
    total = rec.get("total_documentable", 0) or 0
    fully = rec.get("fully_documented", 0) or 0
    if total == 0 and rec.get("last_scan") is None:
        return 1
    return max(0, total - fully)


def pick_next_binary(
    inventory: dict,
    candidate_paths: list,
    blacklist: set,
    current_path: Optional[str] = None,
) -> Optional[str]:
    """Pick the next binary to audit.

    When `current_path` is set and that path is in `candidate_paths`, not
    blacklisted, and still has pending globals, it wins unconditionally —
    the user's focused binary always gets backfilled first. Otherwise,
    most-globals-with-issues first; reverse-alpha tiebreak (matches
    inventory_scorer's Q4 ordering). Skip blacklisted paths. None when
    nothing eligible."""
    if current_path and current_path in candidate_paths and current_path not in blacklist:
        rec = inventory.get(current_path) or {}
        if _has_pending(rec) > 0:
            return current_path

    best_path = None
    best_key = None
    for path in candidate_paths:
        if path in blacklist:
            continue
        rec = inventory.get(path) or {}
        with_issues = _has_pending(rec)
        if with_issues <= 0:
            continue
        name = rec.get("name") or Path(path).name
        key = (with_issues, name)
        if best_key is None or key > best_key:
            best_key = key
            best_path = path
    return best_path


def _inventory_path(base_dir: Path) -> Path:
    return Path(base_dir) / GLOBAL_INVENTORY_FILE_NAME


def load_inventory(base_dir: Path) -> dict:
    """Load global_inventory.json. Returns a fresh skeleton on missing
    or corrupt input — never raises."""
    path = _inventory_path(base_dir)
    if not path.exists():
        return {"version": GLOBAL_INVENTORY_FILE_VERSION, "binaries": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"version": GLOBAL_INVENTORY_FILE_VERSION, "binaries": {}}
    if not isinstance(data, dict):
        return {"version": GLOBAL_INVENTORY_FILE_VERSION, "binaries": {}}
    data.setdefault("version", GLOBAL_INVENTORY_FILE_VERSION)
    bins = data.get("binaries")
    if not isinstance(bins, dict):
        data["binaries"] = {}
    return data


def save_inventory(base_dir: Path, data: dict) -> None:
    """Atomic tmp-then-replace write. Same pattern as inventory_scorer
    and provider_pause."""
    path = _inventory_path(base_dir)
    tmp = path.with_suffix(".json.tmp")
    payload = {
        "version": GLOBAL_INVENTORY_FILE_VERSION,
        "binaries": data.get("binaries", {}),
    }
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, AttributeError):
            pass
    tmp.replace(path)


# ---------- threaded scorer ----------


class GlobalScorer:
    """Single-threaded background global-quality auditor. See module
    docstring for design.

    Construction takes injected callables so the class is testable
    without standing up Ghidra/MCP. Only `start()` (via set_enabled)
    spawns a thread; pure-logic methods can be exercised standalone.
    """

    def __init__(
        self,
        *,
        worker_manager,
        project_folder_getter,
        state_dir: Path,
        fetch_programs,
        list_globals_for_program,
        audit_global,
        on_status_change=None,
        current_binary_name_getter=None,
        fail_strikes: int = DEFAULT_FAIL_STRIKES,
        idle_sleep: float = IDLE_SLEEP_SECONDS,
    ):
        self._wm = worker_manager
        self._project_folder_getter = project_folder_getter
        self._state_dir = Path(state_dir)
        self._fetch_programs = fetch_programs
        self._list_globals_for_program = list_globals_for_program
        self._audit_global = audit_global
        self._on_status_change = on_status_change
        self._current_binary_name_getter = current_binary_name_getter
        self._fail_strikes = fail_strikes
        self._idle_sleep = idle_sleep

        self._enabled = False
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        self._fail_streak: dict = {}
        self._current_target: Optional[str] = None
        self._paused_reason: Optional[str] = None
        self._last_progress_at: Optional[str] = None
        self._last_error: Optional[str] = None

        self._cached_programs: Optional[list] = None
        self._cached_programs_at: Optional[float] = None
        self._programs_ttl_seconds = PROGRAMS_TTL_SECONDS

    # ---- public API ----

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            if enabled == self._enabled:
                return
            self._enabled = enabled
            if enabled:
                self._stop_event.clear()
                if not self._thread or not self._thread.is_alive():
                    self._thread = threading.Thread(
                        target=self._run,
                        name="fundoc-global-scorer",
                        daemon=True,
                    )
                    self._thread.start()
            else:
                self._stop_event.set()
                self._paused_reason = "disabled"
                self._current_target = None
        self._notify()

    def get_status(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "running": bool(
                    self._thread and self._thread.is_alive() and self._enabled
                ),
                "current_target": self._current_target,
                "paused_reason": self._paused_reason,
                "last_progress_at": self._last_progress_at,
                "last_error": self._last_error,
                "blacklisted": [
                    p for p, n in self._fail_streak.items() if n >= self._fail_strikes
                ],
            }

    def clear_blacklist(self, path: Optional[str] = None) -> None:
        with self._lock:
            if path is None:
                self._fail_streak.clear()
            else:
                self._fail_streak.pop(path, None)

    # ---- thread loop ----

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self._wm.has_active_workers():
                    self._set_paused("doc workers active")
                    self._sleep_or_exit(self._idle_sleep)
                    continue

                programs = self._get_programs()
                if not programs:
                    self._set_paused("no programs available")
                    self._sleep_or_exit(self._idle_sleep)
                    continue

                inventory = self._snapshot_inventory(programs)
                blacklist = {
                    p for p, n in self._fail_streak.items()
                    if n >= self._fail_strikes
                }
                target = pick_next_binary(
                    inventory,
                    [p["path"] for p in programs],
                    blacklist,
                    current_path=self._resolve_current_path(programs),
                )
                if target is None:
                    self._set_paused("global inventory complete")
                    self._sleep_or_exit(self._idle_sleep)
                    continue

                self._clear_paused()
                with self._lock:
                    self._current_target = target
                self._notify()

                self._audit_one_binary(target)
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                self._notify()
                self._sleep_or_exit(self._idle_sleep)

        with self._lock:
            self._current_target = None
            self._paused_reason = "stopped"
        self._notify()

    # ---- helpers ----

    def _sleep_or_exit(self, seconds: float) -> None:
        self._stop_event.wait(timeout=seconds)

    def _set_paused(self, reason: str) -> None:
        changed = False
        with self._lock:
            if self._paused_reason != reason or self._current_target is not None:
                self._paused_reason = reason
                self._current_target = None
                changed = True
        if changed:
            self._notify()

    def _clear_paused(self) -> None:
        changed = False
        with self._lock:
            if self._paused_reason is not None:
                self._paused_reason = None
                changed = True
        if changed:
            self._notify()

    def _notify(self) -> None:
        if self._on_status_change is None:
            return
        try:
            self._on_status_change(self.get_status())
        except Exception:  # noqa: BLE001
            pass

    def _resolve_current_path(self, programs: list) -> Optional[str]:
        """Map the dashboard's `active_binary` (a name like 'D2Common.dll')
        to a project path so it can be passed to pick_next_binary. Returns
        None if no current binary is set or it doesn't match any program
        in the project tree."""
        getter = self._current_binary_name_getter
        if getter is None:
            return None
        try:
            name = getter()
        except Exception:  # noqa: BLE001 — getter must not break the loop
            return None
        if not name:
            return None
        for prog in programs:
            if prog.get("name") == name:
                return prog.get("path")
        return None

    def _get_programs(self) -> list:
        now = time.time()
        if (
            self._cached_programs is not None
            and self._cached_programs_at is not None
            and (now - self._cached_programs_at) < self._programs_ttl_seconds
        ):
            return self._cached_programs
        folder = self._project_folder_getter()
        if not folder:
            return []
        progs = self._fetch_programs(folder) or []
        self._cached_programs = progs
        self._cached_programs_at = now
        return progs

    def _snapshot_inventory(self, programs: list) -> dict:
        """Build the per-binary inventory from persisted state, backfilling
        every program in the project tree so pick_next_binary can pick a
        not-yet-walked binary via the unfetched-sentinel."""
        persisted = load_inventory(self._state_dir).get("binaries", {})
        out: dict = {}
        for path, rec in persisted.items():
            out[path] = dict(rec)
        for prog in programs:
            path = prog["path"]
            if path not in out:
                out[path] = {
                    "name": prog["name"],
                    "total_documentable": 0,
                    "fully_documented": 0,
                    "last_scan": None,
                }
        return out

    def _audit_one_binary(self, prog_path: str) -> None:
        """Walk every global in the program, audit it, and tally totals."""
        try:
            globals_list = self._list_globals_for_program(prog_path)
        except Exception as exc:  # noqa: BLE001
            self._record_failure(prog_path, f"list_globals raised {exc}")
            return
        if globals_list is None:
            self._record_failure(prog_path, "list_globals returned None")
            return

        prog_name = Path(prog_path).name
        total = 0
        fully = 0
        for entry in globals_list:
            if self._stop_event.is_set():
                return
            if self._wm.has_active_workers():
                # Cooperative pause — same pattern as inventory_scorer.
                self._set_paused("doc workers active mid-scan")
                return
            addr = entry.get("address") if isinstance(entry, dict) else entry
            if not addr:
                continue
            try:
                audit = self._audit_global(prog_path, addr)
            except Exception as exc:  # noqa: BLE001
                self._record_failure(prog_path, f"audit_global({addr}) raised {exc}")
                return
            if not audit:
                continue
            total += 1
            issues = audit.get("issues") or []
            if not issues:
                fully += 1

        # Stamp the inventory.
        data = load_inventory(self._state_dir)
        bins = data.setdefault("binaries", {})
        bins[prog_path] = {
            "name": prog_name,
            "total_documentable": total,
            "fully_documented": fully,
            "last_scan": datetime.now().isoformat(),
        }
        save_inventory(self._state_dir, data)

        with self._lock:
            self._last_progress_at = datetime.now().isoformat()
            self._fail_streak.pop(prog_path, None)
        self._notify()

    def _record_failure(self, prog_path: str, reason: str) -> None:
        with self._lock:
            self._fail_streak[prog_path] = self._fail_streak.get(prog_path, 0) + 1
            self._last_error = f"{Path(prog_path).name}: {reason}"
        self._notify()
