"""Background inventory scorer for fun-doc.

Continuously fills in missing `analyze_function_completeness` scores for every
binary in the Ghidra project tree, so the dashboard can show a complete
per-function inventory without the user having to manually run a scan.

Design (locked via Q&A 2026-04-25 — see CLAUDE.md / git history for the
full reasoning behind each choice):

  Q1 idle-time backfill — pauses when any doc worker runs.
  Q2 walks the entire Ghidra project tree.
  Q3 "complete" = every documentable function has a non-null score (coverage
     only, no freshness check).
  Q4 ordering: most-missing first, reverse-alphabetical tiebreaker.
  Q5 single scorer thread.
  Q6 status widget + Inventory tab on the dashboard.
  Q7 cooperative pause at batch boundaries; releases the program slot.
  Q8 session blacklist after 3 consecutive failures, cleared on restart.
  Q9 default-off, opt-in toggle in priority_queue.json.
  Q10 dedicated fun-doc/inventory.json for persistence.
  Q11 skip thunks/externals (matches select_candidates exclusion).
  Q12 scorer tracks its own program opens; never closes user-opened ones.

The module splits into:

  * Pure functions (compute_per_binary_inventory, pick_next_binary, etc.) —
    no threads, no I/O, easy to unit test.
  * Persistence helpers (load_inventory / save_inventory) — atomic JSON I/O.
  * InventoryScorer class — the threaded orchestrator. Pulls from the pure
    functions, consults a WorkerManager-like object's has_active_workers(),
    drives _fetch_function_list / _batch_score / save_state.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


INVENTORY_FILE_NAME = "inventory.json"
INVENTORY_FILE_VERSION = 1

# Number of addresses per outer chunk handed to _batch_score. Pause/yield is
# checked between chunks, so smaller = more responsive pause, larger = less
# overhead. 50 is a reasonable middle ground; tunable via CHUNK_SIZE param to
# InventoryScorer if we ever need to scale it.
DEFAULT_CHUNK_SIZE = 50

# A binary is dropped from the queue after this many consecutive failures in
# the same dashboard session. Cleared on restart per Q8.
DEFAULT_FAIL_STRIKES = 3

# Idle sleep between completed iterations / when paused. Keeps the thread
# from busy-waiting while still picking up doc-worker-finished transitions
# without noticeable lag.
IDLE_SLEEP_SECONDS = 5.0


# ---------- pure functions: ordering, blacklist, scored counts ----------


def is_documentable(func: dict) -> bool:
    """Q11: a function counts toward the inventory if it's not a thunk and
    not external. Mirrors select_candidates's exclusion."""
    return not func.get("is_thunk") and not func.get("is_external")


def is_scored(func: dict) -> bool:
    """A function counts as 'scored' if its state.json entry has a numeric
    `score` field. 0 counts as scored (a legitimately trivial function still
    has a real score). Missing entry or null means unscored."""
    score = func.get("score")
    return isinstance(score, (int, float))


def compute_per_binary_inventory(
    state_funcs: dict, totals_by_path: Optional[dict] = None
) -> dict:
    """Tally documentable + scored functions per program path.

    state_funcs is state["functions"] (key -> entry). totals_by_path, when
    supplied, is a path -> total_documentable map from a fresh function-list
    fetch; fields it covers override what we'd derive from state alone (some
    functions may exist in Ghidra but not yet in state.json — those are
    unscored). When totals_by_path is None, totals come from state alone
    (used in tests and on initial load before any binary has been walked).

    Returns: {program_path: {name, total_documentable, scored, last_scan}}
    last_scan is None here — caller fills it from inventory.json overlay.
    """
    out: dict = {}
    for entry in state_funcs.values():
        prog_path = entry.get("program")
        if not prog_path:
            continue
        if not is_documentable(entry):
            continue
        rec = out.setdefault(
            prog_path,
            {
                "name": entry.get("program_name") or Path(prog_path).name,
                "total_documentable": 0,
                "scored": 0,
                "last_scan": None,
            },
        )
        rec["total_documentable"] += 1
        if is_scored(entry):
            rec["scored"] += 1

    if totals_by_path:
        for path, total in totals_by_path.items():
            rec = out.setdefault(
                path,
                {
                    "name": Path(path).name,
                    "total_documentable": 0,
                    "scored": 0,
                    "last_scan": None,
                },
            )
            # Fresh totals override state-derived totals (Ghidra is the
            # authority on what functions exist; state.json may lag).
            rec["total_documentable"] = total
            # scored cannot exceed total — clamp if state has stale entries.
            if rec["scored"] > total:
                rec["scored"] = total
    return out


def status_for(rec: dict) -> str:
    """Derive the per-binary status from its inventory record."""
    total = rec.get("total_documentable", 0) or 0
    scored = rec.get("scored", 0) or 0
    last = rec.get("last_scan")
    if total == 0:
        # Either no documentable functions or we haven't fetched the list yet.
        return "untouched" if last is None else "complete"
    if scored >= total:
        return "complete"
    if scored == 0 and last is None:
        return "untouched"
    return "in_progress"


def pick_next_binary(
    inventory: dict,
    candidate_paths: list,
    blacklist: set,
) -> Optional[str]:
    """Q4 ordering: among candidate_paths, pick the binary with the most
    missing scores; tiebreak reverse-alphabetical (later in alphabet wins).
    Skip paths in blacklist. None when nothing eligible.
    """
    best_path = None
    best_key = None  # (missing, name) — bigger missing wins; bigger name wins on tie
    for path in candidate_paths:
        if path in blacklist:
            continue
        rec = inventory.get(path) or {}
        total = rec.get("total_documentable", 0) or 0
        scored = rec.get("scored", 0) or 0
        # Treat unfetched binaries (total=0, last_scan=None) as having
        # unknown-but-likely-positive missing — score them ahead of "complete"
        # binaries but behind known-large-deficit ones.
        if total == 0 and rec.get("last_scan") is None:
            missing = 1  # tiny positive sentinel — gets picked over complete
        else:
            missing = max(0, total - scored)
        if missing <= 0:
            continue
        name = rec.get("name") or Path(path).name
        key = (missing, name)
        if best_key is None or key > best_key:
            best_key = key
            best_path = path
    return best_path


# ---------- persistence ----------


def _inventory_path(base_dir: Path) -> Path:
    return Path(base_dir) / INVENTORY_FILE_NAME


def load_inventory(base_dir: Path) -> dict:
    """Load inventory.json. Returns a fresh skeleton if the file is missing
    or corrupt — never raises so the dashboard can boot through bad state."""
    path = _inventory_path(base_dir)
    if not path.exists():
        return {"version": INVENTORY_FILE_VERSION, "binaries": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"version": INVENTORY_FILE_VERSION, "binaries": {}}
    # Schema fix-ups for older shapes.
    if not isinstance(data, dict):
        return {"version": INVENTORY_FILE_VERSION, "binaries": {}}
    data.setdefault("version", INVENTORY_FILE_VERSION)
    bins = data.get("binaries")
    if not isinstance(bins, dict):
        data["binaries"] = {}
    return data


def save_inventory(base_dir: Path, data: dict) -> None:
    """Atomic write of inventory.json — same tmp-then-replace pattern as
    save_priority_queue / save_state."""
    path = _inventory_path(base_dir)
    tmp = path.with_suffix(".json.tmp")
    payload = {
        "version": INVENTORY_FILE_VERSION,
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


class InventoryScorer:
    """Single-threaded background scorer. See module docstring for design.

    Construction takes injected callables so the class is usable in tests
    without standing up the whole fun_doc module. Only `start()` actually
    spawns a thread; pure-logic methods can be exercised standalone.
    """

    def __init__(
        self,
        *,
        worker_manager,
        project_folder_getter,
        state_dir: Path,
        load_state,
        save_state,
        fetch_programs,
        fetch_function_list,
        batch_score,
        on_status_change=None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        fail_strikes: int = DEFAULT_FAIL_STRIKES,
        idle_sleep: float = IDLE_SLEEP_SECONDS,
    ):
        self._wm = worker_manager
        self._project_folder_getter = project_folder_getter
        self._state_dir = Path(state_dir)
        self._load_state = load_state
        self._save_state = save_state
        self._fetch_programs = fetch_programs
        self._fetch_function_list = fetch_function_list
        self._batch_score = batch_score
        self._on_status_change = on_status_change
        self._chunk_size = chunk_size
        self._fail_strikes = fail_strikes
        self._idle_sleep = idle_sleep

        self._enabled = False
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        # Per-binary fail counters, session-only (Q8). Map path -> consecutive
        # failures. Once >= fail_strikes, the path is treated as blacklisted
        # for this dashboard session.
        self._fail_streak: dict = {}

        # Live runtime state — surfaced to the dashboard.
        self._current_target: Optional[str] = None
        self._paused_reason: Optional[str] = None
        self._last_progress_at: Optional[str] = None
        self._last_error: Optional[str] = None

        # Cached project file list. Refreshed lazily.
        self._cached_programs: Optional[list] = None
        self._cached_programs_at: Optional[float] = None
        # Refresh project file list at most this often. The Ghidra project
        # tree doesn't change frequently mid-session, but we still want to
        # pick up new imports without a dashboard restart.
        self._programs_ttl_seconds = 300

    # ---- public API ----

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Idempotent enable/disable. If enabling and the thread isn't
        already running, start it; if disabling, signal the thread to exit
        but don't block. The thread loops on the stop_event so it'll wake
        and exit on its own."""
        with self._lock:
            if enabled == self._enabled:
                return
            self._enabled = enabled
            if enabled:
                self._stop_event.clear()
                if not self._thread or not self._thread.is_alive():
                    self._thread = threading.Thread(
                        target=self._run,
                        name="fundoc-inventory-scorer",
                        daemon=True,
                    )
                    self._thread.start()
            else:
                self._stop_event.set()
                self._paused_reason = "disabled"
                self._current_target = None
        self._notify()

    def get_status(self) -> dict:
        """Snapshot of scorer state for the dashboard."""
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
        """Clear the session blacklist for one path or all paths. Used by
        the Inventory tab's per-row 'Retry' button and a 'Clear all' button."""
        with self._lock:
            if path is None:
                self._fail_streak.clear()
            else:
                self._fail_streak.pop(path, None)

    # ---- thread loop ----

    def _run(self) -> None:
        """Main loop. Sleeps when paused/idle, picks the next binary when
        active, scores it chunk-at-a-time with pause checks between chunks."""
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
                    p
                    for p, n in self._fail_streak.items()
                    if n >= self._fail_strikes
                }
                target = pick_next_binary(
                    inventory,
                    [p["path"] for p in programs],
                    blacklist,
                )
                if target is None:
                    self._set_paused("inventory complete")
                    self._sleep_or_exit(self._idle_sleep)
                    continue

                self._clear_paused()
                with self._lock:
                    self._current_target = target
                self._notify()

                # Run one binary scan; yields between chunks if a worker starts.
                self._score_one_binary(target)
            except Exception as exc:  # noqa: BLE001 — defensive, never let the scorer thread die
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
        # Event.wait returns True early if set — so we exit promptly when
        # set_enabled(False) flips the flag.
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
        except Exception:  # noqa: BLE001 — callbacks must not break the loop
            pass

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
        """Build the per-binary inventory by overlaying state.json counts on
        top of the persisted inventory.json (which carries totals + last_scan
        for binaries we've already walked)."""
        state = self._load_state()
        funcs = state.get("functions") or {}
        # Persisted totals from prior walks — used until we re-fetch the list.
        persisted = load_inventory(self._state_dir).get("binaries", {})
        totals_by_path = {
            path: rec.get("total_documentable", 0)
            for path, rec in persisted.items()
            if rec.get("total_documentable")
        }
        # State-derived per-binary tallies.
        derived = compute_per_binary_inventory(funcs, totals_by_path=totals_by_path)
        # Backfill any program in the project tree that's not in state yet —
        # they'd have total=0 from state but we want them in the queue so
        # pick_next_binary can pick them (with the unfetched-sentinel).
        for prog in programs:
            path = prog["path"]
            rec = derived.setdefault(
                path,
                {
                    "name": prog["name"],
                    "total_documentable": 0,
                    "scored": 0,
                    "last_scan": None,
                },
            )
            # Carry forward last_scan from persisted record so a previously-
            # walked binary stays "complete" even if state.json got nuked.
            if path in persisted:
                rec["last_scan"] = persisted[path].get("last_scan")
        return derived

    def _score_one_binary(self, prog_path: str) -> None:
        """Fetch the function list for prog_path, identify unscored
        documentable functions, score them in chunks, persist results, and
        bump the last_scan timestamp. Yields (returns early) when a doc
        worker becomes active mid-scan; the next loop iteration will pick
        up the same binary if it's still the most-missing."""
        func_list = self._fetch_function_list(prog_path)
        if func_list is None:
            self._record_failure(prog_path, "fetch_function_list returned None")
            return

        # Build documentable view + which need scoring.
        documentable = [
            f for f in func_list if not f.get("isThunk") and not f.get("isExternal")
        ]
        total_documentable = len(documentable)

        state = self._load_state()
        funcs = state.setdefault("functions", {})

        addrs_to_score: list[str] = []
        for f in documentable:
            key = f"{prog_path}::{f['address']}"
            cached = funcs.get(key)
            if cached is None or not is_scored(cached):
                addrs_to_score.append(f"0x{f['address']}")

        if not addrs_to_score:
            # Already complete — record the totals and last_scan so the
            # status flips to "complete" without re-scoring.
            self._stamp_inventory(
                prog_path,
                Path(prog_path).name,
                total_documentable=total_documentable,
                scored_delta=0,
                replace_scored=total_documentable,
            )
            self._fail_streak.pop(prog_path, None)
            return

        prog_name = (
            (documentable[0].get("program_name") if documentable else None)
            or Path(prog_path).name
        )

        addr_to_func = {f["address"]: f for f in documentable}
        chunked_count = 0
        for i in range(0, len(addrs_to_score), self._chunk_size):
            if self._stop_event.is_set():
                return
            if self._wm.has_active_workers():
                # Q7: cooperative pause at chunk boundary, release implicit
                # (we hold no Ghidra-side handles; _batch_score is per-call).
                self._set_paused("doc workers active mid-scan")
                return

            chunk = addrs_to_score[i : i + self._chunk_size]
            try:
                score_map = self._batch_score(chunk, prog_path) or {}
            except Exception as exc:  # noqa: BLE001
                self._record_failure(prog_path, f"batch_score raised {exc}")
                return

            chunk_scored = self._apply_chunk_results(
                state, funcs, prog_path, prog_name, addr_to_func, chunk, score_map
            )
            chunked_count += chunk_scored
            self._save_state(state)
            self._stamp_inventory(
                prog_path,
                prog_name,
                total_documentable=total_documentable,
                scored_delta=chunk_scored,
            )
            with self._lock:
                self._last_progress_at = datetime.now().isoformat()
            self._notify()

        # Whole binary processed without a yield — clear failure streak.
        self._fail_streak.pop(prog_path, None)

    def _apply_chunk_results(
        self,
        state: dict,
        funcs: dict,
        prog_path: str,
        prog_name: str,
        addr_to_func: dict,
        chunk_addrs: list,
        score_map: dict,
    ) -> int:
        """Merge per-function scoring results into state['functions'].
        Returns the number of newly-scored functions (i.e., entries that
        gained an integer score field this call)."""
        newly_scored = 0
        now_iso = datetime.now().isoformat()
        for raw_addr in chunk_addrs:
            # _batch_score returns score_map keyed by address without 0x.
            addr_no_prefix = raw_addr[2:] if raw_addr.startswith("0x") else raw_addr
            score_info = score_map.get(addr_no_prefix)
            if not score_info or "error" in (score_info or {}):
                # Ghidra-side failure on a single function; leave entry
                # absent so it'll be retried on the next pass.
                continue
            f = addr_to_func.get(addr_no_prefix)
            if f is None:
                continue
            key = f"{prog_path}::{addr_no_prefix}"
            prior = funcs.get(key)
            had_score = prior is not None and is_scored(prior)
            funcs[key] = {
                "program": prog_path,
                "program_name": prog_name,
                "address": addr_no_prefix,
                "name": f.get("name", ""),
                "score": score_info.get("score", 0),
                "fixable": score_info.get("fixable", 0),
                "has_custom_name": score_info.get("has_custom_name", False),
                "has_plate_comment": score_info.get("has_plate_comment", False),
                "deductions": score_info.get("deductions", []),
                "caller_count": (prior or {}).get("caller_count", 0),
                "is_leaf": score_info.get("is_leaf", False),
                "classification": score_info.get("classification", "unknown"),
                "is_thunk": False,
                "is_external": False,
                "last_processed": now_iso,
                "last_result": "inventory-scored",
            }
            if not had_score:
                newly_scored += 1
        return newly_scored

    def _stamp_inventory(
        self,
        path: str,
        name: str,
        *,
        total_documentable: int,
        scored_delta: int,
        replace_scored: Optional[int] = None,
    ) -> None:
        """Update inventory.json for one binary."""
        data = load_inventory(self._state_dir)
        bins = data.setdefault("binaries", {})
        rec = bins.setdefault(
            path,
            {
                "name": name,
                "total_documentable": 0,
                "scored": 0,
                "last_scan": None,
            },
        )
        rec["name"] = name
        rec["total_documentable"] = total_documentable
        if replace_scored is not None:
            rec["scored"] = replace_scored
        else:
            rec["scored"] = min(
                total_documentable, (rec.get("scored", 0) or 0) + scored_delta
            )
        rec["last_scan"] = datetime.now().isoformat()
        save_inventory(self._state_dir, data)

    def _record_failure(self, prog_path: str, reason: str) -> None:
        with self._lock:
            self._fail_streak[prog_path] = self._fail_streak.get(prog_path, 0) + 1
            self._last_error = f"{Path(prog_path).name}: {reason}"
        self._notify()
