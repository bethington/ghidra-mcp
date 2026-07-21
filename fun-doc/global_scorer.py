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
import re
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

# Version of the "counts as documented" rules below. Stamped into every
# inventory record; a record stamped under an older version is treated as
# never-scanned (bypasses the rescan cooldown) so a rules change
# automatically triggers a full re-walk instead of leaving every stored
# tally stale until someone clicks 31 per-binary reset buttons.
#   v2 (2026-07-09): severity-tiered bar — soft-only, OS-canonical, and
#   code-label globals count as documented, matching the doc-worker.
RULES_VERSION = 2


_PHANTOM_PROGRAM_RE = re.compile(r"\.\d+$")


def _is_phantom_program_name(name):
    """True for Ghidra project artifacts like `D2Launch.dll.0` — a second,
    trailing-.N versioned copy of a program that shouldn't be walked or
    counted (it double-counts a binary and skews inventory totals). Matches
    a trailing `.<digits>` after a real file extension. Real programs
    (`D2Launch.dll`, `Game.exe`) never end in `.<digits>`."""
    if not name:
        return False
    return bool(_PHANTOM_PROGRAM_RE.search(name))


def classify_documented(audit, address=None):
    """Classify one global's documentation state under the severity-tiered
    bar, matching the doc-worker's own completion/skip rules
    (fun_doc.process_global). Returns one of:

      * "clean"        — zero issues
      * "soft_only"    — only soft issues (plate_line_too_long etc.);
                         non-blocking by design
      * "code_label"   — the address is code / a function label, not data
      * "os_canonical" — TIB/PEB/KUSER symbol; the Microsoft name IS the
                         documentation
      * "pending"      — has hard/medium issues; real work remains

    Everything except "pending" counts as documented. Before this bar the
    scorer counted raw `issues != []` and reported a binary as 71-pending
    when the worker had legitimately drained it — which kept continuous
    mode re-picking already-drained binaries forever."""
    issues = audit.get("issues") or []
    if not issues:
        return "clean"
    if audit.get("is_code_address") or audit.get("is_function_entry"):
        return "code_label"
    name = audit.get("name") or ""
    addr = str(address or audit.get("address") or "")
    try:
        # Same predicates the worker's skip path uses. Lazy import: fun_doc
        # imports this module (function-locally), so a module-level import
        # here would be circular; at runtime fun_doc is already loaded.
        from fun_doc import _is_os_canonical_global, _looks_like_function_label

        if _looks_like_function_label(name):
            return "code_label"
        if _is_os_canonical_global(name, addr if addr.startswith("0x") else f"0x{addr.replace('ram:', '')}"):
            return "os_canonical"
    except Exception:  # noqa: BLE001 — standalone/test fallback below
        for prefix in ("FID_conflict:", "FID_", "FUN_", "thunk_", "j_", "_imp_", "__imp_"):
            if name.startswith(prefix):
                return "code_label"
        try:
            addr_int = int(addr.replace("ram:", "").replace("0x", ""), 16)
            if 0xFFDF0000 <= addr_int <= 0xFFDFFFFF:
                return "os_canonical"
            if 0x7FFE0000 <= addr_int <= 0x7FFEFFFF:
                return "os_canonical"
        except (ValueError, TypeError):
            pass
    sev = audit.get("severity_summary") or {}
    if sev and ((sev.get("hard", 0) or 0) + (sev.get("medium", 0) or 0)) == 0:
        return "soft_only"
    return "pending"


def counts_as_documented(audit, address=None):
    """Boolean view of classify_documented — kept for existing callers."""
    return classify_documented(audit, address) != "pending"


# ---------- pure functions: ordering, status, persistence ----------


def status_for(rec: dict) -> str:
    """Derive the per-binary global-coverage status from its record.
    Records with `total=0` are never reported as "complete" — that
    combination used to be the bug signature for "scorer ran into a
    closed binary and stamped zeros." Status reflects re-pickable state.

    Mirrors inventory_scorer.status_for. A binary's globals are "complete"
    when every documentable global has zero issues; "in_progress" while
    some are still flagged; "untouched" until the scorer has visited it.
    """
    total = rec.get("total_documentable", 0) or 0
    fully = rec.get("fully_documented", 0) or 0
    last = rec.get("last_scan")
    if total == 0:
        return "untouched" if last is None else "in_progress"
    if fully >= total:
        return "complete"
    if fully == 0 and last is None:
        return "untouched"
    return "in_progress"


def _pick_least_recent(
    inventory: dict,
    candidate_paths: list,
    blacklist: set,
) -> Optional[str]:
    """Force-on fallback: pick the oldest-scanned binary so the re-walk
    surfaces stale data first. Mirrors inventory_scorer._pick_least_recent."""
    best_path = None
    best_key = None
    for path in candidate_paths:
        if path in blacklist:
            continue
        last = (inventory.get(path) or {}).get("last_scan")
        key = (0, "") if last is None else (1, last)
        if best_key is None or key < best_key:
            best_key = key
            best_path = path
    return best_path


def _has_pending(rec: dict) -> int:
    """Returns the number of globals still needing documentation for one
    inventory record. Any record with total=0 is treated as re-pickable
    (sentinel=1):
      * `total=0 AND last_scan is None` — never walked, sentinel applies as before.
      * `total=0 AND last_scan is set` — bug signature from a pre-fix scorer
        run that stamped an empty fetch as "0/0 complete". Auto-heal: treat
        as unfetched-equivalent so the fixed scorer re-walks it. The bug
        that produced this signature is fixed in `_audit_one_binary` (empty
        list now records a failure rather than stamping zeros)."""
    total = rec.get("total_documentable", 0) or 0
    fully = rec.get("fully_documented", 0) or 0
    if total == 0:
        return 1
    if rec.get("rules_version") != RULES_VERSION:
        # Stamped under an older counting bar — the stored tally can't be
        # trusted, so the binary is re-pickable regardless of it.
        return max(1, total - fully)
    return max(0, total - fully)


# Once a binary has been audited, suppress re-picks for this long. Without
# this, "most-with-issues first" ordering kept selecting D2Game.dll forever
# after a successful walk because its 328 unresolved issues outranked every
# other candidate. The scorer needs to rotate through every binary at least
# once before re-auditing any of them. Doc-worker fixes for a given binary
# will be reflected on the next cycle.
RESCAN_COOLDOWN_SECONDS = 3600


def _scan_age_seconds(rec: dict) -> float:
    """Seconds since this binary was last scanned. Returns infinity when
    never scanned (or the timestamp is unparseable) so never-walked
    binaries always sort ahead of any scanned candidate. A record stamped
    under an older RULES_VERSION is also treated as never-scanned — its
    stored tally is meaningless under the current bar, so it must bypass
    the rescan cooldown."""
    if rec.get("last_scan") and rec.get("rules_version") != RULES_VERSION:
        return float("inf")
    last = rec.get("last_scan")
    if not last:
        return float("inf")
    try:
        return (datetime.now() - datetime.fromisoformat(last)).total_seconds()
    except (ValueError, TypeError):
        return float("inf")


def pick_next_binary(
    inventory: dict,
    candidate_paths: list,
    blacklist: set,
    current_path: Optional[str] = None,
    rescan_cooldown_seconds: float = RESCAN_COOLDOWN_SECONDS,
) -> Optional[str]:
    """Pick the next binary to audit.

    Priority:
      1. `current_path` (the user's focused binary), if it has pending
         issues and is past the cooldown window.
      2. Never-scanned binaries with pending issues — primary backlog.
      3. Stale-scanned binaries (last scan older than cooldown) with
         pending issues — oldest first, so the rotation revisits the
         binary that's gone the longest without an update.

    Returns None when every binary has either no pending issues or was
    scanned within the cooldown — that's the legitimate "everything's
    covered, sit idle until a recent scan ages out" state.

    The cooldown is the fix for the production loop where a 328-issue
    binary kept winning the most-issues tiebreak and got re-walked every
    few seconds, blocking the other 30 binaries from ever being scanned.
    """
    # Helper to apply the same cooldown rule everywhere.
    def _eligible(path: str) -> bool:
        if path in blacklist:
            return False
        rec = inventory.get(path) or {}
        if _has_pending(rec) <= 0:
            return False
        return _scan_age_seconds(rec) >= rescan_cooldown_seconds

    if current_path and current_path in candidate_paths and _eligible(current_path):
        return current_path

    eligible = [p for p in candidate_paths if _eligible(p)]
    if not eligible:
        return None

    # Sort largest-tuple-first via reverse=True. Primary key is scan age
    # (largest age = oldest = goes first; never-scanned has inf age and
    # naturally wins). Tiebreaks preserve the legacy "most-missing,
    # reverse-alpha" ordering for equal ages — relevant on the initial
    # pass when every binary is unscanned.
    eligible.sort(
        key=lambda p: (
            _scan_age_seconds(inventory.get(p) or {}),
            _has_pending(inventory.get(p) or {}),
            (inventory.get(p) or {}).get("name") or Path(p).name,
        ),
        reverse=True,
    )
    return eligible[0]


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
        # Force-on overrides every loop-level pause. See inventory_scorer
        # for the full rationale (Q3=C trade-off accepted).
        self._force_on = False
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
                "force_on": self._force_on,
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

    def set_force_on(self, force_on: bool) -> None:
        """Toggle force-on mode (Q3=C). Mirrors InventoryScorer.set_force_on."""
        with self._lock:
            self._force_on = bool(force_on)
        self._notify()

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
                if self._wm.has_active_workers() and not self._force_on:
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
                    if self._force_on:
                        target = _pick_least_recent(
                            inventory,
                            [p["path"] for p in programs],
                            blacklist,
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
        progs = [p for p in progs if not _is_phantom_program_name(p.get("name"))]
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

    # Stamp progress every N audited globals so partial work survives
    # mid-scan interruptions (pause, stop, exception). Sized small enough
    # that a typical pause loses < 1s of work, large enough to keep the
    # inventory.json write rate reasonable.
    AUDIT_STAMP_EVERY = 50

    # An audit walk is treated as successful (and stamped fully complete)
    # as long as fewer than this fraction of audits raised exceptions.
    # Above the threshold, the binary is treated as broken and gets a
    # strike — protects against runaway walks where every audit fails.
    AUDIT_FAILURE_RATIO = 0.5

    def _audit_one_binary(self, prog_path: str) -> None:
        """Walk every global in the program, audit it, and tally totals.
        Stamps progress incrementally every AUDIT_STAMP_EVERY entries so
        partial work survives any mid-walk pause / stop / individual audit
        exception. Single audit exceptions are skipped (counted as errors,
        not fatal) so one malformed address can't kill a thousand-global
        walk — that was the original "no progress on D2Game.dll" symptom."""
        try:
            globals_list = self._list_globals_for_program(prog_path)
        except Exception as exc:  # noqa: BLE001
            self._record_failure(prog_path, f"list_globals raised {exc}")
            return
        if globals_list is None:
            self._record_failure(prog_path, "list_globals returned None")
            return
        if not globals_list:
            # Empty list = couldn't open the binary or /list_globals returned
            # []. Stamping "0/0 complete" would lock the binary out forever
            # (legacy bug). Record a strike so the blacklist machinery handles
            # it instead.
            self._record_failure(prog_path, "list_globals returned empty list")
            return

        prog_name = Path(prog_path).name
        total_to_audit = len(globals_list)
        total = 0
        fully = 0
        errors = 0
        cats = {"clean": 0, "soft_only": 0, "os_canonical": 0, "code_label": 0, "pending": 0}
        last_stamp_at = 0
        print(
            f"  [global-scorer] {prog_name}: auditing {total_to_audit} globals",
            flush=True,
        )

        for idx, entry in enumerate(globals_list):
            if self._stop_event.is_set():
                self._stamp_partial(prog_path, prog_name, total, fully, cats)
                return
            if self._wm.has_active_workers() and not self._force_on:
                # Cooperative pause — partial progress is stamped before
                # bailing so the next pass can pick up where we left off
                # (or at least show real numbers in the dashboard).
                self._stamp_partial(prog_path, prog_name, total, fully, cats)
                self._set_paused("doc workers active mid-scan")
                return
            addr = entry.get("address") if isinstance(entry, dict) else entry
            if not addr:
                continue
            try:
                audit = self._audit_global(prog_path, addr)
            except Exception as exc:  # noqa: BLE001
                # Skip individual failures — one bad address must not
                # abort thousands of successful audits. Tracked in
                # `errors` and used to detect a fully-broken walk below.
                errors += 1
                if errors <= 3:
                    print(
                        f"  [global-scorer] {prog_name}: audit_global({addr}) "
                        f"raised {type(exc).__name__}: {exc}",
                        flush=True,
                    )
                continue
            if not audit:
                continue
            total += 1
            cat = classify_documented(audit, addr)
            cats[cat] = cats.get(cat, 0) + 1
            if cat != "pending":
                fully += 1
            # Periodic stamp + console progress so the dashboard sees
            # work happening before the walk completes.
            if total - last_stamp_at >= self.AUDIT_STAMP_EVERY:
                self._stamp_partial(prog_path, prog_name, total, fully, cats)
                last_stamp_at = total
                print(
                    f"  [global-scorer] {prog_name}: {total}/{total_to_audit} "
                    f"audited, {fully} fully documented",
                    flush=True,
                )

        # Final stamp — full counts.
        self._stamp_partial(prog_path, prog_name, total, fully, cats)

        # If almost every audit failed, treat the binary as broken so it
        # eventually gets blacklisted instead of looping forever.
        if total_to_audit > 0 and errors / max(total_to_audit, 1) >= self.AUDIT_FAILURE_RATIO:
            self._record_failure(
                prog_path,
                f"{errors}/{total_to_audit} audits raised exceptions",
            )
            return

        with self._lock:
            self._last_progress_at = datetime.now().isoformat()
            self._fail_streak.pop(prog_path, None)
        print(
            f"  [global-scorer] {prog_name}: done ({total} audited, "
            f"{fully} fully documented, {errors} errors)",
            flush=True,
        )
        self._notify()

    def _stamp_partial(
        self, prog_path: str, prog_name: str, total: int, fully: int, cats: Optional[dict] = None
    ) -> None:
        """Write the current tally to global_inventory.json. Called both
        mid-walk (so partial progress survives interruptions) and at the
        end of a successful walk. `cats` is the classify_documented
        category breakdown; `rules_version` stamps which counting bar
        produced the record so a bar change auto-invalidates it."""
        try:
            data = load_inventory(self._state_dir)
            bins = data.setdefault("binaries", {})
            rec = {
                "name": prog_name,
                "total_documentable": total,
                "fully_documented": fully,
                "last_scan": datetime.now().isoformat(),
                "rules_version": RULES_VERSION,
            }
            for key in ("clean", "soft_only", "os_canonical", "code_label", "pending"):
                rec[key] = (cats or {}).get(key, 0)
            bins[prog_path] = rec
            save_inventory(self._state_dir, data)
        except Exception as exc:  # noqa: BLE001 — never let a stamp failure kill the walk
            print(
                f"  [global-scorer] {prog_name}: stamp failed ({type(exc).__name__}: {exc})",
                flush=True,
            )

    def _record_failure(self, prog_path: str, reason: str) -> None:
        with self._lock:
            self._fail_streak[prog_path] = self._fail_streak.get(prog_path, 0) + 1
            self._last_error = f"{Path(prog_path).name}: {reason}"
        self._notify()
