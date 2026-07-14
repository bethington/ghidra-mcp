"""Capability-loop batch builder — UNFILTERED by difficulty.

Selection order: (1) retry-queue functions whose blocking capability landed,
(2) next pool functions from the cursor. NO class filtering — hard functions
are the point. Only hard skips: already CONF_LIVE+ (any rung), already
attempted this loop (they live in buckets awaiting a capability), and
library/runtime names (recorded to buckets.library as triage feedback, never
burned against the oracle).

Writes loop_iter_batch.json + updates loop_state.json.
"""
import json
import re
import sys
from pathlib import Path

FUNDOC = Path(r"C:\Users\benam\source\mcp\ghidra-mcp\fun-doc")
sys.path.insert(0, str(FUNDOC))
import port_pipeline as pp  # noqa: E402

# CRT / logging / OS-wrapper leakage in triage in_scope (iter-3 finding: the
# 0x6fd519xx-0x6fd58xxx stretch is C-runtime land -- LOG_CloseLogFileHandle,
# shortsort, FOpenShared, CRTUnlockExitLockIfNeeded all burned oracle cycles as
# no_vectors/malformed/crash). Recorded to buckets.library as feedback for the
# user's triage/scope classifier; never attempted. Extends (not replaces)
# pp._looks_like_library_or_runtime.
_LIB_RE = re.compile(
    r"^(LOG_|CRT|__|_[a-z]|FOpen|FClose|shortsort|swap|qsort|memcpy|memset|"
    r"strn?|wcs|Acquire|Release|Lock|Unlock|Display(Runtime|Security)|"
    r"GetDos|GetLocale|Interlocked|Heap|Critical|EnterCritical|LeaveCritical|"
    r"IsBadRead|IsBadWrite|Fltused|alloca|chkstk|"
    r"FILEIO|EH\d|Seh|ExitHandler|RunCrt|Realloc|CopyString|FormatString|"
    r"WriteFile|parse_|write_|report_|StoreSeh|Cleanup|Initializ|"
    r"ValidateHandler|cmdline|Flush|CloseHandle|Errno|Atexit|OnExit|Terminat|"
    r"CRITSEC|RtlUnwind|GetReturnAddress|FileLseek|ReadTextFile|ExtendFile|"
    r"setSBCS|CompareStrings|CopyMemory|BinarySearch|SearchBinaryTree)",
    re.IGNORECASE)
# All-lowercase snake_case (write_char, parse_cmdline) is CRT source naming --
# D2 game symbols are MODULE_CamelCase or CamelCase. Never matches game fns.
_SNAKE_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _is_library(name):
    return (pp._looks_like_library_or_runtime(name) or bool(_LIB_RE.search(name))
            or bool(_SNAKE_RE.match(name)))


import urllib.parse
import urllib.request

_IAT_RE = re.compile(r"JMP\s+dword ptr \[0x[0-9a-fA-F]+\]", re.IGNORECASE)


def _is_import_thunk(addr):
    """Single `JMP dword ptr [IAT]` body = cross-DLL import stub (Fog/Storm),
    triage disposition EXTERNAL. Checked at SELECTION time (one disasm probe)
    after iter 5 spent a whole batch slot-sweeping a 15-thunk band."""
    try:
        a = str(addr).lower().replace("0x", "")   # pool addrs carry 0x already
        u = ("http://127.0.0.1:8089/disassemble_function?"
             + urllib.parse.urlencode({"address": f"0x{a}",
                                       "program": "/Mods/PD2-S12/D2Common.dll"}))
        raw = urllib.request.urlopen(u, timeout=15).read().decode("utf-8", "replace")
        try:
            o = json.loads(raw)
            t = o.get("result", raw) if isinstance(o, dict) else raw
        except json.JSONDecodeError:
            t = raw
        lines = [l for l in str(t).splitlines() if re.match(r"^\s*0x?[0-9a-fA-F]+:", l)]
        return len(lines) <= 2 and bool(_IAT_RE.search(str(t)))
    except Exception:
        return False

HERE = Path(__file__).parent
STATE = HERE / "loop_state.json"
OUT = HERE / "loop_iter_batch.json"
POOL = Path(r"C:\Users\benam\source\cpp\D2MOO\conformance\profiler\triage_backlog.json")
REG = Path(r"C:\Users\benam\source\cpp\D2MOO\conformance\proven_functions.jsonl")


def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {"iteration": 0, "cursor": 0, "attempted": {}, "retry_queue": [],
            "buckets": {}, "journal": [], "phase": "idle"}


CAND_DIR = Path(r"C:\Users\benam\source\cpp\D2MOO\conformance\reimpl_provider\candidates")


def _git_tracked_candidates():
    """Set of candidate basenames git TRACKS (committed). These are curated --
    hand-authored foundational reimpls (unit_getmode.cpp == the UNIT_GetMode
    dispatcher, datatable_rowcount.cpp, seed_getrandom.cpp, ...) whose FILENAME
    does NOT match the export name. Auto-hygiene must NEVER touch them."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "ls-files", "reimpl_provider/candidates/"],
            cwd=str(CAND_DIR.parent.parent), capture_output=True, text=True, timeout=15)
        return {Path(p).stem for p in out.stdout.split() if p.endswith(".cpp")}
    except Exception:
        return None  # unknown -> fail SAFE (touch nothing)


def purge_orphan_candidates(proven_names):
    """CANDIDATES-DIR HYGIENE (2026-07-13, capability loop): the shared provider
    DLL compiles EVERY *.cpp in candidates/. A failed prove that leaves a
    TRUNCATED draft fails the WHOLE build, so correct reimpls marshal_fault
    (the provider-compile-cascade). Remove ONLY genuinely-broken drafts that are
    ALSO untracked by git.

    SAFETY (learned the hard way 2026-07-13): an earlier version keyed on
    'filename not in proven_names' and DELETED committed hand-authored
    foundational candidates (unit_getmode.cpp == UNIT_GetMode dispatcher, etc.)
    whose filename != export name. NEVER delete a git-tracked file, and NEVER
    use name-matching as the orphan signal -- only structural truncation
    (unbalanced braces / missing export marker) on an UNTRACKED file."""
    if not CAND_DIR.exists():
        return 0
    tracked = _git_tracked_candidates()
    if tracked is None:
        return 0  # can't tell what's committed -> touch nothing
    removed = 0
    for f in CAND_DIR.glob("*.cpp"):
        if f.stem in tracked:
            continue  # committed/curated -- never auto-delete
        txt = f.read_text(encoding="utf-8", errors="replace")
        truncated = (txt.count("{") != txt.count("}")
                     or txt.count("(") != txt.count(")")
                     or "D2MOO_REIMPL_EXPORT" not in txt)
        if truncated:
            f.unlink()
            removed += 1
    return removed


def main(count=15):
    state = load_state()
    pool = json.loads(POOL.read_text(encoding="utf-8"))["in_scope"]
    proven = set()
    proven_names = set()
    for line in REG.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("conf"):
                proven.add(r.get("address", "").lower())
                proven.add(r.get("name", ""))
                proven_names.add(r.get("name", ""))
    _purged = purge_orphan_candidates(proven_names)
    if _purged:
        print(f"[hygiene] purged {_purged} orphan candidate(s) to prevent build cascade")

    batch, lib_skips = [], []
    # 1) retries first (capability landed since they were bucketed)
    for e in list(state.get("retry_queue", [])):
        if len(batch) >= count:
            break
        batch.append(e)
        state["retry_queue"].remove(e)
    # 1b) GETTER-PRIORITY QUEUE (2026-07-13, user-directed jump-to-getters): a
    # persistent, pre-scanned list of getter-shaped fns from getter-dense
    # subsystems across the WHOLE pool. Drained before the cursor so the loop
    # produces proofs instead of grinding the sequential DRLG/PRESET stateful
    # band. The address-order cursor still advances underneath (completeness);
    # getters just jump the line. When getter_queue empties, fall back to cursor.
    gq = state.get("getter_queue", [])
    while gq and len(batch) < count:
        e = gq.pop(0)
        n, a = e["name"], e.get("address", "").lower()
        if a in proven or n in proven or n in state["attempted"]:
            continue
        batch.append({"name": n, "address": a})
    state["getter_queue"] = gq
    # 2) fresh pool from cursor
    cur = state.get("cursor", 0)
    while cur < len(pool) and len(batch) < count:
        e = pool[cur]
        cur += 1
        n, a = e["name"], e.get("address", "").lower()
        if a in proven or n in proven or n in state["attempted"]:
            continue
        if _is_library(n):
            lib_skips.append(n)
            state["attempted"][n] = "library"
            continue
        if _is_import_thunk(a):
            state["attempted"][n] = "import_thunk"
            state.setdefault("buckets", {}).setdefault(
                "import_thunk_external", []).append(n)
            continue
        batch.append({"name": n, "address": a})
    state["cursor"] = cur
    if lib_skips:
        state.setdefault("buckets", {}).setdefault("library", []).extend(lib_skips)

    state["iteration"] = state.get("iteration", 0) + 1
    state["phase"] = "proving"
    OUT.write_text(json.dumps(batch, indent=1) + "\n", encoding="utf-8")
    STATE.write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")
    print(f"iteration {state['iteration']}: {len(batch)} fns "
          f"(cursor {cur}/{len(pool)}, {len(lib_skips)} library->triage-feedback)")
    for e in batch:
        print(f"  {e['address']}  {e['name']}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 15)
