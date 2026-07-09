"""battletest_promoter.py -- the promotion half of the continuous port loop's
"shadow to verify" step (sibling to shadow_promote.py, which STAGES a function
as a shadow dispatcher; this module watches the ALREADY-STAGED-AND-DEPLOYED
dispatchers and promotes CONF_LIVE -> CONF_BATTLETESTED once real gameplay has
produced enough zero-divergence evidence).

This automates, exactly, the manual procedure run by hand 2026-07-07 (see
conformance/D2COMMON_FULL_SHADOW_PLAN.md and proven_functions.jsonl history):
poll D2Debugger's /dispatchers, and for any dispatcher in shadow mode with
zero divergences and hits over a volume bar, flip its Ghidra CONF_ tag and
registry row from CONF_LIVE to CONF_BATTLETESTED.

Standalone (imports nothing from fun_doc). Two ways to use it:
  - CLI: `python battletest_promoter.py` (one poll+promote pass) or
         `python battletest_promoter.py --loop --interval 60` (continuous).
  - Library: `poll_and_promote()` from fun_doc's continuous port-worker loop
    (best-effort, non-fatal -- see maybe_promote's docstring).
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import time
import urllib.parse
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROVEN_REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790")
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

_D2COMMON_BASE = 0x6FD50000
BATTLE_MIN_HITS = int(os.environ.get("FUNDOC_BATTLETEST_MIN_HITS", "1000"))

CONF_TAGS = ["CONF_DRAFT", "CONF_VECTORS", "CONF_LIVE", "CONF_BATTLETESTED"]


def _http_get_json(base_url: str, path: str, timeout: int = 8) -> dict:
    u = urllib.parse.urlparse(base_url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request("GET", path)
        raw = conn.getresponse().read().decode("utf-8", "replace")
    finally:
        conn.close()
    return json.loads(raw)


def _ghidra_post(path: str, data: dict) -> dict:
    u = urllib.parse.urlparse(GHIDRA_HTTP)
    conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=15)
    try:
        conn.request("POST", path, body=json.dumps(data),
                      headers={"Content-Type": "application/json"})
        raw = conn.getresponse().read().decode("utf-8", "replace")
    except OSError as e:
        return {"error": f"ghidra unreachable: {e}"}
    finally:
        conn.close()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": raw[:200]}


def _set_battletested(address_hex: str, program: str = "D2Common.dll") -> dict:
    others = ",".join(t for t in CONF_TAGS if t != "CONF_BATTLETESTED")
    _ghidra_post("/remove_function_tag", {"function": address_hex, "tags": others, "program": program})
    return _ghidra_post("/add_function_tag",
                         {"function": address_hex, "tags": "CONF_BATTLETESTED", "program": program})


def _load_registry() -> list:
    if not PROVEN_REGISTRY.exists():
        return []
    return [json.loads(l) for l in PROVEN_REGISTRY.read_text(encoding="utf-8").splitlines() if l.strip()]


def _save_registry(rows: list) -> None:
    PROVEN_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    with open(PROVEN_REGISTRY, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def poll_and_promote(*, min_hits: int = BATTLE_MIN_HITS, program: str = "D2Common.dll") -> dict:
    """One pass: read live dispatcher hit/divergence counters, refresh the
    registry's shadow_hits/shadow_divergences on every dispatcher-active row,
    and promote any CONF_LIVE row that has crossed the zero-divergence volume
    bar. Best-effort -- returns {"ok": False, "error": ...} on any connectivity
    problem rather than raising (this is meant to run unattended)."""
    try:
        disp = _http_get_json(ORACLE_URL, "/dispatchers")
    except OSError as e:
        return {"ok": False, "error": f"D2Debugger unreachable: {e}"}
    if not disp.get("ok"):
        return {"ok": False, "error": disp.get("error", "bad /dispatchers response")}

    rows = _load_registry()
    by_key = {(r["name"], r["address"]): r for r in rows}
    promoted = []
    for d in disp.get("dispatchers", []):
        addr_hex = f"0x{_D2COMMON_BASE + d['offset']:x}"
        key = (d["name"], addr_hex)
        r = by_key.get(key)
        if r is None:
            continue  # not a fun-doc/hand-tracked function; nothing to update
        hits, divs = d.get("hits", 0), d.get("divergences", 0)
        r["shadow_hits"] = hits
        r["shadow_divergences"] = divs
        r["shadow_mode"] = d.get("modeName")
        # WINDOWED rate since the last epoch. A hot-reloaded fix (verify_shadow_fix /
        # --set-epoch) records the counters at fix time as shadow_epoch_*; we then
        # judge the DELTA, so a fixed function promotes on its own without a game
        # restart to clear the pre-fix (poisoned) cumulative divergences. Default
        # epoch 0/0 == lifetime totals (unchanged behavior for never-reset rows).
        eh = r.get("shadow_epoch_hits", 0)
        ed = r.get("shadow_epoch_divergences", 0)
        dhits, ddivs = hits - eh, divs - ed
        is_shadow = d.get("modeName") == "shadow"
        if (is_shadow and ddivs == 0 and dhits >= min_hits and not r.get("weak_proof")
                and r.get("conf") != "CONF_BATTLETESTED"):
            tag_result = _set_battletested(addr_hex, program=program)
            if tag_result.get("status") == "success" or "already_present" in str(tag_result):
                r["conf"] = "CONF_BATTLETESTED"
                r["battletested_date"] = time.strftime("%Y-%m-%d")
                if eh or ed:
                    r["battletested_windowed"] = f"{dhits} clean hits since epoch (post-fix)"
                promoted.append({"name": d["name"], "hits": dhits})

    _save_registry(rows)
    return {"ok": True, "promoted": promoted, "dispatchers_seen": len(disp.get("dispatchers", []))}


def set_shadow_epoch(name: str, *, program: str = "D2Common.dll") -> dict:
    """Record the CURRENT live (hits, divergences) as this function's epoch baseline
    in the registry, so poll_and_promote judges only NEW calls. Call right after a
    hot-reloaded reimpl fix -- the pre-fix cumulative divergences are poisoned; the
    epoch draws a clean line so a correct fix promotes without a game restart."""
    try:
        disp = _http_get_json(ORACLE_URL, "/dispatchers")
    except OSError as e:
        return {"ok": False, "error": f"D2Debugger unreachable: {e}"}
    cur = None
    for d in disp.get("dispatchers", []):
        if d["name"] == name:
            cur = d
            break
    if cur is None:
        return {"ok": False, "error": f"{name} is not a live dispatcher"}
    rows = _load_registry()
    hit = False
    for r in rows:
        if r.get("name") == name:
            r["shadow_epoch_hits"] = cur.get("hits", 0)
            r["shadow_epoch_divergences"] = cur.get("divergences", 0)
            r["shadow_epoch_date"] = time.strftime("%Y-%m-%d")
            hit = True
    if not hit:
        return {"ok": False, "error": f"{name} not in registry"}
    _save_registry(rows)
    return {"ok": True, "name": name, "epoch_hits": cur.get("hits", 0),
            "epoch_divergences": cur.get("divergences", 0)}


def loop(interval: int = 60, *, stop_flag=None) -> None:
    """Continuous polling loop. `stop_flag` (optional) is anything with
    .is_set() -- lets a caller (e.g. fun-doc's WorkerManager) interrupt it the
    same way the existing functions-mode worker loop does."""
    while True:
        if stop_flag is not None and stop_flag.is_set():
            return
        result = poll_and_promote()
        if result.get("promoted"):
            print(f"[battletest_promoter] promoted: {result['promoted']}")
        elif not result.get("ok"):
            print(f"[battletest_promoter] {result.get('error')}")
        for _ in range(interval):
            if stop_flag is not None and stop_flag.is_set():
                return
            time.sleep(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="poll continuously instead of once")
    ap.add_argument("--interval", type=int, default=60, help="seconds between polls in --loop mode")
    ap.add_argument("--min-hits", type=int, default=BATTLE_MIN_HITS)
    ap.add_argument("--set-epoch", metavar="NAME",
                    help="record NAME's current shadow counters as its epoch baseline "
                         "(after a hot-reloaded fix -- promote on NEW clean calls, no restart)")
    args = ap.parse_args()
    if args.set_epoch:
        print(json.dumps(set_shadow_epoch(args.set_epoch), indent=2))
    elif args.loop:
        loop(args.interval)
    else:
        print(json.dumps(poll_and_promote(min_hits=args.min_hits), indent=2))
