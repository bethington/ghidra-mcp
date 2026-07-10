"""verify_shadow_fix.py -- first-class hot-reload shadow-delta verification.

The fastest correct way to verify a re-drafted reimpl (2026-07-08): rebuild ONLY
the provider DLL, hot-reload it, flip the dispatcher to shadow, and watch the
divergence DELTA on REAL game calls. Seconds, no restart, real input distribution --
strictly better than the town-capture oracle that produced the original false
positive. This automates the loop I ran by hand:

    1. snapshot the dispatcher's baseline (hits, divergences)
    2. (optional) POST /reimpl/reload  -- bind the freshly rebuilt provider
    3. set the dispatcher to shadow mode
    4. poll until N NEW clean hits accrue  -> VERIFIED
       or any NEW divergence appears        -> STILL DIVERGING
       or the hit budget stalls             -> INSUFFICIENT (needs gameplay)
    5. on VERIFIED: set the promotion EPOCH (battletest_promoter) so the fixed
       function auto-promotes to CONF_BATTLETESTED on new clean calls -- no restart
       needed to clear the poisoned pre-fix cumulative divergences.

The verdict math is pure + unit-tested (verdict()); the live flow needs the game
on :8790.

    python verify_shadow_fix.py STAT_GetActiveSkillFieldC --reload --target 2000
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import time
import urllib.parse

ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790")


def _get(path: str, timeout: int = 6) -> dict:
    u = urllib.parse.urlparse(ORACLE_URL)
    c = http.client.HTTPConnection(u.hostname, u.port or 8790, timeout=timeout)
    try:
        c.request("GET", path)
        return json.loads(c.getresponse().read().decode("utf-8", "replace"))
    finally:
        c.close()


def _post(path: str, body: dict | None = None, timeout: int = 20) -> dict:
    u = urllib.parse.urlparse(ORACLE_URL)
    c = http.client.HTTPConnection(u.hostname, u.port or 8790, timeout=timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        c.request("POST", path, body=payload,
                  headers={"Content-Type": "application/json"} if payload else {})
        return json.loads(c.getresponse().read().decode("utf-8", "replace"))
    finally:
        c.close()


def _find(name: str) -> dict | None:
    for d in _get("/dispatchers").get("dispatchers", []):
        if d["name"] == name:
            return d
    return None


def verdict(base: dict, cur: dict, target_hits: int) -> dict:
    """PURE decision from a baseline and current counter snapshot. Returns
    {status, dhits, ddivs} with status in verified | diverging | insufficient."""
    dhits = cur["hits"] - base["hits"]
    ddivs = cur["divergences"] - base["divergences"]
    if ddivs > 0:
        status = "diverging"          # a NEW divergence -> the fix is still wrong
    elif dhits >= target_hits:
        status = "verified"           # enough NEW calls, all matched
    else:
        status = "insufficient"       # clean so far but not enough calls yet
    return {"status": status, "dhits": dhits, "ddivs": ddivs}


def run(name: str, *, target_hits: int = 1000, reload: bool = True,
        poll_secs: int = 3, budget_secs: int = 180, set_epoch: bool = True) -> dict:
    d = _find(name)
    if d is None:
        return {"ok": False, "error": f"{name} is not a live dispatcher"}
    idx = d["index"]
    base = {"hits": d["hits"], "divergences": d["divergences"]}
    print(f"[baseline] {name} idx={idx} hits={base['hits']} divergences={base['divergences']}")

    if reload:
        rl = _post("/reimpl/reload")
        print(f"[reload] {rl.get('provider', rl.get('error'))}")

    sm = _post(f"/dispatcher/{idx}/mode", {"mode": "shadow"})
    if not sm.get("ok"):
        return {"ok": False, "error": f"set shadow failed: {sm.get('error')}"}
    print(f"[shadow] {name} -> shadow; watching for {target_hits} clean new hits "
          f"(budget {budget_secs}s)")

    waited = 0
    last = base
    while waited < budget_secs:
        time.sleep(poll_secs)
        waited += poll_secs
        cur_d = _find(name)
        if cur_d is None:
            return {"ok": False, "error": "dispatcher vanished (bridge died?)"}
        cur = {"hits": cur_d["hits"], "divergences": cur_d["divergences"]}
        v = verdict(base, cur, target_hits)
        print(f"  t={waited:>3}s  +{v['dhits']} hits  +{v['ddivs']} div  -> {v['status']}")
        if v["status"] == "diverging":
            return {"ok": True, "verified": False, "status": "diverging",
                    "new_divergences": v["ddivs"], "new_hits": v["dhits"],
                    "note": "the re-drafted reimpl STILL diverges on real calls -- re-check the disasm"}
        if v["status"] == "verified":
            out = {"ok": True, "verified": True, "status": "verified",
                   "new_hits": v["dhits"], "new_divergences": 0}
            if set_epoch:
                try:
                    import battletest_promoter as bp
                    ep = bp.set_shadow_epoch(name)
                    out["epoch"] = ep
                    print(f"[epoch] set promotion baseline -> it auto-promotes on new clean calls: {ep}")
                except Exception as e:  # noqa: BLE001
                    out["epoch_error"] = str(e)
            return out
        last = cur

    return {"ok": True, "verified": False, "status": "insufficient",
            "new_hits": last["hits"] - base["hits"], "new_divergences": last["divergences"] - base["divergences"],
            "note": f"only {last['hits'] - base['hits']} new hits in {budget_secs}s and 0 divergences -- "
                    f"clean so far but under target; play/move to exercise it, or lower --target"}


def _selftest() -> int:
    b = {"hits": 100, "divergences": 50}
    assert verdict(b, {"hits": 2000, "divergences": 50}, 1000)["status"] == "verified"
    assert verdict(b, {"hits": 2000, "divergences": 51}, 1000)["status"] == "diverging"
    assert verdict(b, {"hits": 300, "divergences": 50}, 1000)["status"] == "insufficient"
    # a diverging verdict wins even past the hit target
    assert verdict(b, {"hits": 9999, "divergences": 60}, 1000)["status"] == "diverging"
    print("[ok] verify_shadow_fix verdict self-test passed")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="?", help="dispatcher/function name to verify")
    ap.add_argument("--target", type=int, default=1000, help="clean new hits required to VERIFY")
    ap.add_argument("--no-reload", action="store_true", help="skip provider hot-reload")
    ap.add_argument("--budget", type=int, default=180, help="seconds to watch before INSUFFICIENT")
    ap.add_argument("--no-epoch", action="store_true", help="don't set the promotion epoch on verify")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.name:
        raise SystemExit(_selftest())
    print(json.dumps(run(args.name, target_hits=args.target, reload=not args.no_reload,
                         budget_secs=args.budget, set_epoch=not args.no_epoch), indent=2))
