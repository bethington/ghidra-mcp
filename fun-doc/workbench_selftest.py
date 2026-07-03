"""
Headless self-test for the conformance workbench dashboard routes.

Exercises /api/conformance/* through a Flask TEST CLIENT -- no browser, no live
server -- so the side-by-side panel's data contract can be verified as it's
built, and MiniMax output can be spot-checked in CI-style runs.

    python workbench_selftest.py

Exit code 0 = all checks pass. The assembly/pseudocode panes need the Ghidra
plugin (127.0.0.1:8089); if it's down those panes carry a "<ghidra fetch
failed>" marker but the route still returns 200 and the OpenD2 pane is populated
from the committed source, so the harness still validates the contract.
"""
import os
import sys


def main():
    os.environ.setdefault("FUNDOC_DASHBOARD", "false")
    os.environ.setdefault("FUNDOC_OPEND2_REPO", r"C:\Users\benam\source\cpp\OpenD2")
    from web import create_app

    state_file = os.path.join(os.path.dirname(__file__), "state.json")
    app, _socketio = create_app(state_file)
    client = app.test_client()
    ok = True

    # 1) coverage endpoint
    r = client.get("/api/conformance/coverage")
    cov = r.get_json() or {}
    d2c = (cov.get("by_program") or {}).get("D2Common.dll", {})
    print("[coverage]   status=%s total_ported=%s  D2Common ported=%s proven=%s"
          % (r.status_code, cov.get("total_ported"), d2c.get("ported"), d2c.get("proven")))
    if r.status_code != 200 or (d2c.get("proven") or 0) < 3:
        print("  FAIL: expected >=3 PROVEN functions in D2Common.dll")
        ok = False

    # 2) side-by-side for a known LINKED function (RNG advance)
    r = client.get("/api/conformance/sidebyside",
                   query_string={"program": "D2Common.dll", "address": "6fd51100"})
    sbs = r.get_json() or {}
    o = sbs.get("opend2") or {}
    print("[sidebyside] status=%s implemented=%s opend2=%s"
          % (r.status_code, sbs.get("implemented"), o.get("symbol")))
    if r.status_code != 200 or not sbs.get("implemented") or not o.get("code"):
        print("  FAIL: expected linked OpenD2 code for 6fd51100")
        ok = False
    else:
        print("  OpenD2 %s:%s [%s]  src=%d chars | asm=%d chars | pseudo=%d chars"
              % (o.get("file"), o.get("line"), o.get("state"), len(o.get("code") or ""),
                 len(sbs.get("assembly") or ""), len(sbs.get("pseudocode") or "")))

    # 3) an UNLINKED (tagged but not-yet-ported) function still returns cleanly
    r = client.get("/api/conformance/sidebyside",
                   query_string={"program": "D2Game.dll", "address": "6fc32380"})
    sbs2 = r.get_json() or {}
    print("[sidebyside] unlinked drop fn: status=%s implemented=%s (expect False)"
          % (r.status_code, sbs2.get("implemented")))
    if r.status_code != 200 or sbs2.get("implemented"):
        print("  FAIL: unlinked function should report implemented=False without erroring")
        ok = False

    print("\nSELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
