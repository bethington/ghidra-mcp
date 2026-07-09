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

    # 4) port pipeline candidates (Stage 2/3 -- fun-doc's own port_status
    # tracking, distinct from the committed-@PD2S12-marker coverage above)
    r = client.get("/api/conformance/pipeline")
    pipe = r.get_json() or {}
    cands = pipe.get("candidates") or []
    print("[pipeline]   status=%s candidates=%d" % (r.status_code, len(cands)))
    if r.status_code != 200:
        print("  FAIL: /api/conformance/pipeline should always return 200")
        ok = False
    proven = [c for c in cands if c.get("port_status") == "proven_pending_review"]
    if proven:
        c = proven[0]
        print("  proven_pending_review: %s attempts=%s result=%s"
              % (c.get("name"), c.get("port_attempts"), c.get("port_last_result")))
        if not c.get("port_draft_path"):
            print("  FAIL: proven_pending_review candidate missing port_draft_path")
            ok = False
        else:
            # 5) draft content viewer for that candidate
            r2 = client.get("/api/conformance/draft_content",
                             query_string={"path": c["port_draft_path"]})
            draft = r2.get_json() or {}
            print("[draft]      status=%s content_len=%d"
                  % (r2.status_code, len(draft.get("content") or "")))
            if r2.status_code != 200 or "namespace D2Lib" not in (draft.get("content") or ""):
                print("  FAIL: expected the staged header's real content")
                ok = False

            # 6) draft content viewer rejects a path outside the staging dir
            r3 = client.get("/api/conformance/draft_content",
                             query_string={"path": r"C:\Windows\win.ini"})
            print("[draft-esc]  status=%s (expect 403)" % r3.status_code)
            if r3.status_code != 403:
                print("  FAIL: path outside _generated_candidates/ must be rejected")
                ok = False
    else:
        print("  (no proven_pending_review candidate staged right now -- run the PORT worker "
              "or process_port_candidate() manually to exercise checks 5-6)")

    print("\nSELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
