"""
Tests for the global-variable completeness assessment (the data-address analog
of the function completeness scorer).

Covers the Python side of the feature — the Java /analyze_global_completeness
scorer is verified live post-deploy:

  * _sync_global_band writes/clears COMPLETE_<band> in the `Complete` property
    map (auto-creating the map on first use).
  * run_assess_globals_pass re-scores EVERY in-scope global via
    /analyze_global_completeness and rewrites its band. It no longer stamps a DOC
    rung and no longer skips already-tagged globals: the rung was a watermark that
    froze 96% of a binary's globals out of re-assessment, and the scorer is cheap
    enough (~15ms/address) that a cache bought nothing worth its staleness.
  * The cheap short-circuit skips the HTTP score for globals that can't band
    (no meaningful name AND no real type).
  * conformance_dashboard.glob_bands rolls the `Complete` map into band counts.

Fast, pure Python, no network, no Ghidra.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import fun_doc as fd  # noqa: E402


# --------------------------------------------------------------------------- #
# _image_range — dynamic per-program image window (any base address)
# --------------------------------------------------------------------------- #
# 7.0.0: list_segments returns structured records inside the standard envelope.
def _segments(*blocks):
    return {"segments": list(blocks), "count": len(blocks),
            "offset": 0, "total": len(blocks)}


_SEGMENTS = _segments(
    {"name": "Headers", "start": "10000000", "end": "100003ff"},
    {"name": ".text", "start": "10001000", "end": "100ebfff"},
    {"name": ".rdata", "start": "100ec000", "end": "1011bdff"},
    {"name": ".data", "start": "1011c000", "end": "101254eb"},
    {"name": ".reloc", "start": "10128000", "end": "101371ff"},
    # A malformed record (no start/end) must be skipped, not crash the parse --
    # the pre-7.0.0 text form had the same case as a rangeless "tdb:" line.
    {"name": "tdb"},
)


def test_image_range_from_segments(monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", lambda path, params=None, timeout=None: _SEGMENTS)
    lo, hi = fd._image_range("/p")
    assert lo == 0x10000000
    assert hi == 0x101371ff + 1          # max end, exclusive


def test_image_range_excludes_os_overlay(monkeypatch):
    # A TIB/PEB overlay block far above the image must not stretch the window.
    segs = _segments(*_SEGMENTS["segments"],
                     {"name": "tib", "start": "ffdf0000", "end": "ffdfffff"})
    monkeypatch.setattr(fd, "ghidra_get", lambda path, params=None, timeout=None: segs)
    lo, hi = fd._image_range("/p")
    assert lo == 0x10000000
    assert hi == 0x101371ff + 1          # overlay dropped, not 0xffe00000


def test_image_range_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", lambda path, params=None, timeout=None: "")
    assert fd._image_range("/p") is None   # caller falls back to legacy window


# --------------------------------------------------------------------------- #
# _sync_global_band — Complete property-map writer
# --------------------------------------------------------------------------- #
class _PostRec:
    def __init__(self, set_fails_first=False):
        self.calls = []           # (path, data)
        self.set_fails_first = set_fails_first
        self._set_count = 0

    def __call__(self, path, data=None, params=None, timeout=60):
        self.calls.append((path, data or {}))
        if path == "/set_property":
            self._set_count += 1
            if self.set_fails_first and self._set_count == 1:
                return {"success": False, "error": "No property map named 'Complete'"}
        return {"success": True}

    def paths(self):
        return [p for p, _ in self.calls]

    def sets_to(self, map_name):
        return [d for p, d in self.calls if p == "/set_property" and d.get("map") == map_name]


def test_sync_global_band_writes_complete_map(monkeypatch):
    rec = _PostRec()
    monkeypatch.setattr(fd, "ghidra_post", rec)
    fd._sync_global_band("/p", "0x6fbc9a50", "COMPLETE_90")
    sets = rec.sets_to("Complete")
    assert len(sets) == 1
    assert sets[0]["value"] == "COMPLETE_90"
    assert sets[0]["address"] == "0x6fbc9a50"


def test_sync_global_band_clears_when_none(monkeypatch):
    rec = _PostRec()
    monkeypatch.setattr(fd, "ghidra_post", rec)
    fd._sync_global_band("/p", "0x6fbc9a50", None)
    assert rec.paths() == ["/remove_property"]
    assert rec.calls[0][1]["map"] == "Complete"


def test_sync_global_band_autocreates_map(monkeypatch):
    rec = _PostRec(set_fails_first=True)
    monkeypatch.setattr(fd, "ghidra_post", rec)
    fd._sync_global_band("/p", "0x6fbc9a50", "COMPLETE_100")
    # first set fails -> create_property_map -> retry set
    assert rec.paths() == ["/set_property", "/create_property_map", "/set_property"]


# --------------------------------------------------------------------------- #
# run_assess_globals_pass — score -> band (no rung, no cache)
# --------------------------------------------------------------------------- #
# 7.0.0 response contract: list-shaped tools return a named plural key plus
# count/total. list_globals entries are still preformatted lines.
_GLOBAL_LINES = [
    "g_dwPlayerCount @ 6fbc9a50 [data] (int) xrefs=10",     # scores 100 -> COMPLETE_100
    "g_pFooTable @ 6fbc9a54 [data] (FooTable *) xrefs=3",   # scores 85  -> band only
    "DAT_6fbc9a58 @ 6fbc9a58 [data] (undefined4) xrefs=1",  # bare -> short-circuit, no HTTP
]
_LIST_GLOBALS = {
    "globals": _GLOBAL_LINES,
    "count": len(_GLOBAL_LINES),
    "offset": 0,
    "total": len(_GLOBAL_LINES),
}

_SCORES = {
    "0x6fbc9a50": {"applicable": True, "effective_score": 100.0,
                   "band": "COMPLETE_100", "missing": []},
    "0x6fbc9a54": {"applicable": True, "effective_score": 85.0,
                   "band": "COMPLETE_80", "missing": ["comment"]},
}


class _Harness:
    """Records posts and serves fake ghidra_get responses for the assess pass."""
    def __init__(self, scores=None, scorer_down=False):
        self.posts = []           # (path, data)
        self.post_params = []      # query params per post (parallel to self.posts)
        self.scored_addrs = []     # addresses the endpoint was called for
        self.scores = scores if scores is not None else _SCORES
        self.scorer_down = scorer_down
        self.doc_entries = []      # pre-existing `Doc` map rows, if any

    def get(self, path, params=None, timeout=60):
        params = params or {}
        if path == "/list_globals":
            return _LIST_GLOBALS
        if path == "/list_properties":
            return {"entries": list(self.doc_entries)}
        if path == "/analyze_global_completeness":
            self.scored_addrs.append(params["address"])
            if self.scorer_down:
                return {"error": "unknown endpoint"}
            return self.scores.get(params["address"], {"applicable": True,
                                                        "effective_score": 0.0, "band": None,
                                                        "missing": ["name", "type"]})
        return {}

    def post(self, path, data=None, params=None, timeout=60):
        self.posts.append((path, data or {}))
        self.post_params.append(params or {})
        return {"success": True}

    def doc_map_writes(self):
        """Any write to the `Doc` map. The assess pass must make NONE -- `Doc` is
        the review bit now, and only a review pass or a human may set it."""
        return [d for p, d in self.posts
                if p in ("/set_property", "/remove_property") and d.get("map") == "Doc"]

    def band_writes(self):
        return {d["address"]: d["value"] for p, d in self.posts
                if p == "/set_property" and d.get("map") == "Complete"}

    def band_clears(self):
        return [d["address"] for p, d in self.posts if p == "/remove_property"]


@pytest.fixture
def harness(monkeypatch):
    h = _Harness()
    monkeypatch.setattr(fd, "ghidra_get", h.get)
    monkeypatch.setattr(fd, "ghidra_post", h.post)
    monkeypatch.setattr(fd, "_good_enough_for_draft", lambda: 90)
    return h


def test_assess_never_touches_the_doc_map(harness):
    """The rung is retired. Assess measures completeness; it does not vouch."""
    rc = fd.run_assess_globals_pass("/p")
    assert rc == 0
    assert harness.doc_map_writes() == []


def test_bands_written_by_effective_band(harness):
    fd.run_assess_globals_pass("/p")
    bw = harness.band_writes()
    assert bw.get("0x6fbc9a50") == "COMPLETE_100"
    assert bw.get("0x6fbc9a54") == "COMPLETE_80"     # banded even though below Target


def test_rescores_globals_that_already_carry_a_doc_entry(monkeypatch):
    """No cache. A pre-existing `Doc` entry must not exclude a global from scoring.

    Regression guard for the exact defect this replaced: the pass used to skip
    anything already tagged, which left 2,142 of D2Common's 2,231 globals reporting
    a stale band forever -- including every global the worker had just improved.
    """
    h = _Harness()
    monkeypatch.setattr(fd, "ghidra_get", h.get)
    monkeypatch.setattr(fd, "ghidra_post", h.post)
    monkeypatch.setattr(fd, "_good_enough_for_draft", lambda: 90)
    # every in-scope global already carries a Doc entry
    h.doc_entries = [{"address": a, "value": "REVIEWED"}
                     for a in ("0x6fbc9a50", "0x6fbc9a54", "0x6fbc9a58")]
    fd.run_assess_globals_pass("/p")
    assert set(h.scored_addrs) == {"0x6fbc9a50", "0x6fbc9a54"}   # 9a58 short-circuits
    assert h.band_writes().get("0x6fbc9a50") == "COMPLETE_100"


def test_writes_target_program_via_query_param(harness):
    # Regression guard: these endpoints resolve `program` from the QUERY, so a
    # body-only program silently hits the active program (this exact bug leaked
    # D2Client bands into BenchmarkDebug during live verification).
    fd.run_assess_globals_pass("/p")
    guarded = {"/set_property", "/remove_property", "/create_property_map", "/save_program"}
    checked = 0
    for (path, _data), params in zip(harness.posts, harness.post_params):
        if path in guarded:
            assert params.get("program") == "/p", f"{path} must carry program in query"
            checked += 1
    assert checked > 0            # the pass really did write something


def test_short_circuits_bare_global(harness):
    fd.run_assess_globals_pass("/p")
    # DAT_ (no name, no real type) is never sent to the scorer...
    assert "0x6fbc9a58" not in harness.scored_addrs
    # ...and its band is cleared
    assert "0x6fbc9a58" in harness.band_clears()


def test_defaults_threshold_to_target(monkeypatch):
    h = _Harness()
    monkeypatch.setattr(fd, "ghidra_get", h.get)
    monkeypatch.setattr(fd, "ghidra_post", h.post)
    calls = []
    monkeypatch.setattr(fd, "_good_enough_for_draft", lambda: calls.append(1) or 90)
    fd.run_assess_globals_pass("/p")               # draft_score defaults to None
    assert calls == [1]                             # resolved the live Target


def test_threshold_is_reporting_only_never_a_write_gate(harness):
    """`draft_score` still tunes the summary line, but gates nothing on disk."""
    fd.run_assess_globals_pass("/p", draft_score=80)
    assert harness.doc_map_writes() == []
    # bands are written on their own merits, independent of the threshold
    assert harness.band_writes() == {"0x6fbc9a50": "COMPLETE_100",
                                     "0x6fbc9a54": "COMPLETE_80"}


def test_scorer_unavailable_is_survivable(monkeypatch):
    h = _Harness(scorer_down=True)
    monkeypatch.setattr(fd, "ghidra_get", h.get)
    monkeypatch.setattr(fd, "ghidra_post", h.post)
    monkeypatch.setattr(fd, "_good_enough_for_draft", lambda: 90)
    rc = fd.run_assess_globals_pass("/p")
    assert rc == 0                          # never raises
    assert h.doc_map_writes() == []         # nothing vouched for when scorer down


# --------------------------------------------------------------------------- #
# conformance_dashboard.glob_bands — Complete-map rollup
# --------------------------------------------------------------------------- #
def test_glob_bands_rollup(monkeypatch):
    import conformance_dashboard as cd

    complete_entries = {"entries": [
        {"address": "6fbc9a50", "value": "COMPLETE_100"},
        {"address": "6fbc9a54", "value": "COMPLETE_80"},
        {"address": "6fbc9a60", "value": "COMPLETE_90"},
    ]}

    def fake_get(path, **kw):
        if path == "/list_properties" and kw.get("map") == "Complete":
            return complete_entries
        return {}

    # 5 in-scope globals total (3 banded, 2 unscored). Addresses must MATCH the
    # map: `tagged` counts bands on real in-scope rows, not raw map size, so a
    # stale entry for a departed address no longer inflates the count.
    monkeypatch.setattr(cd, "_get", fake_get)
    monkeypatch.setattr(cd, "_image_range", lambda p: (0x6FBC9000, 0x6FBCA000))
    monkeypatch.setattr(cd, "_global_rows", lambda program: [
        {"addr": a} for a in ("0x6fbc9a50", "0x6fbc9a54", "0x6fbc9a60",
                              "0x6fbc9a64", "0x6fbc9a68")])

    out = cd.glob_bands(program="/p")
    assert out["in_scope"] == 5
    assert out["tagged"] == 3
    assert out["untagged"] == 2
    assert out["bands"]["COMPLETE_100"] == 1
    assert out["bands"]["COMPLETE_90"] == 1
    assert out["bands"]["COMPLETE_80"] == 1
    assert out["bands"]["COMPLETE_95"] == 0


# --------------------------------------------------------------------------- #
# The REVIEWED trust bit — _set_global_reviewed / _resolve_globals_audit_provider
# --------------------------------------------------------------------------- #
def test_set_global_reviewed_writes_doc_map(monkeypatch):
    rec = _PostRec()
    monkeypatch.setattr(fd, "ghidra_post", rec)
    fd._set_global_reviewed("/p", "0x6fbc9a50", True)
    sets = rec.sets_to("Doc")
    assert len(sets) == 1
    assert sets[0]["value"] == "REVIEWED"


def test_set_global_reviewed_clears(monkeypatch):
    rec = _PostRec()
    monkeypatch.setattr(fd, "ghidra_post", rec)
    fd._set_global_reviewed("/p", "0x6fbc9a50", False)
    assert rec.paths() == ["/remove_property"]
    assert rec.calls[0][1]["map"] == "Doc"


def test_set_global_reviewed_autocreates_map(monkeypatch):
    rec = _PostRec(set_fails_first=True)
    monkeypatch.setattr(fd, "ghidra_post", rec)
    fd._set_global_reviewed("/p", "0x6fbc9a50", True)
    assert rec.paths() == ["/set_property", "/create_property_map", "/set_property"]


def test_review_provider_off_by_default():
    assert fd.DEFAULT_QUEUE_CONFIG["globals_audit_provider"] is None
    assert fd._resolve_globals_audit_provider("minimax", {"globals_audit_provider": None}) is None
    assert fd._resolve_globals_audit_provider("minimax", {"globals_audit_provider": "off"}) is None


def test_review_provider_refuses_self_review(capsys):
    """A model reviewing its own output is not independent evidence. The pairing
    is refused LOUDLY -- silently allowing it would keep the badge populated
    while making it mean nothing, which is the failure the rung ladder had."""
    got = fd._resolve_globals_audit_provider("claude", {"globals_audit_provider": "claude"})
    assert got is None
    assert "not independent evidence" in capsys.readouterr().out


def test_review_provider_accepts_a_different_provider():
    assert fd._resolve_globals_audit_provider(
        "minimax", {"globals_audit_provider": "claude"}) == "claude"


class _ReviewEnv:
    """Minimal stand-in for the review path's collaborators."""

    def __init__(self, after_issues, sev=None, meta=None):
        self.after_issues = after_issues
        self.sev = sev
        self.meta = meta or {}
        self.posts = []
        self.audits = 0

    def audit(self, prog, addr):
        self.audits += 1
        if self.audits == 1:                      # before
            return {"name": "g_foo", "issues": ["untyped"],
                    "severity_summary": {"hard": 1, "medium": 0, "soft": 0}}
        out = {"name": "g_foo", "issues": list(self.after_issues)}
        if self.sev is not None:
            out["severity_summary"] = self.sev
        return out

    def post(self, path, data=None, params=None, timeout=60):
        self.posts.append((path, data or {}))
        return {"success": True}

    def reviewed_writes(self):
        return [d for p, d in self.posts
                if p == "/set_property" and d.get("value") == "REVIEWED"]


def _wire_review(monkeypatch, env):
    monkeypatch.setattr(fd, "select_model", lambda *a, **k: "m1")
    monkeypatch.setattr(fd, "_audit_global_with_retry", env.audit)
    monkeypatch.setattr(fd, "_build_global_review_prompt", lambda *a, **k: "PROMPT")
    monkeypatch.setattr(fd, "_inject_tool_block", lambda p: p)
    monkeypatch.setattr(fd, "invoke_claude", lambda *a, **k: ("ok", env.meta))
    monkeypatch.setattr(fd, "bus_emit", lambda *a, **k: None)
    monkeypatch.setattr(fd, "ghidra_post", env.post)


def test_review_sets_bit_when_no_blocking_issues_remain(monkeypatch):
    env = _ReviewEnv(after_issues=[], sev={"hard": 0, "medium": 0, "soft": 0})
    _wire_review(monkeypatch, env)
    assert fd.review_global("/p", "0x6fbc9a50", "claude") == "reviewed"
    assert len(env.reviewed_writes()) == 1


def test_review_tolerates_soft_issues(monkeypatch):
    """Soft issues (cosmetics) are non-blocking everywhere else in the globals
    path; the review bar must agree or nothing ever gets reviewed."""
    env = _ReviewEnv(after_issues=["plate_line_too_long"],
                     sev={"hard": 0, "medium": 0, "soft": 1})
    _wire_review(monkeypatch, env)
    assert fd.review_global("/p", "0x6fbc9a50", "claude") == "reviewed"


def test_review_withholds_bit_when_blocking_issues_remain(monkeypatch):
    env = _ReviewEnv(after_issues=["untyped"], sev={"hard": 1, "medium": 0, "soft": 0})
    _wire_review(monkeypatch, env)
    assert fd.review_global("/p", "0x6fbc9a50", "claude") == "issues_remain"
    assert env.reviewed_writes() == []


def test_review_withholds_bit_on_provider_error(monkeypatch):
    """A review that never actually ran must not vouch for anything -- and must
    say so out loud rather than failing silently."""
    env = _ReviewEnv(after_issues=[], sev={"hard": 0, "medium": 0, "soft": 0},
                     meta={"provider_error": "timeout"})
    _wire_review(monkeypatch, env)
    assert fd.review_global("/p", "0x6fbc9a50", "claude") == "provider_error"
    assert env.reviewed_writes() == []


def test_review_is_a_no_op_without_a_provider():
    assert fd.review_global("/p", "0x6fbc9a50", None) == "skipped"


# --------------------------------------------------------------------------- #
# conformance_dashboard — image filtering + band-based inventory
# --------------------------------------------------------------------------- #
def test_prop_map_drops_foreign_addresses(monkeypatch):
    """Property maps hold entries that leaked from other programs (4,848 of
    19,996 project-wide). Every consumer must filter by image or it counts
    another binary's work as its own."""
    import conformance_dashboard as cd

    monkeypatch.setattr(cd, "_get", lambda path, **kw: {"entries": [
        {"address": "6fde9f10", "value": "REVIEWED"},     # in image
        {"address": "1010c1b0", "value": "REVIEWED"},     # foreign (leaked)
        {"address": "6fb89a54", "value": "REVIEWED"},     # foreign (leaked)
    ]})
    img = (0x6FD50000, 0x6FDF9000)
    assert set(cd._prop_map("/p", "Doc", {"REVIEWED"}, img)) == {"0x6fde9f10"}
    assert len(cd._prop_map("/p", "Doc", {"REVIEWED"})) == 3      # unfiltered


def test_globals_inventory_is_band_based(monkeypatch):
    import conformance_dashboard as cd

    rows = [
        {"addr": "0x6fde9f10", "name": "g_pSkillsTxt", "type": "SkillsTxt *",
         "typed": True, "xrefs": 9},
        {"addr": "0x6fde9f20", "name": "g_nCount", "type": "int",
         "typed": True, "xrefs": 3},
        {"addr": "0x6fde9f30", "name": "DAT_x", "type": "undefined",
         "typed": False, "xrefs": 1},
    ]

    def fake_get(path, **kw):
        if path == "/list_properties" and kw.get("map") == "Complete":
            return {"entries": [{"address": "6fde9f10", "value": "COMPLETE_100"},
                                {"address": "6fde9f20", "value": "COMPLETE_80"}]}
        if path == "/list_properties" and kw.get("map") == "Doc":
            return {"entries": [{"address": "6fde9f10", "value": "REVIEWED"}]}
        return {}

    monkeypatch.setattr(cd, "_get", fake_get)
    monkeypatch.setattr(cd, "_image_range", lambda p: (0x6FD50000, 0x6FDF9000))
    monkeypatch.setattr(cd, "_global_rows", lambda program: rows)

    out = cd.globals_inventory(program="/p")
    s = out["summary"]
    assert s["scope"] == 3
    assert s["bands"]["COMPLETE_100"] == 1 and s["bands"]["COMPLETE_80"] == 1
    assert s["unscored"] == 1
    assert s["reviewed"] == 1
    # no retired rung vocabulary survives in the payload
    assert "rungs" not in s and "typed_pct" not in s
    # worst-first: unscored, then COMPLETE_80, then COMPLETE_100
    assert [r["name"] for r in out["rows"]] == ["DAT_x", "g_nCount", "g_pSkillsTxt"]
    assert out["rows"][2]["reviewed"] is True


def test_set_global_reviewed_puts_program_in_the_query(monkeypatch):
    """Regression guard for the leak that produced 4,848 foreign entries:
    /set_property resolves `program` from the QUERY string, so a body-only
    program silently writes to whatever program is active."""
    import conformance_dashboard as cd

    seen = []
    monkeypatch.setattr(
        cd, "_post", lambda path, data=None: seen.append(path) or {"success": True})
    cd.set_global_reviewed("0x6fde9f10", True, program="/Mods/PD2-S12/D2Common.dll")
    assert all("?program=%2FMods%2FPD2-S12%2FD2Common.dll" in p for p in seen), seen


def test_global_rows_are_one_per_address(monkeypatch):
    """Ghidra allows many labels on one data address and /list_globals emits a line
    for each -- D2Client has 3,405 lines over 3,223 addresses, one address carrying
    seven. Both property maps are keyed by ADDRESS, so counting lines made the
    inventory report 3,398 scored while glob_bands reported 3,219 for the same
    binary. One row per address; extra labels ride along as aliases."""
    import conformance_dashboard as cd

    lines = [
        "g_nScreenShiftX @ 6fbcb9a0 [Label] (int) xrefs=40",
        "g_nPanelBaseX @ 6fbcb9a0 [Label] (int) xrefs=40",
        "g_nScreenCenterX @ 6fbcb9a0 [Label] (int) xrefs=40",
        "g_pRosterUnit @ 6fbcb980 [Label] (RosterUnit *) xrefs=9",
    ]
    monkeypatch.setattr(cd, "_get", lambda path, **kw:
                        {"globals": lines} if path == "/list_globals" else {})
    monkeypatch.setattr(cd, "_image_range", lambda p: (0x6FB00000, 0x6FC00000))
    monkeypatch.setattr(cd, "_scope_excluded_globals", lambda p: set())

    rows = cd._global_rows("/p")
    assert len(rows) == 2                                  # not 4
    first = next(r for r in rows if r["addr"] == "0x6fbcb9a0")
    assert first["name"] == "g_nScreenShiftX"               # first line wins
    assert first["aliases"] == ["g_nPanelBaseX", "g_nScreenCenterX"]


def test_glob_bands_and_inventory_agree(monkeypatch):
    """The two Globals views must report the same scope/scored/reviewed. They are
    the same numbers rendered twice; a disagreement is the exact failure mode the
    retired DOC ladder produced (96% documented vs 51% typed)."""
    import conformance_dashboard as cd

    lines = [
        "g_a @ 6fbcb9a0 [Label] (int) xrefs=4",
        "g_a_alias @ 6fbcb9a0 [Label] (int) xrefs=4",       # same address
        "g_b @ 6fbcb980 [Label] (Foo *) xrefs=9",
        "g_c @ 6fbcb984 [Label] (undefined) xrefs=1",
    ]

    def fake_get(path, **kw):
        if path == "/list_globals":
            return {"globals": lines}
        if path == "/list_properties" and kw.get("map") == "Complete":
            return {"entries": [{"address": "6fbcb9a0", "value": "COMPLETE_100"},
                                {"address": "6fbcb980", "value": "COMPLETE_80"},
                                # stale entry for an address no longer in scope
                                {"address": "6fbcb9f0", "value": "COMPLETE_100"}]}
        if path == "/list_properties" and kw.get("map") == "Doc":
            return {"entries": [{"address": "6fbcb9a0", "value": "REVIEWED"}]}
        return {}

    monkeypatch.setattr(cd, "_get", fake_get)
    monkeypatch.setattr(cd, "_image_range", lambda p: (0x6FB00000, 0x6FC00000))
    monkeypatch.setattr(cd, "_scope_excluded_globals", lambda p: set())

    gb = cd.glob_bands("/p")
    gi = cd.globals_inventory(program="/p")["summary"]
    assert gb["in_scope"] == gi["scope"] == 3          # 4 lines, 3 addresses
    assert gb["tagged"] == gi["scored"] == 2           # stale 9f0 entry excluded
    assert gb["untagged"] == gi["unscored"] == 1
    assert gb["reviewed"] == gi["reviewed"] == 1
    assert gb["bands"] == gi["bands"]
