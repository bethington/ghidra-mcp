"""
Tests for the global-variable completeness assessment (the data-address analog
of the function completeness scorer).

Covers the Python side of the feature — the Java /analyze_global_completeness
scorer is verified live post-deploy:

  * _sync_global_band writes/clears COMPLETE_<band> in the `Complete` property
    map (auto-creating the map on first use).
  * run_assess_globals_pass scores each candidate via /analyze_global_completeness,
    bands it, and stamps DOC_DRAFT when EFFECTIVE score >= the Target
    (good_enough_score) — sticky/add-only, defaulting the threshold to the Target.
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
_SEGMENTS = (
    "Headers: 10000000 - 100003ff\n"
    ".text: 10001000 - 100ebfff\n"
    ".rdata: 100ec000 - 1011bdff\n"
    ".data: 1011c000 - 101254eb\n"
    ".reloc: 10128000 - 101371ff\n"
    "tdb:\n"                          # rangeless line — must be ignored
)


def test_image_range_from_segments(monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", lambda path, params=None, timeout=None: _SEGMENTS)
    lo, hi = fd._image_range("/p")
    assert lo == 0x10000000
    assert hi == 0x101371ff + 1          # max end, exclusive


def test_image_range_excludes_os_overlay(monkeypatch):
    # A TIB/PEB overlay block far above the image must not stretch the window.
    segs = _SEGMENTS + "tib: ffdf0000 - ffdfffff\n"
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
# run_assess_globals_pass — score -> band -> DOC_DRAFT
# --------------------------------------------------------------------------- #
_LIST_GLOBALS = "\n".join([
    "g_dwPlayerCount @ 6fbc9a50 [data] (int) xrefs=10",     # scores 100 -> DOC_DRAFT
    "g_pFooTable @ 6fbc9a54 [data] (FooTable *) xrefs=3",   # scores 85  -> band only
    "DAT_6fbc9a58 @ 6fbc9a58 [data] (undefined4) xrefs=1",  # bare -> short-circuit, no HTTP
])

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

    def get(self, path, params=None, timeout=60):
        params = params or {}
        if path == "/list_globals":
            return _LIST_GLOBALS
        if path == "/list_properties":
            return {"entries": []}          # no pre-existing Doc rungs
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

    def doc_rung_addrs(self):
        return [d["address"] for p, d in self.posts
                if p == "/set_property" and d.get("map") == "Doc" and d.get("value") == "DOC_DRAFT"]

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


def test_stamps_draft_at_or_above_target(harness):
    rc = fd.run_assess_globals_pass("/p")
    assert rc == 0
    # only the 100-scorer crosses the 90 Target -> DOC_DRAFT
    assert harness.doc_rung_addrs() == ["0x6fbc9a50"]


def test_bands_written_by_effective_band(harness):
    fd.run_assess_globals_pass("/p")
    bw = harness.band_writes()
    assert bw.get("0x6fbc9a50") == "COMPLETE_100"
    assert bw.get("0x6fbc9a54") == "COMPLETE_80"     # banded even though below Target


def test_below_target_not_drafted(harness):
    fd.run_assess_globals_pass("/p")
    assert "0x6fbc9a54" not in harness.doc_rung_addrs()   # 85 < 90


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


def test_explicit_threshold_overrides_target(harness):
    # With a Target of 80, the 85-scorer also drafts.
    fd.run_assess_globals_pass("/p", draft_score=80)
    assert set(harness.doc_rung_addrs()) == {"0x6fbc9a50", "0x6fbc9a54"}


def test_scorer_unavailable_is_survivable(monkeypatch):
    h = _Harness(scorer_down=True)
    monkeypatch.setattr(fd, "ghidra_get", h.get)
    monkeypatch.setattr(fd, "ghidra_post", h.post)
    monkeypatch.setattr(fd, "_good_enough_for_draft", lambda: 90)
    rc = fd.run_assess_globals_pass("/p")
    assert rc == 0                          # never raises
    assert len(h.doc_rung_addrs()) == 0     # nothing stamped when scorer down


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

    # 5 in-scope globals total (3 banded, 2 below/unscored)
    monkeypatch.setattr(cd, "_get", fake_get)
    monkeypatch.setattr(cd, "_global_rows", lambda program: [{"addr": f"0x{i}"} for i in range(5)])

    out = cd.glob_bands(program="/p")
    assert out["in_scope"] == 5
    assert out["tagged"] == 3
    assert out["untagged"] == 2
    assert out["bands"]["COMPLETE_100"] == 1
    assert out["bands"]["COMPLETE_90"] == 1
    assert out["bands"]["COMPLETE_80"] == 1
    assert out["bands"]["COMPLETE_95"] == 0
