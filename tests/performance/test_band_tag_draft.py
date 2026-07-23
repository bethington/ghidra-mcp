"""
Regression tests for the DOC_DRAFT auto-stamp folded into sync_band_tag.

Behavior under test (design locked 2026-07-22):
  * When a score write pushes a function to/over the completeness Target
    (good_enough_score), sync_band_tag stamps the DOC_DRAFT provenance rung.
  * The stamp is ADD-ONLY + STICKY:
      - fires only on the UPWARD Target crossing (old < target <= new, or a
        first-ever score at/above target);
      - never overwrites a higher rung (DOC_REVIEWED / DOC_VERIFIED);
      - is never re-added once present, and never removed when a later re-score
        drops the function below target (DOC_* is provenance, COMPLETE_* is the
        live score).
  * The stamp does NOT piggyback on COMPLETE band crossings: a Target that
    isn't a band boundary (e.g. 85) still fires even when the band is unchanged.
  * The pre-existing COMPLETE_<band> sync is unaffected, and the no-crossing
    hot path stays a pure no-op (zero Ghidra I/O).
  * run_assess_pass defaults its DOC_DRAFT threshold to the live Target.

Fast, pure Python, no network, no Ghidra.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import fun_doc  # noqa: E402


class _GhidraStub:
    """Serves a fixed tag set for /get_function_tags and records every post."""

    def __init__(self, existing_tags=()):
        self.existing = list(existing_tags)
        self.posts = []  # (path, payload)
        self.post_params = []  # query params per post (parallel to self.posts)

    def get(self, path, params=None, **kw):
        if path == "/get_function_tags":
            return {"tags": [{"name": t} for t in self.existing]}
        return {}

    def post(self, path, payload=None, params=None, **kw):
        self.posts.append((path, payload or {}))
        self.post_params.append(params or {})
        return {"success": True}

    def _tags_for(self, wanted_path):
        out = []
        for path, payload in self.posts:
            if path == wanted_path:
                out += [t for t in str(payload.get("tags", "")).split(",") if t]
        return out

    def added_tags(self):
        return self._tags_for("/add_function_tag")

    def removed_tags(self):
        return self._tags_for("/remove_function_tag")


@pytest.fixture(autouse=True)
def _reset_target_cache():
    """Keep the mtime memo from leaking between tests."""
    fun_doc._GOOD_ENOUGH_DRAFT_CACHE.update({"mtime": None, "value": None})
    yield
    fun_doc._GOOD_ENOUGH_DRAFT_CACHE.update({"mtime": None, "value": None})


@pytest.fixture
def ghidra(monkeypatch):
    stub = _GhidraStub()
    monkeypatch.setattr(fun_doc, "ghidra_get", stub.get)
    monkeypatch.setattr(fun_doc, "ghidra_post", stub.post)
    return stub


# --------------------------------------------------------------------------- #
# _crossed_good_enough — the upward-crossing predicate
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "old,new,ge,expected",
    [
        (None, 90, 90, True),     # first-ever score, exactly at target
        (None, 91, 90, True),     # first-ever score, above target
        (None, 89, 90, False),    # first-ever score, below target
        (80, 90, 90, True),       # upward crossing, lands on target
        (89, 91, 90, True),       # upward crossing through target
        (0, 90, 90, True),        # 0 is the common "unscored" sentinel
        (90, 95, 90, False),      # already at target -> sticky, no re-fire
        (95, 92, 90, False),      # stays above target
        (92, 40, 90, False),      # drops below target -> never fires
        (60, 85, 90, False),      # rises but not to target
        (None, "n/a", 90, False),  # unparseable new score
        ("junk", 90, 90, True),   # unparseable old, new meets -> treat as cross
    ],
)
def test_crossed_good_enough(old, new, ge, expected):
    assert fun_doc._crossed_good_enough(old, new, ge) is expected


# --------------------------------------------------------------------------- #
# sync_band_tag — DOC_DRAFT stamping
# --------------------------------------------------------------------------- #
def test_stamps_draft_on_target_crossing(ghidra):
    ghidra.existing = []  # no rung yet
    fun_doc.sync_band_tag("/p", "0x1000", 92, old_score=70, good_enough=90)
    assert "DOC_DRAFT" in ghidra.added_tags()
    assert "COMPLETE_90" in ghidra.added_tags()  # band crosses too


def test_tag_writes_target_program_via_query_param(ghidra):
    # Regression guard: add/remove_function_tag resolve `program` from the QUERY.
    # A body-only program silently targets the active program (the same leak
    # that hit the globals path). Every tag-write POST must carry program in query.
    ghidra.existing = ["COMPLETE_80"]
    fun_doc.sync_band_tag("/p", "0x1000", 96, old_score=70, good_enough=90)
    writes = {"/add_function_tag", "/remove_function_tag"}
    checked = 0
    for (path, _payload), params in zip(ghidra.posts, ghidra.post_params):
        if path in writes:
            assert params.get("program") == "/p", f"{path} must carry program in query"
            checked += 1
    assert checked > 0


def test_never_clobbers_higher_rung(ghidra):
    ghidra.existing = ["DOC_VERIFIED", "COMPLETE_90"]
    fun_doc.sync_band_tag("/p", "0x1000", 96, old_score=88, good_enough=90)
    assert "DOC_DRAFT" not in ghidra.added_tags()  # verified stays
    assert "COMPLETE_95" in ghidra.added_tags()    # band still advances


def test_idempotent_when_already_draft(ghidra):
    ghidra.existing = ["DOC_DRAFT", "COMPLETE_90"]
    fun_doc.sync_band_tag("/p", "0x1000", 92, old_score=70, good_enough=90)
    assert "DOC_DRAFT" not in ghidra.added_tags()  # already carries a rung


def test_sticky_no_refire_above_target(ghidra):
    ghidra.existing = ["DOC_DRAFT", "COMPLETE_90"]
    # 92 -> 94: same band, no target crossing -> pure no-op, no I/O at all
    fun_doc.sync_band_tag("/p", "0x1000", 94, old_score=92, good_enough=90)
    assert ghidra.posts == []


def test_no_stamp_below_target(ghidra):
    ghidra.existing = []
    # 60 -> 85: band crosses into COMPLETE_80, but target 90 not reached
    fun_doc.sync_band_tag("/p", "0x1000", 85, old_score=60, good_enough=90)
    assert "DOC_DRAFT" not in ghidra.added_tags()
    assert "COMPLETE_80" in ghidra.added_tags()


def test_non_boundary_target_crosses_without_band_change(ghidra):
    # good_enough=85 is NOT a COMPLETE boundary. 82 -> 88 stays in band 80, so
    # there is no band crossing, yet the target IS crossed -> DOC_DRAFT must
    # still fire. Proves the stamp doesn't rely on band crossings.
    ghidra.existing = []
    fun_doc.sync_band_tag("/p", "0x1000", 88, old_score=82, good_enough=85)
    assert "DOC_DRAFT" in ghidra.added_tags()
    assert ghidra.removed_tags() == []               # band untouched
    assert not any(t.startswith("COMPLETE_") for t in ghidra.added_tags())


def test_drop_below_target_never_removes_draft(ghidra):
    ghidra.existing = ["DOC_DRAFT", "COMPLETE_90"]
    # 92 -> 82: band demotes 90 -> 80, but the DOC rung must survive
    fun_doc.sync_band_tag("/p", "0x1000", 82, old_score=92, good_enough=90)
    assert "DOC_DRAFT" not in ghidra.removed_tags()
    assert "COMPLETE_90" in ghidra.removed_tags()     # band still demotes
    assert "COMPLETE_80" in ghidra.added_tags()


def test_pure_noop_when_nothing_changes(ghidra):
    ghidra.existing = ["COMPLETE_80"]
    # same band (80), no target crossing, old given -> zero Ghidra I/O
    fun_doc.sync_band_tag("/p", "0x1000", 85, old_score=82, good_enough=90)
    assert ghidra.posts == []


def test_complete_band_sync_preserved(ghidra):
    # Regression: the pre-existing COMPLETE_<band> behavior is unchanged.
    ghidra.existing = ["COMPLETE_80"]  # stale lower band
    fun_doc.sync_band_tag("/p", "0x1000", 96, old_score=82, good_enough=90)
    assert "COMPLETE_80" in ghidra.removed_tags()
    assert "COMPLETE_95" in ghidra.added_tags()


def test_resolves_target_when_not_supplied(ghidra, monkeypatch):
    # good_enough omitted -> sync_band_tag pulls the live Target.
    monkeypatch.setattr(fun_doc, "_good_enough_for_draft", lambda: 90)
    ghidra.existing = []
    fun_doc.sync_band_tag("/p", "0x1000", 93, old_score=70)
    assert "DOC_DRAFT" in ghidra.added_tags()


# --------------------------------------------------------------------------- #
# _good_enough_for_draft — mtime-memoized Target resolver
# --------------------------------------------------------------------------- #
class _FakePQFile:
    def __init__(self, mtime):
        self._m = mtime

    def exists(self):
        return True

    def stat(self):
        m = self._m

        class _S:
            st_mtime = m

        return _S()


def test_good_enough_memoized_on_mtime(monkeypatch):
    fake = _FakePQFile(111.0)
    monkeypatch.setattr(fun_doc, "PRIORITY_QUEUE_FILE", fake)
    parses = []

    def fake_load():
        parses.append(1)
        return {"config": {"good_enough_score": 93}}

    monkeypatch.setattr(fun_doc, "load_priority_queue", fake_load)

    assert fun_doc._good_enough_for_draft() == 93
    assert fun_doc._good_enough_for_draft() == 93  # served from cache
    assert parses == [1]                            # parsed once for one mtime

    fake._m = 222.0                                 # file "changed"
    assert fun_doc._good_enough_for_draft() == 93
    assert parses == [1, 1]                         # re-parsed after mtime change


# --------------------------------------------------------------------------- #
# run_assess_pass — batch sweep defaults to the Target
# --------------------------------------------------------------------------- #
def test_run_assess_pass_defaults_to_target(monkeypatch):
    calls = []
    monkeypatch.setattr(
        fun_doc, "_good_enough_for_draft", lambda: calls.append(1) or 90
    )
    # Empty function list -> early return after the threshold is resolved.
    monkeypatch.setattr(fun_doc, "_fetch_function_list", lambda program: [])
    rc = fun_doc.run_assess_pass("/p")  # draft_score defaults to None
    assert calls == [1]  # resolved the live Target
    assert rc == 1       # no functions -> documented early-return path
