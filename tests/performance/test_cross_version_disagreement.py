"""Pure grouping/diff logic of the cross-version disagreement harvester.

Same code (same normalized hash) + different human names = at least one name
is wrong. Offline — the pure layer only; the paged fetch is I/O and is
covered by running the tool.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
for p in (FUN_DOC, FUN_DOC / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

fz = pytest.importorskip("falsify")
cvd = pytest.importorskip("cross_version_disagreement")


def _row(name, hash_="H1", addr="6fd51000", icount=20):
    return {"name": name, "hash": hash_, "address": addr,
            "instruction_count": icount}


def test_disagreement_found_across_versions():
    rows = {
        "/Vanilla/1.09d/D2Common.dll": [_row("DATATBLS_GetRecord")],
        "/Vanilla/1.13c/D2Common.dll": [_row("ITEMS_LookupEntry", addr="6fd62000")],
    }
    groups = cvd.group_rows(rows)
    dis = cvd.find_disagreements(groups)
    assert len(dis) == 1
    assert dis[0]["names"] == {"DATATBLS_GetRecord": 1, "ITEMS_LookupEntry": 1}
    assert len(dis[0]["members"]) == 2


def test_agreeing_names_are_not_a_disagreement():
    rows = {
        "/Vanilla/1.09d/D2Common.dll": [_row("DATATBLS_GetRecord")],
        "/Vanilla/1.13c/D2Common.dll": [_row("DATATBLS_GetRecord", addr="6fd62000")],
    }
    assert cvd.find_disagreements(cvd.group_rows(rows)) == []


def test_propagation_suffix_is_not_a_disagreement():
    """`Foo` vs `Foo_2` is the propagator's name-conflict fallback, not a
    human disagreement."""
    rows = {
        "/a/x.dll": [_row("DATATBLS_GetRecord")],
        "/b/x.dll": [_row("DATATBLS_GetRecord_2", addr="6fd62000")],
    }
    assert cvd.find_disagreements(cvd.group_rows(rows)) == []


def test_tiny_functions_are_skipped():
    """Sub-threshold bodies hash-collide meaninglessly (the Propagate script
    skips <2 instructions for the same reason)."""
    rows = {
        "/a/x.dll": [_row("StubReturnZero", icount=2)],
        "/b/x.dll": [_row("NoOp", addr="6fd62000", icount=2)],
    }
    assert cvd.group_rows(rows) == {}


def test_lib_tagged_functions_are_skipped():
    """Identical CRT sharing a name is the GOOD case; the misnamed case
    belongs to doc_lint's library_domain_prefix check, not this one."""
    rows = {
        "/a/x.dll": [_row("memcpy")],
        "/b/x.dll": [_row("MONSTER_CopyBuffer", addr="6fd62000")],
    }
    groups = cvd.group_rows(rows, {"/a/x.dll": ["memcpy"],
                                   "/b/x.dll": ["MONSTER_CopyBuffer"]})
    assert groups == {}


def test_different_hashes_never_group():
    rows = {
        "/a/x.dll": [_row("Alpha", hash_="H1")],
        "/b/x.dll": [_row("Beta", hash_="H2", addr="6fd62000")],
    }
    assert cvd.find_disagreements(cvd.group_rows(rows)) == []


def test_finding_is_tier2_and_names_the_other_side():
    rows = {
        "/a/x.dll": [_row("Alpha")],
        "/b/x.dll": [_row("Beta", addr="6fd62000")],
        "/c/x.dll": [_row("Beta", addr="6fd63000")],
    }
    g = cvd.find_disagreements(cvd.group_rows(rows))[0]
    alpha = next(m for m in g["members"] if m["name"] == "Alpha")
    f = cvd.finding_for_member(alpha, g)
    assert f.tier == fz.TIER_REVIEW, "the harvester never issues a verdict"
    assert f.check_id == "cross_version_disagreement"
    assert "Alpha" in f.claim
    assert "Beta (x2)" in f.evidence
    assert f.detail["member_count"] == 3


def test_merge_preserves_other_checks_and_replaces_stale_self():
    existing = [
        {"check_id": "arity_contradiction", "tier": 1},
        {"check_id": "cross_version_disagreement", "tier": 2, "stale": True},
    ]
    fresh = {"check_id": "cross_version_disagreement", "tier": 2}
    merged = cvd.merge_finding_into_row(existing, fresh)
    assert {f["check_id"] for f in merged} == {"arity_contradiction",
                                              "cross_version_disagreement"}
    cv = [f for f in merged if f["check_id"] == "cross_version_disagreement"]
    assert cv == [fresh], "stale cross_version finding must be replaced"


def test_flag_finding_tier2_wording_and_idempotency(monkeypatch):
    posts = []
    plate = {"text": ""}
    monkeypatch.setattr(fz, "_get",
                        lambda path, **p: {"plate": plate["text"]})

    def post(path, data, **p):
        posts.append((path, data, p))
        plate["text"] = data.get("comment", plate["text"])
        return {"success": True}
    monkeypatch.setattr(fz, "_post", post)

    f = fz.Finding(check_id="cross_version_disagreement", tier=2,
                   program="/a/x.dll", address="6fd51000", function="Alpha",
                   claim="name 'Alpha'", evidence="others say Beta")
    assert fz.flag_finding("/a/x.dll", "6fd51000", f, date="2026-08-02") == "flagged"
    assert posts[0][2]["program"] == "x.dll", "program rides the query string"
    assert "REVIEW:" in posts[0][1]["comment"]
    assert "CONTRADICTION" not in posts[0][1]["comment"], \
        "tier-2 wording must not claim mechanical certainty"
    # Second call: marker present -> no write.
    assert fz.flag_finding("/a/x.dll", "6fd51000", f,
                           date="2026-08-03") == "already-flagged"
    assert len(posts) == 1
