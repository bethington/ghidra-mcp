"""Falsifiability state plumbing: Ghidra write-back + SQL persistence.

Covers the three layers a falsify verdict crosses:
  1. falsify.sync_to_ghidra — DOC_REFUTED tag, `Falsify` property record and
     idempotent plate flags, with `program` in the QUERY string on every write
     (a body-only program silently targets the ACTIVE program — 4,848 of
     17,442 Doc-map entries once landed on the wrong binary that way).
  2. storage round-trip — the migration-0007 columns survive
     upsert_function / update_function_fields (the both-lists trap).
  3. fun_doc's state<->row converters — falsify fields ride
     _state_func_to_row / _row_to_state_func including the timestamp.

Offline: Ghidra HTTP is a recorder rig (test_global_completeness._PostRec
pattern); SQL is a tmp sqlite file.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

fz = pytest.importorskip("falsify")


def _finding(check_id="convention_contradiction", tier=1):
    return fz.Finding(check_id=check_id, tier=tier,
                      program="/Mods/PD2-S12/D2Common.dll", address="0x6fd51000",
                      function="DATATBLS_GetRecordCount",
                      claim="declared __cdecl", evidence="RET 0x4 cleans stack")


class _HttpRig:
    """Records every falsify._get/_post call; scriptable responses."""

    def __init__(self):
        self.gets = []          # (path, params)
        self.posts = []         # (path, data, params)
        self.plate = ""
        self.fail_first_set_property = False
        self._set_prop_calls = 0

    def get(self, path, **params):
        self.gets.append((path, params))
        if path == "/get_comment":
            return {"plate": self.plate}
        return {}

    def post(self, path, data, **params):
        self.posts.append((path, data, params))
        if path == "/set_property":
            self._set_prop_calls += 1
            if self.fail_first_set_property and self._set_prop_calls == 1:
                return {"success": False,
                        "error": "No property map named 'Falsify'"}
        if path == "/set_comment":
            self.plate = data.get("comment", "")
        return {"success": True}

    def posts_to(self, path):
        return [(d, p) for (pp, d, p) in self.posts if pp == path]


@pytest.fixture
def rig(monkeypatch):
    r = _HttpRig()
    monkeypatch.setattr(fz, "_get", r.get)
    monkeypatch.setattr(fz, "_post", r.post)
    monkeypatch.setattr(fz, "_SYNC_FAILURES", 0)
    return r


# ------------------------------------------------------ sync_to_ghidra ------

def test_contradicted_writes_tag_property_and_flag(rig):
    ok = fz.sync_to_ghidra("/Mods/PD2-S12/D2Common.dll", "0x6fd51000",
                           "contradicted", [_finding()], "worker",
                           date="2026-08-02")
    assert ok

    tags = rig.posts_to("/add_function_tag")
    assert len(tags) == 1
    data, params = tags[0]
    assert data["tags"] == fz.DOC_REFUTED_TAG
    assert params["program"] == "D2Common.dll", \
        "program must ride the QUERY string, and as the bare name"

    props = rig.posts_to("/set_property")
    assert len(props) == 1
    assert props[0][0]["map"] == fz.FALSIFY_PROPERTY_MAP
    assert props[0][1]["program"] == "D2Common.dll"
    assert '"status":"contradicted"' in props[0][0]["value"]

    comments = rig.posts_to("/set_comment")
    assert len(comments) == 1
    assert fz.flag_marker("convention_contradiction") in comments[0][0]["comment"]
    assert comments[0][1]["program"] == "D2Common.dll"


def test_lazy_property_map_creation_retries(rig):
    rig.fail_first_set_property = True
    ok = fz.sync_to_ghidra("D2Common.dll", "0x6fd51000", "contradicted",
                           [_finding()], "sweep", date="2026-08-02")
    assert ok
    creates = rig.posts_to("/create_property_map")
    assert len(creates) == 1
    assert creates[0][0]["name"] == fz.FALSIFY_PROPERTY_MAP
    assert len(rig.posts_to("/set_property")) == 2, "retry after map creation"


def test_plate_flag_is_idempotent(rig):
    rig.plate = fz.finding_flag_text(_finding(), "2026-08-01") + "\n\nSummary."
    fz.sync_to_ghidra("D2Common.dll", "0x6fd51000", "contradicted",
                      [_finding()], "worker", date="2026-08-02")
    assert rig.posts_to("/set_comment") == [], \
        "marker already present -> no duplicate flag, no plate rewrite"


def test_passed_removes_tag_and_strips_flags(rig):
    rig.plate = fz.finding_flag_text(_finding(), "2026-08-01") + "\n\nSummary.\n\nAlgorithm:\n  1. Do the thing."
    ok = fz.sync_to_ghidra("D2Common.dll", "0x6fd51000", "passed",
                           [], "worker", date="2026-08-02")
    assert ok
    assert len(rig.posts_to("/remove_function_tag")) == 1
    comments = rig.posts_to("/set_comment")
    assert len(comments) == 1
    assert fz._FLAG_PREFIX not in comments[0][0]["comment"]
    assert "Summary." in comments[0][0]["comment"]
    assert "Algorithm:" in comments[0][0]["comment"]


def test_passed_with_clean_plate_touches_nothing(rig):
    rig.plate = "Summary.\n\nAlgorithm:\n  1. Fine."
    fz.sync_to_ghidra("D2Common.dll", "0x6fd51000", "passed", [], "worker",
                      date="2026-08-02")
    assert rig.posts_to("/set_comment") == []


def test_unchecked_and_unfalsifiable_write_nothing(rig):
    for status in ("unchecked", "unfalsifiable"):
        assert fz.sync_to_ghidra("D2Common.dll", "0x1", status, [], "worker",
                                 date="2026-08-02")
    assert rig.posts == []


def test_unknown_status_is_refused(rig, capsys):
    assert not fz.sync_to_ghidra("D2Common.dll", "0x1", "bogus", [], "worker")
    assert rig.posts == []
    assert "unknown status" in capsys.readouterr().err


def test_sync_failure_is_loud_and_nonfatal(rig, monkeypatch, capsys):
    def boom(path, data, **params):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(fz, "_post", boom)
    ok = fz.sync_to_ghidra("D2Common.dll", "0x1", "contradicted",
                           [_finding()], "worker", date="2026-08-02")
    assert ok is False
    assert "write-back WARN" in capsys.readouterr().err
    assert fz._SYNC_FAILURES == 1


def test_circuit_breaker_stops_paying_timeouts(rig, monkeypatch):
    monkeypatch.setattr(fz, "_SYNC_FAILURES", fz._SYNC_MAX_FAILURES)
    ok = fz.sync_to_ghidra("D2Common.dll", "0x1", "contradicted",
                           [_finding()], "worker", date="2026-08-02")
    assert ok is False
    assert rig.posts == [], "tripped breaker must not issue HTTP"


# ----------------------------------------------------- pure verdict bits ----

def test_status_for_verdicts():
    t1, t2 = _finding(tier=1), _finding(check_id="return_contradiction", tier=2)
    assert fz.status_for([t1, t2]) == "contradicted"
    assert fz.status_for([t2]) == "passed", "tier-2 alone carries no consequence"
    assert fz.status_for([]) == "passed"
    assert fz.status_for([], checks_ran=False) == "unchecked"


def test_strip_falsify_flags_round_trip():
    body = "Summary line.\n\nAlgorithm:\n  1. Step."
    flagged = (fz.finding_flag_text(_finding(), "2026-08-02") + "\n\n"
               + fz.finding_flag_text(_finding("arity_contradiction"), "2026-08-02")
               + "\n\n" + body)
    assert fz.strip_falsify_flags(flagged) == body
    assert fz.strip_falsify_flags(body) == body


# ------------------------------------------------------- SQL round-trip -----

@pytest.fixture
def sqlite_repo(tmp_path):
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    cfg = StorageConfig(backend="sqlite",
                        url=f"sqlite:///{tmp_path / 'test.db'}", schema=None)
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    yield repo
    engine.dispose()


def test_falsify_fields_survive_upsert(sqlite_repo):
    from datetime import datetime, timezone

    ts = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
    sqlite_repo.upsert_function({
        "program_path": "/Mods/PD2-S12/D2Common.dll",
        "binary_name": "D2Common.dll",
        "address": "6fd51000",
        "falsify_status": "contradicted",
        "falsify_checked_at": ts,
        "falsify_findings": [_finding().to_dict()],
        "falsify_source": "worker",
        "audit_tool_calls": 7,
        "audit_tool_calls_known": True,
    })
    row = sqlite_repo.get_function("/Mods/PD2-S12/D2Common.dll", "6fd51000")
    assert row["falsify_status"] == "contradicted"
    assert row["falsify_source"] == "worker"
    assert row["falsify_findings"][0]["check_id"] == "convention_contradiction"
    assert row["audit_tool_calls"] == 7
    assert row["audit_tool_calls_known"] in (True, 1)


def test_falsify_fields_survive_update_function_fields(sqlite_repo):
    """The both-lists trap: update_function_fields silently drops any field
    missing from _UPDATABLE_WORKFLOW_FIELDS. These must not be dropped."""
    sqlite_repo.upsert_function({
        "program_path": "/p", "binary_name": "p", "address": "1000",
    })
    changed = sqlite_repo.update_function_fields(
        "/p", "1000",
        falsify_status="passed", falsify_source="sweep",
        audit_tool_calls=3, audit_tool_calls_known=True)
    assert changed, "fields were silently filtered out of the update"
    row = sqlite_repo.get_function("/p", "1000")
    assert row["falsify_status"] == "passed"
    assert row["falsify_source"] == "sweep"
    assert row["audit_tool_calls"] == 3


# ------------------------------------------- fun_doc state<->row converts ---

def test_state_row_converters_carry_falsify_fields():
    import fun_doc as fd

    rec = {
        "program": "/Mods/PD2-S12/D2Common.dll",
        "program_name": "D2Common.dll",
        "address": "6fd51000",
        "falsify_status": "contradicted",
        "falsify_findings": [{"check_id": "arity_contradiction", "tier": 1}],
        "falsify_source": "worker",
        "falsify_checked_at": "2026-08-02T12:00:00",
        "audit_tool_calls": 5,
        "audit_tool_calls_known": True,
    }
    row = fd._state_func_to_row("/Mods/PD2-S12/D2Common.dll::6fd51000", rec)
    assert row["falsify_status"] == "contradicted"
    assert row["falsify_source"] == "worker"
    assert row["falsify_findings"][0]["check_id"] == "arity_contradiction"
    assert row["audit_tool_calls"] == 5
    assert row["audit_tool_calls_known"] is True
    assert row["falsify_checked_at"] is not None
    assert hasattr(row["falsify_checked_at"], "isoformat"), \
        "timestamps must cross the boundary as datetimes, not strings"

    back = fd._row_to_state_func(row)
    assert back["falsify_status"] == "contradicted"
    assert back["falsify_checked_at"].startswith("2026-08-02T12:00:00")
    assert back["audit_tool_calls"] == 5
