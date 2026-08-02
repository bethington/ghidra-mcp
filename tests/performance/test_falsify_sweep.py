"""falsify_sweep.py's pure planning/merge layer + the dry-run write guarantee.

Offline. HTTP is a recorder; the assertion that matters most is that a
DRY-RUN SWEEP ISSUES ZERO POSTS — report-first is the contract Ben approved
before any corpus-wide consequence lands.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
for p in (FUN_DOC, FUN_DOC / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

fz = pytest.importorskip("falsify")
sweep = pytest.importorskip("falsify_sweep")


def _finding(check_id="arity_contradiction", tier=1, program="/M/a.dll",
             address="1000", function="F"):
    return fz.Finding(check_id=check_id, tier=tier, program=program,
                      address=address, function=function,
                      claim="c", evidence="e")


# ------------------------------------------------------------ summarize -----

def test_summarize_counts_by_check_and_binary():
    v = {
        "/M/a.dll": {
            "1000": ("F1", "contradicted", [_finding()]),
            "2000": ("F2", "passed", []),
            "3000": ("F3", "passed",
                     [_finding("return_contradiction", 2, address="3000")]),
            "4000": ("F4", "error", []),
        },
    }
    s = sweep.summarize(v)
    assert s["per_check"] == {"arity_contradiction": 1, "return_contradiction": 1}
    b = s["per_binary"]["/M/a.dll"]
    assert b["scanned"] == 4
    assert b["contradicted"] == 1
    assert b["passed"] == 2
    assert b["error"] == 1
    assert b["tier1"] == 1 and b["tier2"] == 1


# --------------------------------------------------------- merge_doclint ----

def test_merge_doclint_recomputes_status(monkeypatch):
    """A doc_lint tier-1 defect must flip an otherwise-passed function to
    contradicted, and append (not replace) existing findings."""
    class _DL:
        @staticmethod
        def collect(p):
            return ["rec"]

        @staticmethod
        def calibrate(recs):
            return {}

    monkeypatch.setitem(sys.modules, "doc_lint", _DL)
    dl_finding = _finding("library_domain_prefix", 1, program="/M/a.dll",
                          address="1000", function="DATATBLS_SortElements")
    monkeypatch.setattr(fz, "doclint_findings", lambda recs, stats: [dl_finding])

    v = {"/M/a.dll": {
        "1000": ("DATATBLS_SortElements", "passed",
                 [_finding("return_contradiction", 2, address="1000")]),
    }}
    sweep.merge_doclint(v, ["/M/a.dll"])
    name, status, findings = v["/M/a.dll"]["1000"]
    assert status == "contradicted"
    assert {f.check_id for f in findings} == {"return_contradiction",
                                              "library_domain_prefix"}


def test_merge_doclint_adds_unseen_function(monkeypatch):
    class _DL:
        @staticmethod
        def collect(p):
            return ["rec"]

        @staticmethod
        def calibrate(recs):
            return {}

    monkeypatch.setitem(sys.modules, "doc_lint", _DL)
    dl_finding = _finding("library_domain_prefix", 2, program="/M/a.dll",
                          address="9999", function="MONSTER_FpuThing")
    monkeypatch.setattr(fz, "doclint_findings", lambda recs, stats: [dl_finding])
    v = {}
    sweep.merge_doclint(v, ["/M/a.dll"])
    name, status, findings = v["/M/a.dll"]["9999"]
    assert name == "MONSTER_FpuThing"
    assert status == "passed", "tier-2 alone must not mark contradicted"
    assert findings[0].check_id == "library_domain_prefix"


# ----------------------------------------------------------- walk/collect ---

def test_walk_folders_recurses(monkeypatch):
    tree = {
        "/": {"folders": ["Mods", "Vanilla"], "files": []},
        "/Mods": {"folders": ["PD2-S12"], "files": []},
        "/Mods/PD2-S12": {"folders": [], "files": []},
        "/Vanilla": {"folders": [], "files": []},
    }
    monkeypatch.setattr(fz, "_get",
                        lambda path, **p: tree[p.get("folder", "/")])
    assert sweep.walk_folders() == ["/", "/Mods", "/Mods/PD2-S12", "/Vanilla"]


# -------------------------------------------------------- dry-run contract --

def test_dry_run_issues_zero_writes(monkeypatch, tmp_path, capsys):
    """The whole point of report-first: without --apply, not one POST."""
    posts = []
    monkeypatch.setattr(fz, "_post",
                        lambda path, data, **p: posts.append(path) or {"success": True})

    def fake_get(path, **params):
        if path == "/list_project_files":
            return {"folders": [], "files": [
                {"name": "a.dll", "path": "/M/a.dll", "content_type": "Program"},
            ]}
        if path == "/list_functions":
            return {"functions": [{"name": "DATATBLS_GetX", "address": "1000"}]}
        if path == "/get_function_documentation":
            return {"function_name": "DATATBLS_GetX",
                    "calling_convention": "__stdcall", "return_type": "int",
                    "parameters": [{"name": "a", "type": "int"}],
                    "plate_comment": ""}
        if path == "/disassemble_function":
            return {"instructions": [
                {"address": "6fd51000",
                 "instruction": "MOV EAX,dword ptr [ESP + 0x4]"},
                {"address": "6fd51004", "instruction": "RET 0x8"},  # contradiction
            ]}
        return {}

    monkeypatch.setattr(fz, "_get", fake_get)
    out = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv",
                        ["falsify_sweep", "--folder", "/M", "--no-doclint",
                         "--json", str(out)])
    assert sweep.main() == 0
    assert posts == [], "dry-run must not issue a single POST"
    import json
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["mode"] == "dry-run"
    assert report["applied"] is None
    v = report["verdicts"]["/M/a.dll"]["1000"]
    assert v["status"] == "contradicted"
    assert v["findings"][0]["check_id"] == "arity_contradiction"


def test_apply_sql_upserts_missing_rows(monkeypatch, tmp_path):
    """--apply's SQL half: existing rows patched, unknown functions upserted
    with a minimal identity row (both survive the field gates)."""
    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{tmp_path / 's.db'}")
    from datetime import datetime, timezone

    from storage import StorageConfig, make_engine, resolve_config
    from storage.repository import Repository

    cfg = resolve_config()
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    repo.upsert_function({"program_path": "/M/a.dll", "binary_name": "a.dll",
                          "address": "1000"})
    engine.dispose()

    v = {"/M/a.dll": {
        "1000": ("F1", "contradicted", [_finding()]),
        "2000": ("F2", "passed", []),
        "3000": ("F3", "error", []),
    }}
    counts = sweep.apply_sql(v, datetime.now(timezone.utc))
    assert counts == {"updated": 1, "upserted": 1}, \
        "error rows must not be stamped"

    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    r1 = repo.get_function("/M/a.dll", "1000")
    assert r1["falsify_status"] == "contradicted"
    assert r1["falsify_source"] == "sweep"
    r2 = repo.get_function("/M/a.dll", "2000")
    assert r2["falsify_status"] == "passed"
    r3 = repo.get_function("/M/a.dll", "3000")
    assert r3 is None
    engine.dispose()
