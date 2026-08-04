"""falsify_api blueprint routes: the dashboard's SQL-backed verdict map.

Runs the blueprint on a bare Flask app (no full create_app — the routes read
only the storage layer). The conftest autouse fixture points FUN_DOC_DB_URL at
an isolated tmp sqlite DB per test.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

flask = pytest.importorskip("flask")


@pytest.fixture
def client(monkeypatch):
    import falsify_api

    monkeypatch.setattr(falsify_api, "_repo", None)  # drop cross-test cache
    app = flask.Flask(__name__)
    app.register_blueprint(falsify_api.falsify_bp)
    return app.test_client()


@pytest.fixture
def seeded_repo():
    """Bootstrap the isolated DB and seed a small verdict map."""
    from storage import make_engine, resolve_config
    from storage.repository import Repository

    cfg = resolve_config()
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    rows = [
        ("/M/a.dll", "1000", "GoodFn", "passed", None),
        ("/M/a.dll", "2000", "WrongFn", "contradicted",
         [{"check_id": "arity_contradiction", "tier": 1,
           "claim": "1 param", "evidence": "RET 0x8"}]),
        ("/M/a.dll", "3000", "NeverChecked", None, None),
        ("/M/b.dll", "4000", "OtherBinaryWrong", "contradicted",
         [{"check_id": "convention_contradiction", "tier": 1,
           "claim": "cdecl", "evidence": "RET 0x4"}]),
    ]
    for path, addr, name, status, findings in rows:
        repo.upsert_function({
            "program_path": path, "binary_name": path.rsplit("/", 1)[-1],
            "address": addr, "name": name,
            "falsify_status": status, "falsify_findings": findings,
            "falsify_source": "sweep" if status else None,
        })
    yield repo
    engine.dispose()


def test_summary_counts_by_binary_and_status(client, seeded_repo):
    r = client.get("/api/falsify/summary")
    assert r.status_code == 200
    j = r.get_json()
    assert j["totals"]["contradicted"] == 2
    assert j["totals"]["passed"] == 1
    assert j["totals"]["unchecked"] == 1, "NULL status reads as unchecked"
    assert j["per_binary"]["/M/a.dll"]["contradicted"] == 1
    assert j["per_binary"]["/M/b.dll"]["contradicted"] == 1


def test_findings_default_lists_contradicted(client, seeded_repo):
    r = client.get("/api/falsify/findings")
    assert r.status_code == 200
    j = r.get_json()
    assert j["status"] == "contradicted"
    names = {f["name"] for f in j["functions"]}
    assert names == {"WrongFn", "OtherBinaryWrong"}
    wrong = next(f for f in j["functions"] if f["name"] == "WrongFn")
    assert wrong["findings"][0]["check_id"] == "arity_contradiction"


def test_findings_program_filter(client, seeded_repo):
    r = client.get("/api/falsify/findings?program=/M/b.dll")
    j = r.get_json()
    assert [f["name"] for f in j["functions"]] == ["OtherBinaryWrong"]


def test_broken_storage_degrades_not_500(client, monkeypatch):
    """Dashboard convention: report, don't 500."""
    import falsify_api

    def boom():
        raise RuntimeError("storage unavailable")
    monkeypatch.setattr(falsify_api, "_get_repo", boom)
    for route in ("/api/falsify/summary", "/api/falsify/findings"):
        r = client.get(route)
        assert r.status_code == 200
        assert "error" in r.get_json()
