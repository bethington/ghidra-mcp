"""Hermetic fixtures for the fun-doc dashboard route contract.

Prerequisites: none. No Ghidra, no browser, no dashboard process, no
provider, no network. That is the entire point of this tier -- it is the
only dashboard coverage that can run in CI, and the only kind that still
runs when the fleet is down, which is exactly when you are most likely to
be changing this code.

What is faked, and where the seam is
------------------------------------
``conformance_dashboard._get`` / ``._post``   the ONLY two functions the
    dashboard read layer uses to reach the Ghidra plugin. Replaced with
    ``fake_ghidra.FakeGhidra``, a corpus with known arithmetic.

``web.OracleHealthMonitor`` / ``web.GhidraHealthMonitor``   both are
    constructed and ``.start()``ed inside ``WorkerManager.__init__``, so they
    are patched at the ``web`` module attribute BEFORE ``create_app`` runs.
    Real ones shell out to PowerShell, probe a game process and can LAUNCH
    GHIDRA -- none of which belongs in a test.

State isolation
---------------
``fun_doc``'s module-level path constants and the dashboard's
``STATE_FILE`` / ``QUEUE_FILE`` / ``LOG_FILE`` are all redirected into a
per-test ``tmp_path``. Nothing here may touch ``fun-doc/state.db``,
``fun-doc/priority_queue.json`` or ``fun-doc/logs/`` -- a test that rewrites
the operator's provider config or queue is worse than no test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FUN_DOC_DIR = REPO_ROOT / "fun-doc"

# `fun_doc`, `web`, `conformance_dashboard` and friends import each other by
# bare module name, so fun-doc/ has to be importable as a directory.
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

pytestmark = pytest.mark.dashboard


def pytest_collection_modifyitems(items):
    for item in items:
        item.add_marker(pytest.mark.dashboard)


# --------------------------------------------------------------------------
# import guard
# --------------------------------------------------------------------------


def _require_fun_doc_deps() -> None:
    """Skip this tier -- loudly, and only this tier -- without the fun-doc deps.

    `fun_doc` calls `sys.exit(1)` on a missing SQLAlchemy import. Inside
    pytest that surfaces as an INTERNALERROR during COLLECTION: zero tests
    run, every other tier goes down with it, and the message looks nothing
    like "you forgot --group fun-doc". Checking first turns that into a skip.
    """
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:  # pragma: no cover - environment dependent
        pytest.skip(
            "fun-doc dependencies absent; run with `uv run --group fun-doc pytest`",
            allow_module_level=True,
        )


_require_fun_doc_deps()


# --------------------------------------------------------------------------
# fake dependency monitors
# --------------------------------------------------------------------------


# The fake monitors and the ORACLE_FAULTS table live in `monitors.py` --
# see that module's docstring for why they are not defined here.
from monitors import (  # noqa: E402
    ORACLE_FAULTS,
    FakeGhidraMonitor,
    FakeOracleMonitor,
)


# --------------------------------------------------------------------------
# sandboxed state
# --------------------------------------------------------------------------


def _seed_queue_config(path: Path) -> None:
    """A minimal but REAL priority_queue.json.

    Copied from the live one when it exists so the settings routes are
    exercised against the operator's actual config *shape* (provider tables
    drift), falling back to a literal when it does not. Either way the copy
    is what gets written to -- the original is opened read-only, once.
    """
    live = FUN_DOC_DIR / "priority_queue.json"
    if live.is_file():
        try:
            data = json.loads(live.read_text(encoding="utf-8"))
            # Never carry the operator's worker roster or pins into a sandbox:
            # a restore-roster route would then try to start real workers.
            cfg = data.get("config", {})
            cfg.pop("dashboard_active_workers", None)
            path.write_text(json.dumps({"config": cfg, "pinned": []}, indent=2), encoding="utf-8")
            return
        except (OSError, ValueError, AttributeError):
            pass
    path.write_text(
        json.dumps(
            {
                "config": {
                    "target": 90,
                    "provider": "minimax",
                    "audit_provider": "gemini",
                    "audit_min_delta": 5,
                    "falsify_enabled": True,
                    "provider_models": {},
                },
                "pinned": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch) -> Path:
    """A throwaway fun-doc working directory. Nothing escapes it."""
    root = tmp_path / "fundoc"
    (root / "logs").mkdir(parents=True)

    state_file = root / "state.json"
    state_file.write_text(json.dumps({"functions": {}, "meta": {}}), encoding="utf-8")
    _seed_queue_config(root / "priority_queue.json")
    (root / "logs" / "runs.jsonl").write_text("", encoding="utf-8")
    (root / "logs" / "events.jsonl").write_text("", encoding="utf-8")

    # SQLite in the sandbox, never fun-doc/state.db.
    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{(root / 'state.db').as_posix()}")
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.setenv("FUNDOC_GHIDRA_PROGRAM", "/testing/fake/Fake.dll")
    # Keep every best-effort outbound integration off.
    monkeypatch.delenv("RE_KB_ARCHIVE_URL", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_ARCHIVE_URL", raising=False)
    monkeypatch.delenv("GHIDRA_DEBUGGER_URL", raising=False)

    import fun_doc

    for attr, value in (
        ("STATE_FILE", state_file),
        ("PRIORITY_QUEUE_FILE", root / "priority_queue.json"),
        ("LOG_FILE", root / "logs" / "runs.jsonl"),
        ("EVENT_LOG_FILE", root / "logs" / "events.jsonl"),
    ):
        if hasattr(fun_doc, attr):
            monkeypatch.setattr(fun_doc, attr, value, raising=False)

    return root


# --------------------------------------------------------------------------
# the app under test
# --------------------------------------------------------------------------


class Harness:
    """A hermetic dashboard: Flask test client + the fakes behind it."""

    def __init__(self, client, fake_ghidra, oracle: FakeOracleMonitor,
                 ghidra: FakeGhidraMonitor, app, sandbox: Path):
        self.client = client
        self.ghidra_corpus = fake_ghidra
        self.oracle = oracle
        self.ghidra = ghidra
        self.app = app
        self.sandbox = sandbox

    # -- request helpers ---------------------------------------------------

    # NOTE: the route is a POSITIONAL-ONLY parameter (the `/` below). Several
    # dashboard endpoints take a query param literally named `path`
    # (`/api/conformance/draft_content?path=...`), and a normal positional
    # would collide with it -- "got multiple values for argument 'path'".
    def get(self, route: str, /, **params: Any):
        return self.client.get(
            route, query_string={k: v for k, v in params.items() if v is not None} or None
        )

    def json(self, route: str, /, **params: Any) -> Any:
        r = self.get(route, **params)
        assert r.status_code == 200, (
            f"GET {route} -> {r.status_code}: {r.get_data(as_text=True)[:400]}"
        )
        return r.get_json()

    def post(self, route: str, /, body: dict | None = None, **params: Any):
        return self.client.post(
            route,
            json=body or {},
            query_string={k: v for k, v in params.items() if v is not None} or None,
        )

    # -- fault injection ---------------------------------------------------

    def set_oracle(self, shape: str, **extra: Any) -> None:
        """Drive the oracle monitor to one of the four named fault shapes."""
        assert shape in ORACLE_FAULTS, f"unknown oracle shape {shape!r}"
        self.oracle.state = {**FakeOracleMonitor.DEFAULT, **ORACLE_FAULTS[shape], **extra}

    def set_ghidra(self, *, running: bool = True, reachable: bool = True, **extra: Any) -> None:
        self.ghidra.state = {**FakeGhidraMonitor.DEFAULT, "running": running,
                             "reachable": reachable, **extra}


@pytest.fixture
def harness(sandbox: Path, monkeypatch) -> Harness:
    import fake_ghidra as fg
    import web

    corpus = fg.install(monkeypatch)

    # Patch the monitor CLASSES on the `web` module: WorkerManager constructs
    # and start()s both in its __init__, which create_app calls. Patching the
    # instances afterwards would already have shelled out to PowerShell and,
    # for the Ghidra monitor, possibly launched Ghidra.
    oracle_holder: dict[str, FakeOracleMonitor] = {}
    ghidra_holder: dict[str, FakeGhidraMonitor] = {}

    def _make_oracle(*a: Any, **kw: Any) -> FakeOracleMonitor:
        m = FakeOracleMonitor(*a, **kw)
        oracle_holder["m"] = m
        return m

    def _make_ghidra(*a: Any, **kw: Any) -> FakeGhidraMonitor:
        m = FakeGhidraMonitor(*a, **kw)
        ghidra_holder["m"] = m
        return m

    monkeypatch.setattr(web, "OracleHealthMonitor", _make_oracle)
    monkeypatch.setattr(web, "GhidraHealthMonitor", _make_ghidra)

    app, _socketio = web.create_app(str(sandbox / "state.json"))
    app.config["QUEUE_FILE"] = sandbox / "priority_queue.json"
    app.config["LOG_FILE"] = sandbox / "logs" / "runs.jsonl"
    app.config["TESTING"] = True
    # TESTING=True makes Flask RE-RAISE handler exceptions instead of turning
    # them into a 500. That is the opposite of what this tier needs: the
    # question being asked is "what does the OPERATOR's browser get when a
    # panel's backend throws", and the answer has to be an HTTP status, not a
    # Python traceback in the test runner.
    app.config["PROPAGATE_EXCEPTIONS"] = False

    return Harness(
        client=app.test_client(),
        fake_ghidra=corpus,
        oracle=oracle_holder.get("m") or FakeOracleMonitor(),
        ghidra=ghidra_holder.get("m") or FakeGhidraMonitor(),
        app=app,
        sandbox=sandbox,
    )


@pytest.fixture
def guard_real_state():
    """Fail the test if the operator's real fun-doc state was modified.

    Belt and braces on top of the sandbox. Every fixture here redirects
    writes, but a route that reconstructs a path from ``__file__`` rather
    than from app config would slip past all of them -- and the failure mode
    is silently rewriting the operator's provider config, which is exactly
    the class of bug that reverted ``globals_audit_provider`` twice in one
    session.
    """
    watched = [
        FUN_DOC_DIR / "priority_queue.json",
        FUN_DOC_DIR / "state.json",
        FUN_DOC_DIR / "state.db",
    ]
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    yield
    for p, sig in before.items():
        assert (p.stat().st_mtime_ns, p.stat().st_size) == sig, (
            f"{p} was modified by a test. The sandbox leaked: find the route "
            f"that builds its path from __file__ instead of app config."
        )
