"""Fixtures for the undocumented -> documented pass over Benchmark.dll.

Three prerequisite levels live here, and each self-skips rather than failing
when its prerequisite is absent:

``offline``   ``test_floors.py`` and the mock pipeline. Nothing required.
``ghidra``    a DEDICATED Ghidra answering on ``--benchmark-ghidra-url``
              (default ``http://127.0.0.1:8189``) holding an UNDOCUMENTED
              ``Benchmark.dll``.
``real``      the above plus ``--real-provider``, which spends tokens.

Why a dedicated instance and not the operator's 8089
----------------------------------------------------
This tier documents a whole binary, which means it RENAMES FUNCTIONS, writes
plates, applies tags and saves the program. Pointed at the working instance
it would do all of that inside whichever project happens to be open. The
existing ``reset_benchmark_fixture`` path is also known to fail with
"Benchmark.dll is in use" against a long-running instance, so "just reset it
first" is not a safe substitute for isolation.

The default port is 8189 rather than 8089 for the same reason: a typo, a
stale env var or a forgotten export must not silently land on the real one.
``require_dedicated_instance`` refuses 8089 outright.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FUN_DOC_DIR = REPO_ROOT / "fun-doc"
BENCHMARK_DIR = FUN_DOC_DIR / "benchmark"

for _p in (BENCHMARK_DIR, FUN_DOC_DIR, Path(__file__).resolve().parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

#: The operator's working instance. Never acceptable as a target here.
FORBIDDEN_URLS = {"http://127.0.0.1:8089", "http://localhost:8089"}

DEFAULT_BENCHMARK_GHIDRA_URL = "http://127.0.0.1:8189"
DEFAULT_PROGRAM = "/testing/benchmark/Benchmark.dll"


def pytest_addoption(parser):
    group = parser.getgroup("fun-doc benchmark e2e")
    group.addoption(
        "--benchmark-ghidra-url",
        action="store",
        default=None,
        help=f"Dedicated Ghidra for the benchmark pass (default "
             f"{DEFAULT_BENCHMARK_GHIDRA_URL}). Must NOT be the working instance on 8089.",
    )
    group.addoption(
        "--benchmark-program",
        action="store",
        default=None,
        help=f"Ghidra program path for Benchmark.dll (default {DEFAULT_PROGRAM})",
    )
    group.addoption(
        "--real-provider",
        action="store_true",
        default=False,
        help="Run the tier that spends real provider tokens. Off by default.",
    )


def pytest_collection_modifyitems(config, items):
    for item in items:
        item.add_marker(pytest.mark.benchmark_e2e)
    if config.getoption("--real-provider"):
        return
    skip = pytest.mark.skip(reason="needs --real-provider (spends tokens)")
    for item in items:
        if "real_provider" in item.keywords:
            item.add_marker(skip)


# --------------------------------------------------------------------------
# ground truth
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ground_truth() -> dict[str, Any]:
    path = BENCHMARK_DIR / "ground_truth.json"
    if not path.is_file():
        pytest.skip(f"{path} missing; run fun-doc/benchmark/extract_truth.py")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def authored_functions(ground_truth) -> list[str]:
    """The hand-written functions -- the only ones with a known right answer.

    This list IS the library positive control: whatever else the run claims
    as CRT, none of these may be among it.
    """
    return sorted(ground_truth.get("functions", {}))


@pytest.fixture(scope="session")
def baseline_run() -> dict[str, Any] | None:
    """`runs/latest.json`, or None on a machine that has never run it."""
    path = BENCHMARK_DIR / "runs" / "latest.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# the dedicated Ghidra
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def benchmark_ghidra_url(request) -> str:
    return (
        request.config.getoption("--benchmark-ghidra-url")
        or os.environ.get("GHIDRA_BENCHMARK_URL")
        or DEFAULT_BENCHMARK_GHIDRA_URL
    ).rstrip("/")


@pytest.fixture(scope="session")
def require_dedicated_instance(benchmark_ghidra_url: str) -> str:
    """Refuse to run against the operator's working Ghidra.

    Not paranoia: this tier renames functions and saves the program. Landing
    on 8089 would write into whatever project is open, and the damage would
    be indistinguishable from a bad documentation run.
    """
    if benchmark_ghidra_url in FORBIDDEN_URLS:
        pytest.fail(
            f"{benchmark_ghidra_url} is the working Ghidra instance. This tier "
            f"RENAMES FUNCTIONS and SAVES THE PROGRAM; point it at a dedicated "
            f"instance (default {DEFAULT_BENCHMARK_GHIDRA_URL}).",
            pytrace=False,
        )
    return benchmark_ghidra_url


@pytest.fixture(scope="session")
def live_benchmark_ghidra(require_dedicated_instance: str) -> str:
    """Skip unless the dedicated instance is answering."""
    import requests

    url = require_dedicated_instance
    try:
        r = requests.get(f"{url}/check_connection", timeout=10)
        r.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"no dedicated Ghidra at {url} ({exc}). Start one with a throwaway "
            f"project holding an UNDOCUMENTED Benchmark.dll -- see "
            f"tests/benchmark_e2e/README.md."
        )
    return url


@pytest.fixture(scope="session")
def benchmark_program(request, live_benchmark_ghidra: str) -> str:
    return (
        request.config.getoption("--benchmark-program")
        or os.environ.get("FUNDOC_BENCHMARK_PROGRAM")
        or DEFAULT_PROGRAM
    )


@pytest.fixture(scope="session")
def ghidra(live_benchmark_ghidra: str):
    """A thin client bound to the DEDICATED instance.

    `benchmark/ghidra_bridge.py` resolves its URL from `GHIDRA_SERVER_URL` at
    IMPORT time, so it cannot be re-pointed by setting the env var in a
    fixture. This client exists so no call in this tier can accidentally
    inherit the module-level default of 8089.
    """
    import requests

    class Client:
        def __init__(self, base: str):
            self.base = base
            self.session = requests.Session()

        def get(self, path: str, **params) -> Any:
            r = self.session.get(
                f"{self.base}{path}",
                params={k: v for k, v in params.items() if v is not None},
                timeout=120,
            )
            r.raise_for_status()
            try:
                return r.json()
            except ValueError:
                return r.text

        def post(self, path: str, body: dict | None = None, **params) -> Any:
            r = self.session.post(
                f"{self.base}{path}",
                json=body or {},
                params={k: v for k, v in params.items() if v is not None},
                timeout=300,
            )
            r.raise_for_status()
            try:
                return r.json()
            except ValueError:
                return r.text

    return Client(live_benchmark_ghidra)


# --------------------------------------------------------------------------
# sandboxed fun-doc state
# --------------------------------------------------------------------------


@pytest.fixture
def fundoc_sandbox(tmp_path: Path, monkeypatch) -> Path:
    """Redirect every fun-doc state write into tmp_path.

    `invoke_fundoc.py` already monkeypatches STATE_FILE / PRIORITY_QUEUE_FILE
    per invocation; this is the belt to that braces, and it also covers the
    SQL store, which `invoke_fundoc` does not redirect.
    """
    root = tmp_path / "fundoc"
    (root / "logs").mkdir(parents=True)
    (root / "state.json").write_text(json.dumps({"functions": {}, "meta": {}}), encoding="utf-8")
    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{(root / 'state.db').as_posix()}")
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.delenv("RE_KB_ARCHIVE_URL", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_ARCHIVE_URL", raising=False)
    return root
