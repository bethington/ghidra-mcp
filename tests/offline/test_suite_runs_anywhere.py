"""The suite must be collectable on a contributor's machine, not just ours.

Found while wiring up the offline tier (#112): `tests/endpoints.json` contains
non-ASCII characters, and four places read it with a bare ``open()``. On any
Windows install whose Python default encoding is cp1252 -- the default -- that
raises ``UnicodeDecodeError`` at *collection* time, so

    pytest tests/

aborts with ``Interrupted: 1 error during collection`` before running a single
test. One of the four is the session-scoped ``endpoints`` fixture in
``tests/conftest.py``, so the blast radius is the whole tree, not one file.

CI never saw it: every Python job runs on ubuntu, where the default encoding is
UTF-8. This is the same class of gap as issue #112 itself -- the suite is
unrunnable for the contributor and green for the maintainer -- so the guard
lives here.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
CATALOG = TESTS_ROOT / "endpoints.json"


def _text_reads_without_encoding(source: str) -> list[str]:
    """Calls to open()/read_text() that leave the encoding to the platform.

    Binary reads are fine -- they have no encoding to get wrong.
    """
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if name not in ("open", "read_text"):
            continue
        if any(kw.arg == "encoding" for kw in node.keywords):
            continue
        if name == "open":
            mode = None
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if mode and "b" in str(mode):
                continue
        offenders.append(f"line {node.lineno}: {name}()")
    return offenders


def test_the_endpoint_catalog_is_not_pure_ascii():
    """Guards the guard.

    If the catalog ever became pure ASCII the encoding bug would stop
    reproducing, and the tests below would start passing for the wrong reason.
    """
    raw = CATALOG.read_bytes()
    assert any(b > 0x7F for b in raw), (
        "tests/endpoints.json is now pure ASCII, so a bare open() no longer "
        "fails on cp1252. The encoding guard below is still correct, but it is "
        "no longer load-bearing -- decide deliberately before relaxing it."
    )


def test_the_catalog_is_utf8():
    json.loads(CATALOG.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "relative_path",
    [
        "conftest.py",
        "run_tests.py",
        "integration/test_all_endpoints.py",
    ],
)
def test_catalog_readers_declare_an_encoding(relative_path):
    """These three read tests/endpoints.json and are collected on every run."""
    path = TESTS_ROOT / relative_path
    offenders = _text_reads_without_encoding(path.read_text(encoding="utf-8"))
    assert not offenders, (
        f"{relative_path} opens a text file without encoding=: {offenders}. "
        f"tests/endpoints.json is UTF-8 and this file is imported during "
        f"collection, so on a cp1252 Windows default the whole suite aborts "
        f"before running anything."
    )
