"""The value ledger: finding code that does not serve the end it was written for.

The original brief asked for a way to identify code that does not contribute to
getting functions to CONF_BATTLETESTED. This session supplied eight worked
specimens, and none of them is what "dead code" normally means -- every one was
written, tested, documented, and reachable:

    conf_ladder.low_frequency_status   called from NOWHERE but its own tests
    port_pipeline outbuf_leaf          gate needed `callee_bodies` no caller
                                       ever passed -- unsatisfiable in prod
    fun_doc._callee_readiness          returned 1.0 for 83% of the corpus: an
                                       output that never varied decided nothing
    the /save_program try/except       ran on every save, could not fire
    subprocess timeout cap             set, never reached

A coverage profiler calls four of those "used". They ran; they just never
changed an outcome. Hence three separable questions -- REACHED, VARIES,
CONSUMED -- because WHICH one fails says whether the code is dead, is a gate
with no input, or is a signal nobody listens to.

Report-only by construction: "only tests call this" is evidence for a human,
never a licence to delete. Some functions are legitimately test-only.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

vl = pytest.importorskip("value_ledger")


def _write(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return p


# --- the measured shape: called only by its own tests ------------------------

def test_a_function_only_tests_call_is_flagged(tmp_path):
    """low_frequency_status, exactly: defined, tested, called from nowhere."""
    prod = _write(tmp_path, "mod.py", "def low_frequency_status(a):\n    return a\n")
    test = _write(tmp_path, "test_mod.py",
                  "import mod\ndef test_x():\n    assert mod.low_frequency_status(1) == 1\n")
    rows = vl.build_ledger([prod], [test], root=tmp_path)
    row = next(r for r in rows if r.symbol.name == "low_frequency_status")
    assert row.verdict == "test_only"
    assert row.test_refs >= 1 and row.prod_refs == 0


def test_a_genuinely_used_function_is_load_bearing(tmp_path):
    prod = _write(tmp_path, "mod.py",
                  "def helper(a):\n    return a + 1\n\n"
                  "def caller(a):\n    return helper(a) * 2\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "helper").verdict == "load_bearing"


def test_nothing_at_all_references_it(tmp_path):
    prod = _write(tmp_path, "mod.py", "def orphan():\n    return 1\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "orphan").verdict == "unreferenced"


def test_self_reference_does_not_count_as_use(tmp_path):
    """A recursive function that nobody else calls is still unreferenced."""
    prod = _write(tmp_path, "mod.py",
                  "def recurse(n):\n    return 1 if n <= 0 else recurse(n - 1)\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "recurse").verdict == "unreferenced"


# --- cross-module calls ------------------------------------------------------

def test_module_qualified_calls_count(tmp_path):
    """Cross-module calls here are module-qualified by convention
    (`transport.do_request`). Missing attribute access would call half the
    codebase dead."""
    a = _write(tmp_path, "a.py", "def do_request():\n    return 1\n")
    b = _write(tmp_path, "b.py", "import a\ndef go():\n    return a.do_request()\n")
    rows = vl.build_ledger([a, b], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "do_request").verdict == "load_bearing"


# --- the discarded-result shape ---------------------------------------------

def test_a_query_whose_result_every_caller_discards(tmp_path):
    """The /save_program shape: the call runs, the answer is thrown away, and a
    failure reported in that answer cannot be seen."""
    prod = _write(tmp_path, "mod.py",
                  "def save():\n    return False\n\n"
                  "def run():\n    save()\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "save").verdict == "result_ignored"


def test_a_procedure_is_not_flagged_for_a_discarded_result(tmp_path):
    """A void helper's callers necessarily discard nothing. Flagging those
    would bury the real findings under every logging call in the tree."""
    prod = _write(tmp_path, "mod.py",
                  "def emit(msg):\n    print(msg)\n\n"
                  "def run():\n    emit('x')\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "emit").verdict == "load_bearing"


def test_one_caller_using_the_result_clears_it(tmp_path):
    prod = _write(tmp_path, "mod.py",
                  "def save():\n    return False\n\n"
                  "def a():\n    save()\n\n"
                  "def b():\n    ok = save()\n    return ok\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "save").verdict == "load_bearing"


# --- returns_a_value ---------------------------------------------------------

@pytest.mark.parametrize("src,expected", [
    ("def f():\n    return 1\n", True),
    ("def f():\n    return\n", False),
    ("def f():\n    return None\n", False),
    ("def f():\n    print(1)\n", False),
])
def test_returns_a_value(src, expected):
    assert vl.returns_a_value(src, "f") is expected


# --- robustness --------------------------------------------------------------

def test_a_syntax_error_does_not_stop_the_sweep(tmp_path):
    bad = _write(tmp_path, "bad.py", "def broken(:\n")
    good = _write(tmp_path, "good.py", "def fine():\n    return 1\n")
    rows = vl.build_ledger([bad, good], [], root=tmp_path)
    assert any(r.symbol.name == "fine" for r in rows)


def test_an_unreadable_file_is_skipped(tmp_path):
    rows = vl.build_ledger([tmp_path / "missing.py"], [], root=tmp_path)
    assert rows == []


# --- the report is a report --------------------------------------------------

def test_summary_lists_candidates_not_deletions(tmp_path):
    prod = _write(tmp_path, "mod.py", "def orphan():\n    return 1\n")
    s = vl.summarise(vl.build_ledger([prod], [], root=tmp_path))
    assert s["symbols"] == 1
    assert s["candidates"][0]["verdict"] == "unreferenced"


def test_the_module_deletes_nothing():
    """Evidence for a human decision, never a licence. A function can be
    legitimately test-only -- a debugging aid, a documented escape hatch."""
    src = (_FUNDOC / "value_ledger.py").read_text(encoding="utf-8")
    for forbidden in ("os.remove", "unlink", "shutil.rm", "write_text", "rmtree"):
        assert forbidden not in src, forbidden


# --- scan scope --------------------------------------------------------------
# MEASURED: pointed at a tree containing .venv, 3,051 of 3,184 "modules" were
# third-party and produced 2,755 meaningless `unreferenced` rows. A sweep that
# includes vendored code is not just slow, it drowns the real findings.

def test_third_party_trees_are_excluded(tmp_path):
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "dep.py").write_text("def x(): return 1\n", encoding="utf-8")
    (tmp_path / "mine.py").write_text("def y(): return 1\n", encoding="utf-8")
    files = vl.iter_source_files(tmp_path)
    assert [f.name for f in files] == ["mine.py"]


def test_tests_are_separated_from_production(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (tmp_path / "mine.py").write_text("def y(): return 1\n", encoding="utf-8")
    prod = vl.iter_source_files(tmp_path)
    tests = vl.iter_source_files(tmp_path, tests=True)
    assert [f.name for f in prod] == ["mine.py"]
    assert [f.name for f in tests] == ["test_a.py"]


def test_counting_a_test_as_production_would_hide_the_finding(tmp_path):
    """If tests were swept in as production, every test-only symbol would look
    load-bearing -- erasing the exact shape this ledger exists to find."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "mod.py").write_text("def only_tested(): return 1\n", encoding="utf-8")
    (tmp_path / "tests" / "test_mod.py").write_text(
        "import mod\ndef test_x(): assert mod.only_tested() == 1\n", encoding="utf-8")
    prod = vl.iter_source_files(tmp_path)
    tests = vl.iter_source_files(tmp_path, tests=True)
    rows = vl.build_ledger(prod, tests, root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "only_tested").verdict == "test_only"


# --- failure signalled by exception ------------------------------------------
# TRIAGE RESULT 2026-08-06. The first result_ignored list was dominated by one
# kind of false positive: functions whose failure path is an EXCEPTION and whose
# return value is merely informational -- library_scope._checked_post (raises
# WriteRejected; detecting failure is its entire purpose), repository's
# upsert_function and record_run (return a row id; SQLAlchemy raises).
#
# A discarded return only hides a failure when the return value IS the failure
# signal, which was exactly ghidra_post's shape in the /save_program bug. An
# instrument whose findings are mostly noise gets ignored, which is the same
# fate as not having it.

def test_a_function_that_raises_is_not_result_ignored(tmp_path):
    prod = _write(tmp_path, "mod.py",
                  "def checked_post(x):\n"
                  "    if x:\n        raise ValueError('rejected')\n"
                  "    return {'ok': True}\n\n"
                  "def run():\n    checked_post(1)\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "checked_post").verdict == "load_bearing"


def test_a_status_returner_that_never_raises_is_still_flagged(tmp_path):
    """The /save_program shape survives the refinement: the return value IS the
    failure signal and every caller discards it."""
    prod = _write(tmp_path, "mod.py",
                  "def save():\n    return False\n\n"
                  "def run():\n    save()\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "save").verdict == "result_ignored"


def test_raises_is_recorded_on_the_row(tmp_path):
    prod = _write(tmp_path, "mod.py",
                  "def a():\n    raise IOError('x')\n\n"
                  "def b():\n    return 1\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    by = {r.symbol.name: r for r in rows}
    assert by["a"].raises is True and by["b"].raises is False


# --- decorator-registered entry points ---------------------------------------
# MEASURED 2026-08-06: 72 of the first 95 `unreferenced` findings were Flask
# routes and SocketIO handlers. They are called by a framework, never by name,
# so a reference count of zero is exactly what a HEALTHY entry point looks like.
# Reporting them as dead code buries the real findings under three times their
# number, and an instrument whose output is mostly noise gets ignored -- the
# same fate as not having one.

def test_a_flask_route_is_an_entry_point_not_dead_code(tmp_path):
    prod = _write(tmp_path, "web.py",
                  "app = object()\n\n"
                  "@app.route('/api/x')\ndef api_x():\n    return {}\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "api_x").verdict == "entry_point"


def test_a_socketio_handler_is_an_entry_point(tmp_path):
    prod = _write(tmp_path, "web.py",
                  "socketio = object()\n\n"
                  "@socketio.on('connect')\ndef handle_connect():\n    return None\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "handle_connect").verdict == "entry_point"


def test_a_plain_name_decorator_does_not_register(tmp_path):
    """`@property` and `@staticmethod` MODIFY a function; they do not hand it to
    a framework. Treating them as entry points would hide genuinely dead code."""
    prod = _write(tmp_path, "mod.py",
                  "def memo(f):\n    return f\n\n"
                  "@memo\ndef orphan():\n    return 1\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "orphan").verdict == "unreferenced"


def test_an_undecorated_orphan_is_still_reported(tmp_path):
    prod = _write(tmp_path, "mod.py", "def orphan():\n    return 1\n")
    rows = vl.build_ledger([prod], [], root=tmp_path)
    assert next(r for r in rows if r.symbol.name == "orphan").verdict == "unreferenced"
