"""Failures must reach the caller, not just the console.

Both defects here were found by the value ledger's `result_ignored` verdict --
"every caller throws the answer away" -- which is exactly the shape that hides a
dropped failure signal. Same family as `save_program_checked` and
`notify.send()`, and the reason `feedback_loud_failures` exists.

    --assess          `run_assess_pass` / `run_assess_globals_pass` return an
                      EXIT CODE (0 ok / 1 failed); that is what their `return 1`
                      branches mean and what the existing tests assert. The CLI
                      dropped both and `main()` was invoked without `sys.exit`,
                      so `--assess` exited 0 no matter what happened -- and
                      `web.py` SHELLS OUT to it, so a failed assess reported
                      success to the dashboard.

    orphan reaper     `reap_orphans()` returns `(reaped, failed)`. `failed`
                      means a wedged provider child SURVIVED the kill and is
                      still holding its resources -- the one outcome an operator
                      must see. It was the only silent path, while the
                      surrounding exception handler printed diligently.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

_SRC = (_FUNDOC / "fun_doc.py").read_text(encoding="utf-8", errors="replace")


def _main_node():
    tree = ast.parse(_SRC)
    return next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "main")


def test_main_result_reaches_the_process_exit_code():
    """Without this, any code main() computes is discarded at the door."""
    assert "sys.exit(main() or 0)" in _SRC, (
        "fun_doc.py must exit with main()'s return value; calling main() bare "
        "throws away every failure code it computes")


def test_main_only_ever_returns_none_or_an_int():
    """`sys.exit()` prints a non-int and exits 1, so a stray `return {...}`
    would turn a successful run into a failure with garbage on stderr. This is
    the safety condition for the line above."""
    main = _main_node()
    nested = {id(x)
              for d in ast.walk(main)
              if isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef)) and d is not main
              for x in ast.walk(d)}
    bad = []
    for n in ast.walk(main):
        if not isinstance(n, ast.Return) or id(n) in nested:
            continue
        if n.value is None:
            continue
        if isinstance(n.value, ast.Constant) and isinstance(n.value.value, int):
            continue
        if isinstance(n.value, ast.Name):        # `return rc`
            continue
        bad.append((n.lineno, ast.unparse(n.value)[:60]))
    assert not bad, f"main() returns a non-int/non-None value: {bad}"


def test_the_assess_branch_keeps_both_return_codes():
    """A pass that fails must not be masked by the other one succeeding."""
    i = _SRC.find("if args.assess:")
    assert i > 0
    branch = _SRC[i:i + 1600]
    assert "rc |= run_assess_pass(" in branch
    assert "rc |= run_assess_globals_pass(" in branch
    assert "return rc" in branch


def test_the_orphan_reaper_reports_survivors():
    """A kill that failed is the finding, not a detail."""
    # A substring search cannot tell a bare call from an assignment -- the
    # assignment CONTAINS the call text. Ask the AST whether the call is used
    # as a statement (its result thrown away) instead.
    bare = [n.lineno for n in ast.walk(ast.parse(_SRC))
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Attribute)
            and n.value.func.attr == "reap_orphans"]
    assert not bare, f"reap_orphans() result is discarded at line(s) {bare}"
    j = _SRC.find("_reaped, _failed = orphan_reaper.reap_orphans()")
    assert j > 0, "reap_orphans() must be unpacked so failures can be reported"
    near = _SRC[j:j + 700]
    assert "if _failed:" in near
    assert "SURVIVED" in near, "the survivor report must be unmistakable in a log"


@pytest.mark.parametrize("fn", ["run_assess_pass", "run_assess_globals_pass"])
def test_the_assess_passes_still_return_a_code(fn):
    """If these stop returning 0/1 the wiring above becomes a no-op -- the
    'mechanism wired to nothing' shape this repo keeps rediscovering."""
    tree = ast.parse(_SRC)
    node = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == fn)
    consts = {r.value.value for r in ast.walk(node)
              if isinstance(r, ast.Return) and isinstance(r.value, ast.Constant)
              and isinstance(r.value.value, int)}
    assert 1 in consts, f"{fn} no longer returns a failure code"
    assert 0 in consts, f"{fn} no longer returns a success code"
