"""Find code that does not serve the end it was written for.

The original brief asked for a way to identify code that does not contribute to
getting functions to CONF_BATTLETESTED, so it can be removed. This session
supplied eight worked specimens, and they are NOT what "dead code" usually
means. Every one was written, tested, documented, and reachable. What they had
in common is subtler and worse:

    conf_ladder.low_frequency_status   called from NOWHERE but its own tests
    port_pipeline outbuf_leaf          reachable, but its gate needed
                                       `callee_bodies` that no caller ever
                                       passed -- unsatisfiable in production
    fun_doc._callee_readiness          called constantly, returned 1.0 for 83%
                                       of the corpus: an output that never
                                       varied decided nothing
    the /save_program try/except        executed on every save, could not fire,
                                       because ghidra_post never raises
    subprocess timeout cap             set, never reached
    ground-truth rule                  written down, never applied

A coverage profiler calls four of those "used". They ran. They just never
changed an outcome. So the ledger measures three separable things:

    REACHED      is it called at all, outside its own tests?
    VARIES       does its output ever differ between calls?
    CONSUMED     does anything act on the result?

Code that fails any one of them is a candidate for deletion or repair, and
WHICH one it fails says which. Never-reached is dead. Reached-but-constant is a
gate with no input -- usually a bug, not waste. Varies-but-ignored is a signal
nobody is listening to.

This module implements the STATIC half, which is what the specimens are mostly
detectable by, and it is deliberately a REPORT: "only tests call this" is
evidence for a human decision, never a licence to delete. A function can be
legitimately test-only (a debugging aid, a documented escape hatch), and the
report says so rather than guessing.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set


@dataclass
class Symbol:
    name: str
    module: str
    lineno: int
    is_private: bool = False
    doc: str = ""


@dataclass
class LedgerRow:
    symbol: Symbol
    prod_refs: int = 0
    test_refs: int = 0
    discarded_calls: int = 0
    returns_value: bool = True

    @property
    def verdict(self) -> str:
        if self.prod_refs == 0 and self.test_refs == 0:
            return "unreferenced"          # nothing calls it at all
        if self.prod_refs == 0:
            return "test_only"             # the measured shape
        if self.returns_value and self.discarded_calls == self.prod_refs:
            return "result_ignored"        # every caller throws the answer away
        return "load_bearing"

    def to_json(self) -> dict:
        return {"name": self.symbol.name, "module": self.symbol.module,
                "line": self.symbol.lineno, "verdict": self.verdict,
                "prod_refs": self.prod_refs, "test_refs": self.test_refs,
                "discarded_calls": self.discarded_calls}


# Directories that are never OUR code. Excluded by default because a sweep that
# includes them is not merely slow -- it drowns the real findings: pointed at a
# tree containing .venv, 3,051 of 3,184 "modules" were third-party and produced
# 2,755 meaningless `unreferenced` rows.
DEFAULT_EXCLUDES = (".venv", "venv", "site-packages", "__pycache__", ".git",
                    "node_modules", "build", "dist", "vendored", ".tox")


def iter_source_files(root, excludes=DEFAULT_EXCLUDES, tests=False):
    """Our own .py files under `root`, third-party trees excluded.

    `tests=True` returns the test files instead, so callers cannot accidentally
    count a test as production code -- which would make every test-only symbol
    look load-bearing and hide the exact shape this ledger exists to find.
    """
    root = Path(root)
    out = []
    for p in root.rglob("*.py"):
        parts = set(p.parts)
        if parts & set(excludes):
            continue
        is_test = p.name.startswith("test_") or "tests" in parts
        if is_test == bool(tests):
            out.append(p)
    return sorted(out)


def _module_name(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name


def collect_symbols(source: str, module: str) -> List[Symbol]:
    """Top-level and class-level function definitions in a module."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    out: List[Symbol] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(Symbol(name=node.name, module=module, lineno=node.lineno,
                              is_private=node.name.startswith("_"),
                              doc=(ast.get_docstring(node) or "")[:200]))
    return out


def returns_a_value(source: str, name: str) -> bool:
    """Does this function ever return something other than None?

    A procedure whose result nobody uses is not a finding; a QUERY whose result
    nobody uses is. Distinguishing them is what keeps `result_ignored` from
    flagging every void helper in the codebase.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    if not (isinstance(sub.value, ast.Constant) and sub.value.value is None):
                        return True
            return False
    return False


def returns_map(source: str) -> Dict[str, bool]:
    """{function name -> does it ever return a non-None value}, one parse."""
    out: Dict[str, bool] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        rv = False
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and sub.value is not None:
                if not (isinstance(sub.value, ast.Constant) and sub.value.value is None):
                    rv = True
                    break
        out[node.name] = rv
    return out


def count_references(source: str, names: Set[str]) -> Dict[str, int]:
    """How many times each name is REFERENCED (called, passed, aliased).

    Attribute access counts: `fd.save_program_checked(...)` is a reference to
    `save_program_checked`. Missing that would have called half this codebase
    dead, since cross-module calls are module-qualified by convention.
    """
    counts = {n: 0 for n in names}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return counts
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in counts:
            counts[node.id] += 1
        elif isinstance(node, ast.Attribute) and node.attr in counts:
            counts[node.attr] += 1
    return counts


def count_self_references(source: str, names: Set[str]) -> Dict[str, int]:
    """References to a function from INSIDE its own body (i.e. recursion).

    Removed from the totals so a recursive function nobody else calls is still
    reported unreferenced -- which is the honest answer, since recursion is not
    a consumer.
    """
    counts = {n: 0 for n in names}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return counts
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in counts:
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id == node.name:
                counts[node.name] += 1
            elif isinstance(sub, ast.Attribute) and sub.attr == node.name:
                counts[node.name] += 1
    return counts


def count_discarded_calls(source: str, names: Set[str]) -> Dict[str, int]:
    """Calls whose return value is thrown away (a bare expression statement).

    This is the `ghidra_post("/save_program", ...)` shape: the call runs, the
    answer is discarded, and a failure reported in that answer cannot be seen.
    """
    counts = {n: 0 for n in names}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return counts
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        fn = node.value.func
        nm = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else None)
        if nm in counts:
            counts[nm] += 1
    return counts


def _is_test(path: Path) -> bool:
    p = str(path).replace("\\", "/")
    return "/tests/" in p or path.name.startswith("test_")


def build_ledger(prod_files: Sequence[Path], test_files: Sequence[Path],
                 root: Optional[Path] = None,
                 skip_private: bool = False) -> List[LedgerRow]:
    """Cross-reference definitions against every reference in the tree."""
    root = root or Path(".")
    sources: Dict[Path, str] = {}
    rows: Dict[str, LedgerRow] = {}

    for f in list(prod_files) + list(test_files):
        try:
            sources[f] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            sources[f] = ""

    for f in prod_files:
        for sym in collect_symbols(sources.get(f, ""), _module_name(f, root)):
            if skip_private and sym.is_private:
                continue
            # A name defined in two modules cannot be attributed by AST alone;
            # keep the first and let the report show the module.
            rows.setdefault(sym.name, LedgerRow(symbol=sym))

    names = set(rows)
    for f in prod_files:
        src = sources.get(f, "")
        # A `def` does NOT produce a Name node, so there is nothing to subtract
        # for the definition itself -- assuming otherwise cost every function
        # one legitimate reference and called used code unreferenced.
        #
        # Self-references DO need removing, or a recursive function that nobody
        # else calls looks used. They are counted from the function's own body.
        selfrefs = count_self_references(src, names)
        for n, c in count_references(src, names).items():
            rows[n].prod_refs += c - selfrefs.get(n, 0)
        for n, c in count_discarded_calls(src, names).items():
            rows[n].discarded_calls += c
    for f in test_files:
        for n, c in count_references(sources.get(f, ""), names).items():
            rows[n].test_refs += c

    # returns_value for EVERY function in one pass per module. The first
    # version called returns_a_value(src, name) per symbol, and each call
    # re-parsed the whole module -- on fun_doc.py (~15K lines, hundreds of
    # functions) that is hundreds of full AST parses of a large file, and the
    # sweep did not finish in ten minutes.
    returns: Dict[str, bool] = {}
    for f in prod_files:
        for name, rv in returns_map(sources.get(f, "")).items():
            returns.setdefault(name, rv)
    for n, row in rows.items():
        row.returns_value = returns.get(n, False)
        row.prod_refs = max(0, row.prod_refs)
    return list(rows.values())


def summarise(rows: Sequence[LedgerRow]) -> dict:
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return {"symbols": len(rows), "verdicts": counts,
            "candidates": [r.to_json() for r in rows
                           if r.verdict in ("unreferenced", "test_only",
                                            "result_ignored")]}
