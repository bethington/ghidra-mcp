"""Offline tests for the canonical exclusion vocabulary -- no Ghidra, no network.

Two invariants carry the weight:

  * NOBODY RE-DECLARES THE SET. Six modules each held their own literal copy and
    two had already drifted (conf_ladder was missing LIB_MATH and LIB_UNKNOWN, so
    a function carrying either counted as in-scope for conformance while every
    other panel counted it as library). A seventh tag must land in one place.
  * PROOF AND INFERENCE STAY APART. SCOPE_EXCLUDED excludes exactly as a LIB_*
    tag does, but must never be reported, stored, or queried AS one.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
FUN_DOC = _ROOT / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

scope_tags = pytest.importorskip("scope_tags")
st = scope_tags


# --------------------------------------------------------------------------
# the vocabulary itself
# --------------------------------------------------------------------------

class TestTheSets:
    def test_known_tags_are_the_six_lanes_emit(self):
        assert set(st.KNOWN_LIB_TAGS) == {
            "LIB_CRT", "LIB_MSVC_EH", "LIB_SECURITY", "LIB_MATH", "LIB_MSVC",
            "LIB_UNKNOWN"}

    def test_inference_is_not_a_lib_tag(self):
        """A LIB_* tag is a claim backed by a matched artifact. An inference must
        not be able to forge one."""
        assert st.SCOPE_EXCLUDED not in st.KNOWN_LIB_TAGS
        assert not st.SCOPE_EXCLUDED.startswith("LIB_")

    def test_excluding_is_proof_plus_inference(self):
        assert set(st.ALL_EXCLUDING_TAGS) == set(st.KNOWN_LIB_TAGS) | set(st.INFERRED_TAGS)

    def test_out_of_scope_adds_the_structural_tags(self):
        assert set(st.OUT_OF_SCOPE_TAGS) == set(st.ALL_EXCLUDING_TAGS) | {
            "STUB", "THUNK", "EXTERNAL"}

    def test_no_tag_is_in_two_families(self):
        fams = [set(st.KNOWN_LIB_TAGS), set(st.INFERRED_TAGS),
                set(st.STRUCTURAL_TAGS)]
        for i, a in enumerate(fams):
            for b in fams[i + 1:]:
                assert not (a & b), f"tag in two families: {a & b}"

    def test_predicates_agree_with_the_sets(self):
        assert st.is_excluding("LIB_CRT") and st.is_excluding(st.SCOPE_EXCLUDED)
        assert not st.is_excluding("STUB")        # structural, not out-of-work
        assert st.is_inference(st.SCOPE_EXCLUDED)
        assert not st.is_inference("LIB_CRT")

    def test_module_has_no_imports_so_the_cheapest_consumer_pays_nothing(self):
        """A script that only needs the vocabulary must not drag in Ghidra HTTP
        helpers or SQLAlchemy. Constants only."""
        tree = ast.parse((FUN_DOC / "scope_tags.py").read_text(encoding="utf-8"))
        imports = [n for n in ast.walk(tree)
                   if isinstance(n, (ast.Import, ast.ImportFrom))]
        names = []
        for n in imports:
            if isinstance(n, ast.ImportFrom):
                names.append(n.module or "")
            else:
                names.extend(a.name for a in n.names)
        assert [x for x in names if x != "__future__"] == [], names


# --------------------------------------------------------------------------
# nobody re-declares it
# --------------------------------------------------------------------------

def _py_sources():
    for base in (FUN_DOC, FUN_DOC / "scripts", FUN_DOC / "storage"):
        for p in sorted(base.glob("*.py")):
            if p.name == "scope_tags.py":
                continue
            if ".venv" in str(p):
                continue
            yield p


class TestNoRedeclaration:
    """A literal collection holding TWO OR MORE LIB_* strings is a second copy of
    this vocabulary. One literal on its own is a single-tag write (`{"tags":
    "LIB_CRT"}`), which is fine and common."""

    @staticmethod
    def _tag_set_literals(tree):
        """Literal collections holding >=2 LIB_* strings, as [(lineno, tags)]."""
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                continue
            libs = [e.value for e in node.elts
                    if isinstance(e, ast.Constant)
                    and isinstance(e.value, str)
                    and e.value.startswith("LIB_")]
            if len(libs) >= 2:
                out.append((node.lineno, libs))
        return out

    def test_the_detector_actually_detects(self):
        """Guard against a vacuous pass. A scan that visits nothing, or a matcher
        that matches nothing, reports a clean repo either way -- which is the
        wired-to-nothing shape this suite is meant to catch, not commit."""
        assert len(list(_py_sources())) > 50, "the source scan found almost nothing"
        planted = ast.parse('LIB_TAGS = ("LIB_CRT", "LIB_MSVC_EH")\n')
        assert self._tag_set_literals(planted), "the matcher cannot see a re-declaration"
        assert not self._tag_set_literals(
            ast.parse('post({"tags": "LIB_CRT"})\n')), \
            "a single-tag write is not a re-declaration and must not be flagged"

    def test_no_module_declares_its_own_tag_set(self):
        offenders = []
        for path in _py_sources():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:                       # not ours to police
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                    continue
                libs = [e.value for e in node.elts
                        if isinstance(e, ast.Constant)
                        and isinstance(e.value, str)
                        and e.value.startswith("LIB_")]
                if len(libs) >= 2:
                    offenders.append(f"{path.name}:{node.lineno} {libs}")
        assert not offenders, (
            "these modules re-declare the exclusion vocabulary instead of "
            "importing scope_tags:\n  " + "\n  ".join(offenders))

    @pytest.mark.parametrize("module,attr", [
        ("conformance_dashboard", "LIB_TAGS"),
        ("conformance_dashboard", "EXCLUDE_TAGS"),
        ("conf_ladder", "OUT_OF_SCOPE_TAGS"),
        ("library_scope", "KNOWN_LIB_TAGS"),
        ("scope_graph", "ALL_EXCLUDING_TAGS"),
    ])
    def test_consumers_expose_the_canonical_values(self, module, attr):
        mod = pytest.importorskip(module)
        got = set(getattr(mod, attr))
        canon = {
            "LIB_TAGS": set(st.KNOWN_LIB_TAGS),
            "KNOWN_LIB_TAGS": set(st.KNOWN_LIB_TAGS),
            "EXCLUDE_TAGS": set(st.OUT_OF_SCOPE_TAGS),
            "OUT_OF_SCOPE_TAGS": set(st.OUT_OF_SCOPE_TAGS),
            "ALL_EXCLUDING_TAGS": set(st.ALL_EXCLUDING_TAGS),
        }[attr]
        assert got == canon

    def test_conf_ladder_drift_is_fixed(self):
        """The measured drift: conf_ladder's local literal lacked LIB_MATH and
        LIB_UNKNOWN, so those functions counted as in-scope for conformance while
        every other panel counted them as library."""
        cl = pytest.importorskip("conf_ladder")
        assert "LIB_MATH" in cl.OUT_OF_SCOPE_TAGS
        assert "LIB_UNKNOWN" in cl.OUT_OF_SCOPE_TAGS

    def test_the_inference_tag_reaches_every_excluding_consumer(self):
        """Wiring the sweep to write a tag nobody reads is the failure mode this
        whole change exists to close."""
        cd = pytest.importorskip("conformance_dashboard")
        cl = pytest.importorskip("conf_ladder")
        assert st.SCOPE_EXCLUDED in cd.EXCLUDE_TAGS
        assert st.SCOPE_EXCLUDED in cl.OUT_OF_SCOPE_TAGS
        # ...and NOT into the identified-library set, on either side.
        assert st.SCOPE_EXCLUDED not in cd.LIB_TAGS


# --------------------------------------------------------------------------
# the two fun_doc readers stay separate
# --------------------------------------------------------------------------

class TestFunDocReaders:
    def test_lib_and_inference_readers_use_different_sets(self):
        fd = pytest.importorskip("fun_doc")
        assert set(fd._ASSESS_LIB_TAGS) == set(st.KNOWN_LIB_TAGS)
        assert set(fd._ASSESS_INFERRED_TAGS) == set(st.INFERRED_TAGS)
        assert st.SCOPE_EXCLUDED not in fd._ASSESS_LIB_TAGS, (
            "_lib_tagged_addrs feeds the `library_code` column, whose name "
            "asserts a lane matched an artifact. The inference has its own "
            "reader and its own column.")

    def test_both_readers_exist(self):
        fd = pytest.importorskip("fun_doc")
        assert callable(fd._lib_tagged_addrs)
        assert callable(fd._scope_excluded_addrs)

    def test_lib_reader_never_queries_the_inference_tag(self, monkeypatch):
        fd = pytest.importorskip("fun_doc")
        asked = []
        monkeypatch.setattr(fd, "_assess_tag_addrs",
                            lambda t, p: asked.append(t) or set())
        fd._lib_tagged_addrs("/x/A.dll")
        assert st.SCOPE_EXCLUDED not in asked

    def test_inference_reader_never_queries_a_lib_tag(self, monkeypatch):
        fd = pytest.importorskip("fun_doc")
        asked = []
        monkeypatch.setattr(fd, "_assess_tag_addrs",
                            lambda t, p: asked.append(t) or set())
        fd._scope_excluded_addrs("/x/A.dll")
        assert asked == [st.SCOPE_EXCLUDED]
