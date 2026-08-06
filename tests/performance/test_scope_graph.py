"""Offline tests for fun-doc/scope_graph.py -- no Ghidra, no network.

The headline invariant is the CASCADE regression. Everything else is guard rails
around it.
"""

from __future__ import annotations

import os
import sys

import pytest

FUN_DOC = os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "fun-doc")
if FUN_DOC not in sys.path:
    sys.path.insert(0, FUN_DOC)

scope_graph = pytest.importorskip("scope_graph")
sg = scope_graph
ls = sg.ls


# --------------------------------------------------------------------------
# the CRT -> author boundary
# --------------------------------------------------------------------------

class TestCrtHandoff:
    @pytest.mark.parametrize("name", [
        "?dllmain_dispatch@@YAHQAUHINSTANCE__@@KQAX@Z",
        "?dllmain_raw@@YGHQAUHINSTANCE__@@KQAX@Z",
        "__initterm", "__initterm_e", "__execute_onexit_table",
        "__scrt_common_main_seh", "_mainCRTStartup", "_WinMainCRTStartup",
    ])
    def test_real_handoffs_recognised(self, name):
        assert sg._is_crt_handoff(name) is True

    @pytest.mark.parametrize("name", [
        "___scrt_dllmain_after_initialize_c",
        "___scrt_dllmain_crt_thread_attach",
        "___scrt_dllmain_crt_thread_detach",
        "___scrt_dllmain_exception_filter",
        "CRT_DllMainProcessAttach", "CRT_DllMainProcessDetach",
        "?dllmain_crt_dispatch@@YAHQAUHINSTANCE__@@KQAX@Z",
    ])
    def test_crt_internals_are_not_handoffs(self, name):
        """These CONTAIN a handoff token but are plumbing, not a door to user
        code. Treating them as handoffs over-protected 16 CRT functions on
        PD2_EXT -- safe direction, still wrong."""
        assert sg._is_crt_handoff(name) is False

    def test_unrelated_names_are_not_handoffs(self):
        for n in ("_qsort", "GAME_InitCommandLine", "", None):
            assert sg._is_crt_handoff(n) is False


# --------------------------------------------------------------------------
# THE cascade regression
# --------------------------------------------------------------------------

class TestCascadeRegression:
    """PD2_EXT.dll, measured 2026-08-04.

        dllmain_dispatch (LIB)  -> PD2EXT_InstallBootstrapHook
                                -> PD2EXT_InstallGameAndFogHooks
                                -> PD2EXT_RemoveLastPathComponent

    Each authored function's ONLY referrer is the one above it. Without the
    CRT-handoff guard the first is swept, which makes it "library", which
    sweeps the second, which sweeps the third -- three of the binary's four
    authored functions deleted from the conformance target by one wrong verdict
    at the boundary.
    """

    NAMES = {
        "0x10001000": "PD2EXT_LoadModAfterGameDataInit",
        "0x10001050": "PD2EXT_RemoveLastPathComponent",
        "0x10001080": "PD2EXT_InstallGameAndFogHooks",
        "0x100011c0": "PD2EXT_InstallBootstrapHook",
        "0x1000145a": "?dllmain_dispatch@@YAHQAUHINSTANCE__@@KQAX@Z",
        "0x10002000": "___scrt_initialize_crt",
    }
    REFERRERS = {
        "0x10001050": {"0x10001080"},
        "0x10001080": {"0x100011c0"},
        "0x100011c0": {"0x1000145a"},
        "0x10002000": {"0x1000145a"},
    }
    LIB = {"0x1000145a", "0x10002000"}

    def _sweep(self, monkeypatch, protect=True):
        monkeypatch.setattr(sg.ls, "_function_ranges", lambda p: [])
        monkeypatch.setattr(sg, "function_referrers",
                            lambda p, a, ranges=None: dict(self.REFERRERS))
        monkeypatch.setattr(sg.ls, "existing_lib_tags", lambda p: set(self.LIB))
        monkeypatch.setattr(sg.ls, "_get", lambda ep, **k: {
            "functions": [{"address": a[2:], "name": n}
                          for a, n in self.NAMES.items()]})
        if not protect:
            monkeypatch.setattr(sg, "protected_addresses",
                                lambda *a, **k: {})
        return sg.sweep_program("/x/PD2_EXT.dll")

    def test_authored_chain_survives(self, monkeypatch):
        rep = self._sweep(monkeypatch)
        swept = {s["name"] for s in rep.swept}
        assert not [n for n in swept if n.startswith("PD2EXT_")], \
            f"authored code was swept: {sorted(swept)}"
        in_scope = {x["name"] for x in rep.in_scope}
        for n in ("PD2EXT_LoadModAfterGameDataInit", "PD2EXT_RemoveLastPathComponent",
                  "PD2EXT_InstallGameAndFogHooks", "PD2EXT_InstallBootstrapHook"):
            assert n in in_scope, f"{n} missing from scope"

    def test_the_boundary_function_is_protected(self, monkeypatch):
        rep = self._sweep(monkeypatch)
        prot = {p["name"]: p["why"] for p in rep.protected}
        assert "PD2EXT_InstallBootstrapHook" in prot
        assert "dllmain_dispatch" in prot["PD2EXT_InstallBootstrapHook"]

    def test_without_the_guard_the_whole_chain_cascades(self, monkeypatch):
        """Pins that the guard is what does the work -- if this ever stops
        cascading, the test above has stopped proving anything."""
        rep = self._sweep(monkeypatch, protect=False)
        swept = {s["name"] for s in rep.swept}
        assert {"PD2EXT_InstallBootstrapHook", "PD2EXT_InstallGameAndFogHooks",
                "PD2EXT_RemoveLastPathComponent"} <= swept

    def test_crt_helper_beside_the_boundary_is_still_swept(self, monkeypatch):
        """The guard must not become a blanket amnesty: a CRT function the
        dispatcher also calls is positively identified, so it stays swept."""
        rep = self._sweep(monkeypatch)
        assert "___scrt_initialize_crt" not in {x["name"] for x in rep.in_scope}


# --------------------------------------------------------------------------
# abstention
# --------------------------------------------------------------------------

class TestAbstention:
    NAMES = {"0x1000": "target", "0x2000": "lib_a", "0x3000": "game_a"}

    def _run(self, monkeypatch, referrers, lib={"0x00002000"}):
        monkeypatch.setattr(sg.ls, "_function_ranges", lambda p: [])
        monkeypatch.setattr(sg, "function_referrers",
                            lambda p, a, ranges=None: referrers)
        monkeypatch.setattr(sg.ls, "existing_lib_tags", lambda p: set(lib))
        monkeypatch.setattr(sg, "protected_addresses", lambda *a, **k: {})
        monkeypatch.setattr(sg.ls, "_get", lambda ep, **k: {
            "functions": [{"address": a[2:], "name": n}
                          for a, n in self.NAMES.items()]})
        rep = sg.sweep_program("/x/A.dll")
        return {s["name"] for s in rep.swept}

    def test_all_library_referrers_is_swept(self, monkeypatch):
        assert "target" in self._run(monkeypatch, {"0x00001000": {"0x00002000"}})

    def test_one_game_referrer_keeps_it(self, monkeypatch):
        assert "target" not in self._run(
            monkeypatch, {"0x00001000": {"0x00002000", "0x00003000"}})

    def test_zero_referrers_keeps_it(self, monkeypatch):
        """Cannot be proven library-owned. 28 of PD2_EXT's 32 survivors are
        exactly this case."""
        assert "target" not in self._run(monkeypatch, {})

    def test_unattributable_referrer_blocks_the_sweep(self, monkeypatch):
        """A reference we cannot resolve to a function might be authored."""
        assert "target" not in self._run(
            monkeypatch, {"0x00001000": {"0x00002000", "?unattributed"}})


# --------------------------------------------------------------------------
# the empty-graph guard
# --------------------------------------------------------------------------

class TestEmptyGraph:
    def test_no_references_raises_rather_than_reporting_a_clean_answer(self, monkeypatch):
        """The original analysis parsed the call graph with the wrong field
        names, dropped all 950 edges, and reported that the authored functions
        "call nothing else in the binary". That read as a finding; it was a bug.
        An empty reference set must be loud."""
        monkeypatch.setattr(sg.ls, "_bulk_xrefs_to", lambda *a, **k: {})
        with pytest.raises(sg.EmptyGraph):
            sg.function_referrers("/x/A.dll", ["0x00001000"], ranges=[])

    def test_message_names_the_program(self, monkeypatch):
        monkeypatch.setattr(sg.ls, "_bulk_xrefs_to", lambda *a, **k: {})
        with pytest.raises(sg.EmptyGraph, match="A.dll"):
            sg.function_referrers("/x/A.dll", ["0x00001000"], ranges=[])


class TestReferrerAttribution:
    def test_sources_resolve_to_containing_function(self, monkeypatch):
        monkeypatch.setattr(sg.ls, "_bulk_xrefs_to",
                            lambda p, a: {"0x00003000": [0x1050, 0x2050]})
        ranges = [(0x1000, 0x1100, "0x00001000"), (0x2000, 0x2100, "0x00002000")]
        got = sg.function_referrers("/x/A.dll", ["0x00003000"], ranges=ranges)
        assert got["0x00003000"] == {"0x00001000", "0x00002000"}

    def test_unresolvable_source_becomes_the_sentinel(self, monkeypatch):
        monkeypatch.setattr(sg.ls, "_bulk_xrefs_to",
                            lambda p, a: {"0x00003000": [0x9999]})
        got = sg.function_referrers("/x/A.dll", ["0x00003000"],
                                    ranges=[(0x1000, 0x1100, "0x00001000")])
        assert got["0x00003000"] == {"?unattributed"}

    def test_self_reference_is_not_a_referrer(self, monkeypatch):
        """Recursion must not make a function its own justification."""
        monkeypatch.setattr(sg.ls, "_bulk_xrefs_to",
                            lambda p, a: {"0x00001000": [0x1050]})
        got = sg.function_referrers("/x/A.dll", ["0x00001000"],
                                    ranges=[(0x1000, 0x1100, "0x00001000")])
        assert got.get("0x00001000", set()) == set()


# --------------------------------------------------------------------------
# marking
# --------------------------------------------------------------------------

class TestMarking:
    def test_scope_excluded_is_not_a_lib_tag(self):
        """A LIB_* tag is a claim backed by a matched artifact. An inference
        must not be able to forge one."""
        assert sg.SCOPE_EXCLUDED not in ls.KNOWN_LIB_TAGS
        assert sg.SCOPE_EXCLUDED in sg.ALL_EXCLUDING_TAGS
        assert set(ls.KNOWN_LIB_TAGS) < set(sg.ALL_EXCLUDING_TAGS)

    def test_apply_writes_tag_property_and_bookmark(self, monkeypatch):
        sent = []
        monkeypatch.setattr(ls, "_post",
                            lambda path, prog, body: sent.append((path, body)) or {})
        rep = sg.ScopeReport(program="/x/A.dll", binary="A.dll")
        rep.swept = [{"address": "0x00001000", "name": "x", "reason": "r"}]
        assert sg.apply_scope(rep)["tagged"] == 1
        paths = [p for p, _ in sent]
        assert "/add_function_tag" in paths and "/set_property" in paths
        tag_body = next(b for p, b in sent if p == "/add_function_tag")
        assert tag_body["tags"] == sg.SCOPE_EXCLUDED

    def test_apply_counts_a_rejected_write_as_a_failure(self, monkeypatch, capsys):
        monkeypatch.setattr(ls, "_post", lambda *a, **k: {"error": "nope"})
        rep = sg.ScopeReport(program="/x/A.dll", binary="A.dll")
        rep.swept = [{"address": "0x00001000", "name": "x", "reason": "r"}]
        stats = sg.apply_scope(rep)
        assert stats["tagged"] == 0 and stats["failed"] == 1
        assert "scope tag failed" in capsys.readouterr().out
