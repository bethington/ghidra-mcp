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

    def test_apply_writes_the_tag_and_a_durable_bookmark(self, monkeypatch):
        sent = []
        monkeypatch.setattr(ls, "_post",
                            lambda path, prog, body: sent.append((path, body)) or {})
        rep = sg.ScopeReport(program="/x/A.dll", binary="A.dll")
        rep.swept = [{"address": "0x00001000", "name": "x", "reason": "r"}]
        assert sg.apply_scope(rep)["tagged"] == 1
        paths = [p for p, _ in sent]
        assert "/add_function_tag" in paths and "/set_bookmark" in paths
        tag_body = next(b for p, b in sent if p == "/add_function_tag")
        assert tag_body["tags"] == sg.SCOPE_EXCLUDED
        # the bookmark carries the reason and survives a rename
        bm = next(b for p, b in sent if p == "/set_bookmark")
        assert "r" in bm["comment"] and bm["category"] == "Library Scope"

    def test_apply_never_touches_the_scope_property_map(self, monkeypatch):
        """The `Scope` map belongs to the GLOBALS lane, and every reader of it in
        this repo treats an entry as a data address -- the globals panel takes the
        map's SIZE as its hidden-globals count. Writing function addresses there
        would have inflated that count by one per swept function and told the
        operator globals were excluded when none were."""
        sent = []
        monkeypatch.setattr(ls, "_post",
                            lambda path, prog, body: sent.append((path, body)) or {})
        rep = sg.ScopeReport(program="/x/A.dll", binary="A.dll")
        rep.swept = [{"address": "0x00001000", "name": "x", "reason": "r"}]
        sg.apply_scope(rep)
        paths = [p for p, _ in sent]
        assert "/set_property" not in paths
        assert "/create_property_map" not in paths

    def test_apply_counts_a_rejected_write_as_a_failure(self, monkeypatch, capsys):
        monkeypatch.setattr(ls, "_post", lambda *a, **k: {"error": "nope"})
        rep = sg.ScopeReport(program="/x/A.dll", binary="A.dll")
        rep.swept = [{"address": "0x00001000", "name": "x", "reason": "r"}]
        stats = sg.apply_scope(rep)
        assert stats["tagged"] == 0 and stats["failed"] == 1
        assert "scope tag failed" in capsys.readouterr().out


# --------------------------------------------------------------------------
# the controls
# --------------------------------------------------------------------------

def _rep(binary, swept=(), in_scope=(), protected=()):
    r = sg.ScopeReport(program=f"/x/{binary}", binary=binary)
    r.swept = [{"address": a, "name": n, "reason": "all referrers are library",
                "referrers": [], "referrer_count": 1} for a, n in swept]
    r.in_scope = [{"address": a, "name": n} for a, n in in_scope]
    r.protected = [{"address": a, "name": n, "why": "w"} for a, n in protected]
    return r


class TestBenchmarkGate:
    AUTHORED = {"Crc16Compute", "ParseSignedShort"}

    def test_sweeping_an_authored_function_fails(self, monkeypatch):
        monkeypatch.setattr(ls, "benchmark_authored_functions",
                            lambda: set(self.AUTHORED))
        rep = _rep("Benchmark.dll", swept=[("0x1000", "Crc16Compute")])
        passed, bad = sg.benchmark_gate([rep])
        assert passed is False and len(bad) == 1 and "Crc16Compute" in bad[0]

    def test_sweeping_only_linked_runtime_passes(self, monkeypatch):
        monkeypatch.setattr(ls, "benchmark_authored_functions",
                            lambda: set(self.AUTHORED))
        rep = _rep("Benchmark.dll", swept=[("0x2000", "__ld12tod")])
        assert sg.benchmark_gate([rep]) == (True, [])

    def test_other_binaries_do_not_trip_it(self, monkeypatch):
        monkeypatch.setattr(ls, "benchmark_authored_functions",
                            lambda: set(self.AUTHORED))
        rep = _rep("D2Common.dll", swept=[("0x1000", "Crc16Compute")])
        assert sg.benchmark_gate([rep]) == (True, [])

    def test_gate_has_no_override_parameter(self):
        """A control you can wave through is not a control. Same assertion
        library_scope's gate carries."""
        import inspect
        sig = inspect.signature(sg.benchmark_gate)
        assert list(sig.parameters) == ["reports"]


class TestCascadeControl:
    """PD2_EXT.dll is where the cascade was measured, so it is the only place a
    LIVE sweep can show the boundary guard still holds."""

    ALL = [("0x1000", "PD2EXT_LoadModAfterGameDataInit"),
           ("0x1100", "PD2EXT_InstallBootstrapHook"),
           ("0x1200", "PD2EXT_InstallGameAndFogHooks"),
           ("0x1300", "PD2EXT_RemoveLastPathComponent")]

    def test_all_four_in_scope_passes_and_is_exercised(self):
        rep = _rep("PD2_EXT.dll", in_scope=self.ALL,
                   swept=[("0x9000", "__scrt_initialize_crt")])
        passed, exercised, bad = sg.cascade_control([rep])
        assert (passed, exercised, bad) == (True, True, [])

    def test_sweeping_the_head_of_the_chain_fails(self):
        rep = _rep("PD2_EXT.dll", swept=[self.ALL[1]], in_scope=[self.ALL[0],
                                                                 self.ALL[2],
                                                                 self.ALL[3]])
        passed, exercised, bad = sg.cascade_control([rep])
        assert passed is False and exercised is True
        assert "InstallBootstrapHook" in bad[0] and "cascade" in bad[0]

    def test_protected_counts_as_present(self):
        """The guard's whole job is to PROTECT these, so they legitimately show up
        under `protected` rather than `in_scope`."""
        rep = _rep("PD2_EXT.dll", protected=self.ALL)
        assert sg.cascade_control([rep]) == (True, True, [])

    def test_an_empty_sweep_is_not_exercised(self):
        """The trap this half exists for: a dead sweep sweeps nothing, so a
        'was anything authored swept?' check passes while verifying nothing. Same
        shape as a CRT detector that claims nothing passing its positive
        control."""
        rep = _rep("PD2_EXT.dll")
        passed, exercised, bad = sg.cascade_control([rep])
        assert exercised is False and bad == []

    def test_missing_authored_names_report_not_exercised(self, capsys):
        rep = _rep("PD2_EXT.dll", in_scope=self.ALL[:2])
        passed, exercised, bad = sg.cascade_control([rep])
        assert exercised is False
        assert "NOT exercised" in capsys.readouterr().out

    def test_absent_control_binary_is_not_exercised(self):
        rep = _rep("D2Common.dll", swept=[("0x1000", "whatever")])
        assert sg.cascade_control([rep]) == (True, False, [])

    def test_control_has_no_override_parameter(self):
        import inspect
        assert list(inspect.signature(sg.cascade_control).parameters) == ["reports"]


class TestGateReport:
    def test_unexercised_is_not_reported_as_passed_overall(self, monkeypatch):
        """`passed` may be True with nothing verified -- which is why the CLI
        checks `exercised` separately and refuses on it."""
        monkeypatch.setattr(ls, "benchmark_authored_functions", lambda: {"X"})
        g = sg.gate_report([_rep("D2Common.dll")])
        assert g["passed"] is True
        assert g["benchmark"]["exercised"] is False
        assert g["cascade"]["exercised"] is False

    def test_a_violation_fails_the_whole_block(self, monkeypatch):
        monkeypatch.setattr(ls, "benchmark_authored_functions", lambda: {"Crc16Compute"})
        g = sg.gate_report([_rep("Benchmark.dll", swept=[("0x1", "Crc16Compute")])])
        assert g["passed"] is False and g["violations"]


# --------------------------------------------------------------------------
# drift: the reviewed set must be the written set
# --------------------------------------------------------------------------

class TestReportDrift:
    def _saved(self, addrs):
        return {"programs": [{"program": "/x/A.dll",
                              "swept": [{"address": a} for a in addrs]}]}

    def test_identical_sweep_has_no_drift(self):
        fresh = [_rep("A.dll", swept=[("0x1000", "a"), ("0x2000", "b")])]
        assert sg.report_drift(self._saved(["0x1000", "0x2000"]), fresh) == []

    def test_a_new_verdict_is_drift(self):
        """The operator approved one set; this would write a different one."""
        fresh = [_rep("A.dll", swept=[("0x1000", "a"), ("0x3000", "c")])]
        d = sg.report_drift(self._saved(["0x1000"]), fresh)
        assert any("0x3000" in x and "not in the report" in x for x in d)

    def test_a_disappeared_verdict_is_drift(self):
        fresh = [_rep("A.dll", swept=[("0x1000", "a")])]
        d = sg.report_drift(self._saved(["0x1000", "0x2000"]), fresh)
        assert any("0x2000" in x and "no longer swept" in x for x in d)

    def test_a_program_missing_from_the_report_is_drift(self):
        fresh = [_rep("A.dll", swept=[("0x1000", "a")]),
                 _rep("B.dll", swept=[("0x5000", "z")])]
        d = sg.report_drift(self._saved(["0x1000"]), fresh)
        assert any("B.dll" in x for x in d)

    def test_a_program_that_failed_to_sweep_is_drift_not_silence(self):
        """A program whose sweep raised EmptyGraph produces no report, and
        applying the file anyway would write verdicts nothing re-verified."""
        d = sg.report_drift(self._saved(["0x1000"]), [])
        assert any("/x/A.dll" in x and "not in this sweep" in x for x in d)

    def test_empty_report_and_empty_sweep_agree(self):
        assert sg.report_drift({"programs": []}, []) == []

    def test_saved_index_survives_a_malformed_entry(self):
        saved = {"programs": [{"program": "/x/A.dll",
                               "swept": [{"address": "0x1000"}, "junk", {}]}]}
        assert sg.saved_swept_index(saved) == {"/x/A.dll": {"0x1000"}}


# --------------------------------------------------------------------------
# the SQL flag -- the selector reads the COLUMN, not the tag
# --------------------------------------------------------------------------

class TestFlagSync:
    def _fake_fun_doc(self, monkeypatch, functions, calls):
        import types
        fake = types.ModuleType("fun_doc")
        fake.load_state = lambda **k: {"functions": functions}
        fake.update_function_state = \
            lambda key, patch: calls["update"].append((key, patch))

        def _save(_s):
            calls["save"] += 1
        fake.save_state = _save
        monkeypatch.setitem(sys.modules, "fun_doc", fake)

    def test_never_bulk_writes_state(self, monkeypatch):
        """A load + mutate + save round trip is a whole-binary read-modify-write;
        a Doc worker finishing mid-sweep would lose its entire result. This sweep
        is explicitly something you run while the fleet works."""
        calls = {"update": [], "save": 0}
        self._fake_fun_doc(monkeypatch, {
            "/x/A.dll::1000": {"program": "/x/A.dll", "address": "1000",
                               "name": "f", "score": 40}}, calls)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: set())
        rep = _rep("A.dll", swept=[("0x00001000", "f")])
        stats = sg.sync_scope_excluded_flags([rep])
        assert calls["save"] == 0 and stats["updated"] == 1
        key, patch = calls["update"][0]
        assert key == "/x/A.dll::1000"
        assert patch["scope_excluded"] is True
        assert patch["scope_excluded_at"] and patch["scope_excluded_reasons"]
        assert patch["score"] == 40           # merge, not replace

    def test_never_writes_the_library_code_column(self, monkeypatch):
        """The whole point of the separate column: an inference must not be
        recorded as 'this IS library code'."""
        calls = {"update": [], "save": 0}
        self._fake_fun_doc(monkeypatch, {
            "/x/A.dll::1000": {"program": "/x/A.dll", "address": "1000"}}, calls)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: set())
        sg.sync_scope_excluded_flags([_rep("A.dll", swept=[("0x00001000", "f")])])
        _key, patch = calls["update"][0]
        assert "library_code" not in patch
        assert patch.get("library_code_reasons") is None

    def test_covers_pre_existing_tags_not_just_this_run(self, monkeypatch):
        """The selector reads the flag, so the flag mirrors the DURABLE tag.
        D2Client carried 1,020 tags against 339 flagged rows; the difference was
        still being handed to workers."""
        calls = {"update": [], "save": 0}
        self._fake_fun_doc(monkeypatch, {
            "/x/A.dll::1000": {"program": "/x/A.dll", "address": "1000"},
            "/x/A.dll::2000": {"program": "/x/A.dll", "address": "2000"}}, calls)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: {"0x00002000"})
        stats = sg.sync_scope_excluded_flags([_rep("A.dll", swept=[("0x00001000", "f")])])
        assert stats["updated"] == 2
        assert {k for k, _ in calls["update"]} == {"/x/A.dll::1000", "/x/A.dll::2000"}

    def test_reconciles_a_report_with_nothing_swept(self, monkeypatch):
        """An empty-check ahead of the union made the equivalent library_scope
        path report 0 updated and do nothing on an already-tagged program."""
        calls = {"update": [], "save": 0}
        self._fake_fun_doc(monkeypatch, {
            "/x/A.dll::2000": {"program": "/x/A.dll", "address": "2000"}}, calls)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: {"0x00002000"})
        assert sg.sync_scope_excluded_flags([_rep("A.dll")])["updated"] == 1

    def test_skips_already_flagged_rows(self, monkeypatch):
        calls = {"update": [], "save": 0}
        self._fake_fun_doc(monkeypatch, {
            "/x/A.dll::1000": {"program": "/x/A.dll", "address": "1000",
                               "scope_excluded": True}}, calls)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: set())
        stats = sg.sync_scope_excluded_flags([_rep("A.dll", swept=[("0x00001000", "f")])])
        assert calls["update"] == [] and stats["updated"] == 0

    def test_counts_rows_it_cannot_find(self, monkeypatch):
        calls = {"update": [], "save": 0}
        self._fake_fun_doc(monkeypatch, {}, calls)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: set())
        stats = sg.sync_scope_excluded_flags([_rep("A.dll", swept=[("0x00001000", "f")])])
        assert stats["missing"] == 1 and stats["updated"] == 0

    def test_a_failed_write_is_counted_and_loud(self, monkeypatch, capsys):
        import types
        fake = types.ModuleType("fun_doc")
        fake.load_state = lambda **k: {"functions": {
            "/x/A.dll::1000": {"program": "/x/A.dll", "address": "1000"}}}

        def _boom(_k, _p):
            raise RuntimeError("db down")
        fake.update_function_state = _boom
        fake.save_state = lambda _s: None
        monkeypatch.setitem(sys.modules, "fun_doc", fake)
        monkeypatch.setattr(sg, "existing_scope_tags", lambda p: set())
        stats = sg.sync_scope_excluded_flags([_rep("A.dll", swept=[("0x00001000", "f")])])
        assert stats["failed"] == 1
        assert "flag write failed" in capsys.readouterr().out


class TestSeedsStayProofOnly:
    def test_the_sweep_does_not_seed_from_its_own_previous_verdicts(self, monkeypatch):
        """Across runs, seeding from an inference would let one wrong verdict
        become the premise for the next, compounding with nothing to review. It
        also keeps the sweep deterministic, which the --apply drift check needs."""
        asked = []
        monkeypatch.setattr(sg.ls, "_function_ranges", lambda p: [])
        monkeypatch.setattr(sg, "function_referrers", lambda p, a, ranges=None: {})
        monkeypatch.setattr(sg, "protected_addresses", lambda *a, **k: {})
        monkeypatch.setattr(sg.ls, "existing_lib_tags",
                            lambda p: asked.append("lib") or set())
        monkeypatch.setattr(sg, "existing_scope_tags",
                            lambda p: asked.append("scope") or {"0x00001000"})
        monkeypatch.setattr(sg.ls, "_get", lambda ep, **k: {
            "functions": [{"address": "1000", "name": "f"}]})
        sg.sweep_program("/x/A.dll")
        assert "scope" not in asked, \
            "sweep_program seeded from SCOPE_EXCLUDED -- inferences must not " \
            "become premises for the next run"
