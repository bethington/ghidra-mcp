"""Offline tests for fun-doc/library_scope.py -- no Ghidra, no network.

The invariants under test are the ones that cost real debugging time in the
lanes this module sequences, restated for the sequencer:

  * a heuristic NEVER writes a tag (a LIB_ tag retires a function permanently)
  * precedence is first-exact-lane-wins, and a later lane cannot overwrite it
  * the globals rule is EXCLUSIVE, and every way of being unsure keeps a global
    IN scope rather than out
  * address normalization does not use lstrip("0x"), which eats leading zeros
  * the Benchmark control has no override path
"""

from __future__ import annotations

import json
import os
import sys

import pytest

FUN_DOC = os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "fun-doc")
if FUN_DOC not in sys.path:
    sys.path.insert(0, FUN_DOC)

library_scope = pytest.importorskip("library_scope")
ls = library_scope


# --------------------------------------------------------------------------
# address normalization
# --------------------------------------------------------------------------

class TestNormAddr:
    def test_canonical_forms_agree(self):
        for a in ("0x10001baf", "10001BAF", "0X10001Baf", " 10001baf "):
            assert ls.norm_addr(a) == "0x10001baf"

    def test_pads_to_eight(self):
        assert ls.norm_addr("abc") == "0x00000abc"
        assert ls.norm_addr("0xabc") == "0x00000abc"

    def test_leading_zeros_do_not_change_identity(self):
        assert ls.norm_addr("0000abc") == ls.norm_addr("abc")

    def test_does_not_eat_leading_hex_digits(self):
        """The lstrip("0x") trap: lstrip takes a CHARACTER SET, so it would
        also strip a leading 'a'..'f' string of 0/x chars. 0x0x0 is contrived,
        but '0' and '00000000' are not."""
        assert ls.norm_addr("0") == "0x00000000"
        assert ls.norm_addr("00000000") == "0x00000000"
        # a real address that begins with the digit 0 keeps its value
        assert ls.norm_addr("0x0040c1f0") == "0x0040c1f0"

    def test_empty_is_zero_not_crash(self):
        assert ls.norm_addr(None) == "0x00000000"
        assert ls.norm_addr("") == "0x00000000"


# --------------------------------------------------------------------------
# verdicts and lane policy
# --------------------------------------------------------------------------

def _v(lane="bytes", name="_qsort", addr="0x1000", tag=ls.TAG_CRT, lib="_qsort"):
    return ls.Verdict(address=ls.norm_addr(addr), lane=lane, tag=tag,
                      lib_name=lib, current_name=name, evidence="test")


class TestLanePolicy:
    @pytest.mark.parametrize("lane", ls.AUTONOMOUS_LANES)
    def test_exact_lanes_tag(self, lane):
        assert _v(lane=lane).writes_tag is True

    def test_heuristic_never_tags(self):
        """The whole safety argument rests on this one property."""
        assert _v(lane="heuristic").writes_tag is False

    def test_heuristic_is_not_in_the_autonomous_set(self):
        assert "heuristic" not in ls.AUTONOMOUS_LANES
        assert "heuristic" in ls.ALL_LANES

    def test_precedence_order_is_evidence_quality(self):
        assert ls.ALL_LANES.index("bytes") < ls.ALL_LANES.index("fid")
        assert ls.ALL_LANES.index("fid") < ls.ALL_LANES.index("bsim")
        assert ls.ALL_LANES.index("bsim") < ls.ALL_LANES.index("heuristic")


class TestGameStyledNames:
    @pytest.mark.parametrize("name", [
        "GAME_CallFunctionPtrArray", "CRT_CloseFileStream",
        "ConvertMbsToWcs", "STRING_DecRefEncodingCtx",
        "EH_StoreRegistrationState",
    ])
    def test_flags_game_style(self, name):
        assert _v(name=name).game_styled is True

    @pytest.mark.parametrize("name", [
        "_qsort", "__acrt_getptd", "___scrt_initialize_crt",
        "?__mbrtowc_utf8@__crt_mbstring@@YAI", "??0exception@std@@QAE@ABV01@@Z",
        "@_EH4_CallFilterFunc@8",
    ])
    def test_ignores_real_library_names(self, name):
        assert _v(name=name).game_styled is False

    def test_ignores_ghidra_defaults(self):
        """A FUN_ name is an absent name, not a suspicious one."""
        assert _v(name="FUN_10001234").game_styled is False


class TestTagVocabulary:
    def test_emitted_tags_are_readable_by_consumers(self):
        """Every tag this module can emit must be one the dashboard and the
        selector already exclude on -- otherwise the exclusion is invisible to
        the panel that renders it."""
        emitted = {ls._tag_for(n) for n in (
            "_qsort", "__except_handler4", "___security_init_cookie",
            "__libm_sse2_log10_precise", "?FrameUnwindToEmptyState@__FrameHandler3@@",
            "__acrt_getptd", "_guard_check_icall", "__87except")}
        assert emitted <= set(ls.KNOWN_LIB_TAGS)

    @pytest.mark.parametrize("name,tag", [
        ("?FrameUnwindToEmptyState@__FrameHandler3@@", ls.TAG_EH),
        ("__CxxThrowException", ls.TAG_EH),
        ("___security_init_cookie", "LIB_SECURITY"),
        ("_guard_check_icall", "LIB_SECURITY"),
        ("__libm_error_support", "LIB_MATH"),
        ("__87except", "LIB_MATH"),
        ("_qsort", ls.TAG_CRT),
    ])
    def test_routes_families(self, name, tag):
        assert ls._tag_for(name) == tag


# --------------------------------------------------------------------------
# envelope handling
# --------------------------------------------------------------------------

class TestItems:
    def test_plain_list_under_key(self):
        assert ls._items({"functions": [1, 2]}, "functions") == [1, 2]

    def test_seven_zero_envelope(self):
        assert ls._items({"result": {"functions": [1]}}, "functions") == [1]

    def test_stringified_envelope(self):
        payload = {"result": json.dumps({"functions": [{"a": 1}]})}
        assert ls._items(payload, "functions") == [{"a": 1}]

    def test_missing_key_is_empty_not_crash(self):
        assert ls._items({"other": [1]}, "functions") == []

    def test_garbage_is_empty(self):
        assert ls._items("not json", "functions") == []
        assert ls._items(None, "functions") == []


# --------------------------------------------------------------------------
# bulk xrefs parsing
# --------------------------------------------------------------------------

class TestBulkXrefs:
    def test_parses_bare_address_keyed_dict(self, monkeypatch):
        """/get_bulk_xrefs answers with a bare dict, NOT a 7.0.0 envelope."""
        monkeypatch.setattr(ls, "_post", lambda *a, **k: {
            "10013d38": [{"from": "10013c98", "type": "DATA"}],
            "10013d6c": [{"from": "10001100", "type": "DATA"}],
        })
        got = ls._bulk_xrefs_to("P", ["0x10013d38", "0x10013d6c"])
        assert got["0x10013d38"] == [0x10013c98]
        assert got["0x10013d6c"] == [0x10001100]

    def test_drops_symbolic_sources(self, monkeypatch):
        """Ghidra puts "Entry Point" in the same field as real addresses; an
        int(...,16) on one of those used to empty a whole program's globals."""
        monkeypatch.setattr(ls, "_post", lambda *a, **k: {
            "10013d38": [{"from": "Entry Point", "type": "EXTERNAL"},
                         {"from": "10001100", "type": "DATA"}],
        })
        assert ls._bulk_xrefs_to("P", ["0x10013d38"]) == {"0x10013d38": [0x10001100]}

    def test_all_symbolic_yields_no_entry(self, monkeypatch):
        monkeypatch.setattr(ls, "_post", lambda *a, **k: {
            "10013d38": [{"from": "Entry Point", "type": "EXTERNAL"}]})
        assert ls._bulk_xrefs_to("P", ["0x10013d38"]) == {}

    def test_chunk_failure_is_loud_not_fatal(self, monkeypatch, capsys):
        def boom(*a, **k):
            raise OSError("connection reset")
        monkeypatch.setattr(ls, "_post", boom)
        assert ls._bulk_xrefs_to("P", ["0x1000"]) == {}
        assert "bulk xrefs" in capsys.readouterr().out


# --------------------------------------------------------------------------
# function ranges
# --------------------------------------------------------------------------

class TestFunctionRanges:
    def _patch(self, monkeypatch, fns, segs):
        def fake_get(path, **params):
            if path == "/list_functions":
                return {"functions": fns}
            if path == "/list_segments":
                return {"segments": segs}
            return {}
        monkeypatch.setattr(ls, "_get", fake_get)

    def test_last_function_clamped_to_segment_end(self, monkeypatch):
        """Unclamped, the last .text function swallows .rdata and every data
        reference in the binary attributes to it."""
        self._patch(monkeypatch,
                    [{"address": "1000", "name": "a"},
                     {"address": "1100", "name": "b"}],
                    [{"start": "1000", "end": "11ff", "permissions": "rx"}])
        rng = ls._function_ranges("P")
        assert rng[-1][1] == 0x1200                    # segment end, not +0x1000
        assert ls._owning_function(0x5000, rng) is None

    def test_reference_maps_to_containing_function(self, monkeypatch):
        self._patch(monkeypatch,
                    [{"address": "1000", "name": "a"},
                     {"address": "1100", "name": "b"}],
                    [{"start": "1000", "end": "11ff", "permissions": "rx"}])
        rng = ls._function_ranges("P")
        assert ls._owning_function(0x1050, rng) == "0x00001000"
        assert ls._owning_function(0x1100, rng) == "0x00001100"

    def test_non_executable_segments_ignored(self, monkeypatch):
        self._patch(monkeypatch,
                    [{"address": "1000", "name": "a"}],
                    [{"start": "1000", "end": "10ff", "permissions": "rx"},
                     {"start": "2000", "end": "2fff", "permissions": "rw"}])
        assert ls._executable_ranges("P") == [(0x1000, 0x1100)]


# --------------------------------------------------------------------------
# the globals exclusive-reference rule
# --------------------------------------------------------------------------

class TestLibraryGlobals:
    """Every branch here answers the same question: when unsure, does the
    global stay IN the inventory? It must."""

    RANGES = [(0x1000, 0x1100, "0x00001000"),      # library
              (0x1100, 0x1200, "0x00001100"),      # library
              (0x2000, 0x2100, "0x00002000")]      # game
    LIB = {"0x00001000", "0x00001100"}

    def _run(self, monkeypatch, globs, refs):
        monkeypatch.setattr(ls, "_bulk_xrefs_to", lambda *a, **k: refs)
        return {g["address"] for g in ls.library_globals(
            "P", self.LIB, globs, fn_ranges=self.RANGES)}

    def test_all_library_referrers_is_excluded(self, monkeypatch):
        globs = {"0x00009000": {"address": "0x00009000", "name": "__acrt_ptd",
                                "type": "int", "xrefs": 2, "aliases": []}}
        got = self._run(monkeypatch, globs, {"0x00009000": [0x1050, 0x1150]})
        assert got == {"0x00009000"}

    def test_one_game_referrer_keeps_it(self, monkeypatch):
        """g_pfnGuardCheckICall: 31 library referrers, 8 game. Stays."""
        globs = {"0x00009000": {"address": "0x00009000", "name": "g_shared",
                                "type": "int", "xrefs": 2, "aliases": []}}
        got = self._run(monkeypatch, globs, {"0x00009000": [0x1050, 0x2050]})
        assert got == set()

    def test_zero_xref_global_stays(self, monkeypatch):
        """Cannot be proven library-owned; silence is not evidence."""
        globs = {"0x00009000": {"address": "0x00009000", "name": "g_orphan",
                                "type": "int", "xrefs": 0, "aliases": []}}
        assert self._run(monkeypatch, globs, {}) == set()

    def test_unreadable_xrefs_abstain(self, monkeypatch):
        """Ghidra claimed xrefs but we got none back -- unknown, not library."""
        globs = {"0x00009000": {"address": "0x00009000", "name": "g_x",
                                "type": "int", "xrefs": 3, "aliases": []}}
        assert self._run(monkeypatch, globs, {}) == set()

    def test_data_only_referrers_stay(self, monkeypatch):
        """Referenced from an import table, not from any function."""
        globs = {"0x00009000": {"address": "0x00009000", "name": "g_import",
                                "type": "int", "xrefs": 1, "aliases": []}}
        assert self._run(monkeypatch, globs, {"0x00009000": [0x8000]}) == set()

    def test_unresolvable_referrer_blocks_exclusion(self, monkeypatch):
        """One referrer inside a function, one outside any function. The
        unidentifiable one could be game code, so it blocks."""
        globs = {"0x00009000": {"address": "0x00009000", "name": "g_x",
                                "type": "int", "xrefs": 2, "aliases": []}}
        got = self._run(monkeypatch, globs, {"0x00009000": [0x1050, 0x8000]})
        assert got == set()

    def test_empty_program_is_empty_not_crash(self, monkeypatch):
        assert self._run(monkeypatch, {}, {}) == set()


class TestProgramGlobals:
    def test_one_row_per_address_aliases_kept(self, monkeypatch):
        """Ghidra allows many labels on one address and /list_globals emits a
        line for each. Counting lines inflates every address-keyed denominator."""
        monkeypatch.setattr(ls, "_get", lambda *a, **k: {"globals": [
            "g_nScreenShiftX @ 6fbcb9a0 [Label] (int) xrefs=3",
            "g_nPanelBaseX @ 6fbcb9a0 [Label] (int) xrefs=3",
            "g_other @ 6fbcb9b0 [Label] (dword) xrefs=1",
        ]})
        rows = ls.program_globals("P")
        assert len(rows) == 2
        assert rows["0x6fbcb9a0"]["aliases"] == ["g_nPanelBaseX"]

    def test_unparseable_lines_skipped(self, monkeypatch):
        monkeypatch.setattr(ls, "_get", lambda *a, **k: {
            "globals": ["garbage", "g_ok @ 1000 [Label] (int) xrefs=1"]})
        assert set(ls.program_globals("P")) == {"0x00001000"}

    def test_failure_is_loud_and_empty(self, monkeypatch, capsys):
        def boom(*a, **k):
            raise OSError("down")
        monkeypatch.setattr(ls, "_get", boom)
        assert ls.program_globals("P") == {}
        assert "list_globals failed" in capsys.readouterr().out


# --------------------------------------------------------------------------
# the Benchmark gate
# --------------------------------------------------------------------------

class TestBenchmarkGate:
    def _rep(self, binary, names):
        r = ls.ProgramReport(program=f"/x/{binary}", binary=binary)
        for i, n in enumerate(names):
            a = ls.norm_addr(f"{0x1000 + i:x}")
            r.verdicts[a] = _v(name=n, addr=a)
        return r

    def test_authored_list_loads(self):
        """If this is empty the gate silently passes everything."""
        assert len(ls.benchmark_authored_functions()) >= 9

    def test_claiming_an_authored_function_fails(self):
        authored = sorted(ls.benchmark_authored_functions())[0]
        ok, bad = ls.benchmark_gate([self._rep(ls.BENCHMARK_BINARY, [authored])])
        assert ok is False and len(bad) == 1 and authored in bad[0]

    def test_claiming_only_library_code_passes(self):
        ok, bad = ls.benchmark_gate(
            [self._rep(ls.BENCHMARK_BINARY, ["_qsort", "__except_handler4"])])
        assert ok is True and bad == []

    def test_other_binaries_do_not_trip_the_gate(self):
        """The same NAME in another binary is not the control."""
        authored = sorted(ls.benchmark_authored_functions())[0]
        ok, _ = ls.benchmark_gate([self._rep("D2Common.dll", [authored])])
        assert ok is True

    def test_gate_has_no_override_parameter(self):
        """A control you can wave through is not a control."""
        import inspect
        params = set(inspect.signature(ls.benchmark_gate).parameters)
        assert params == {"reports"}


# --------------------------------------------------------------------------
# report shape
# --------------------------------------------------------------------------

class TestProgramReport:
    def test_in_scope_is_defined_minus_library(self):
        r = ls.ProgramReport(program="/x/A.dll", binary="A.dll", defined=463)
        for i in range(272):
            a = ls.norm_addr(f"{0x1000 + i:x}")
            r.verdicts[a] = _v(addr=a)
        assert r.in_scope == 191

    def test_in_scope_never_negative(self):
        r = ls.ProgramReport(program="/x/A.dll", binary="A.dll", defined=0)
        r.verdicts["0x1000"] = _v()
        assert r.in_scope == 0

    def test_json_is_serializable_and_records_skips(self):
        r = ls.ProgramReport(program="/x/A.dll", binary="A.dll", defined=10)
        r.verdicts["0x00001000"] = _v()
        r.review.append(_v(lane="heuristic", name="MaybeLib"))
        r.styled.append(_v(name="GAME_Thing"))
        r.lanes_skipped["bsim"] = "no dump"
        blob = json.dumps(r.to_json())
        back = json.loads(blob)
        assert back["library"] == 1 and back["in_scope"] == 9
        assert back["lanes_skipped"]["bsim"] == "no dump"
        assert back["review_queue"][0]["name"] == "MaybeLib"
        assert back["styled_names"][0]["name"] == "GAME_Thing"

    def test_skipped_lane_is_recorded_not_silent(self):
        """A lane that quietly finds zero is indistinguishable from a lane that
        is broken -- no silent caps."""
        r = ls.ProgramReport(program="/x/A.dll", binary="A.dll")
        r.lanes_skipped["bsim"] = "no BSim dump supplied"
        assert "bsim" in r.to_json()["lanes_skipped"]


class TestSweepPrecedence:
    def test_first_lane_wins_and_later_lanes_cannot_override(self, monkeypatch):
        addr = "0x00001000"
        monkeypatch.setattr(ls, "_get", lambda *a, **k: {
            "functions": [{"address": "1000", "name": "x"}]})
        monkeypatch.setattr(ls, "lane_bytes", lambda *a, **k: (
            [_v(lane="bytes", addr=addr, lib="_qsort")], None))
        monkeypatch.setattr(ls, "lane_fid", lambda *a, **k: (
            [_v(lane="fid", addr=addr, lib="_WRONG")], None))
        monkeypatch.setattr(ls, "lane_bsim", lambda *a, **k: ([], None))
        monkeypatch.setattr(ls, "lane_heuristic", lambda *a, **k: ([], None))
        rep = ls.sweep_program("P", lanes=("bytes", "fid"), do_globals=False)
        assert rep.verdicts[addr].lane == "bytes"
        assert rep.verdicts[addr].lib_name == "_qsort"
        assert rep.lane_counts["fid"] == 0

    def test_heuristic_hits_go_to_review_not_verdicts(self, monkeypatch):
        monkeypatch.setattr(ls, "_get", lambda *a, **k: {
            "functions": [{"address": "2000", "name": "y"}]})
        monkeypatch.setattr(ls, "lane_bytes", lambda *a, **k: ([], None))
        monkeypatch.setattr(ls, "lane_fid", lambda *a, **k: ([], None))
        monkeypatch.setattr(ls, "lane_bsim", lambda *a, **k: ([], None))
        monkeypatch.setattr(ls, "lane_heuristic", lambda *a, **k: (
            [_v(lane="heuristic", addr="0x2000")], None))
        rep = ls.sweep_program("P", do_globals=False)
        assert rep.verdicts == {}
        assert len(rep.review) == 1

    def test_bsim_without_dump_reports_a_skip(self):
        verdicts, skip = ls.lane_bsim("P", dump=None)
        assert verdicts == [] and skip and "did not run" in skip


class TestApplyIsGatedOnLane:
    def test_apply_skips_non_tagging_lanes(self, monkeypatch):
        """Even if a heuristic verdict reached `verdicts` by some future bug,
        the writer must still refuse to tag it."""
        calls = []
        monkeypatch.setattr(ls, "_post",
                            lambda p, prog, body: calls.append(p) or {})
        r = ls.ProgramReport(program="/x/A.dll", binary="A.dll")
        r.verdicts["0x00001000"] = _v(lane="heuristic", addr="0x1000")
        stats = ls.apply_function_verdicts(r)
        assert stats["tagged"] == 0 and stats["skipped"] == 1
        assert calls == []

    def test_tag_failure_is_counted_and_loud(self, monkeypatch, capsys):
        def boom(*a, **k):
            raise OSError("no route to host")
        monkeypatch.setattr(ls, "_post", boom)
        r = ls.ProgramReport(program="/x/A.dll", binary="A.dll")
        r.verdicts["0x00001000"] = _v(addr="0x1000")
        stats = ls.apply_function_verdicts(r)
        assert stats["failed"] == 1
        assert "tag failed" in capsys.readouterr().out
