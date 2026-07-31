"""Regression tests for the resolve tables' module attribution (D2MOO side).

WHY
---
`D2MOO_ResolveGameFn` and the provider's `D2MOO_Resolve` used to hand reimpls the
Ghidra ABSOLUTE address of a global. That is only correct for a module that got
its preferred base. D2Common (0x6fd50000) and D2Game (0x6fc20000) do; D2Client
does NOT -- the live process maps it at 0x03600000 and leaves Ghidra's 0x6fab0000
unmapped -- and 3,399 of the 4,535 resolve-table entries are D2Client-range. So
75% of the table returned pointers that fault on first dereference, while the
resolver's own comment read "add ASLR rebasing here if it ever loads elsewhere".

Both generators now emit (module, rva) and both resolvers add the RUNTIME base.
The load-bearing part is ATTRIBUTION: which module owns a given Ghidra address.
A wrong answer there silently rebases against some other DLL, which is the same
bad-pointer failure wearing a different hat -- so `_module_for_address` refuses
to guess, and these tests pin that refusal.

These run against the D2MOO checkout (FUNDOC_D2MOO_REPO); they skip when it is
not present.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_D2MOO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
_TOOLS = _D2MOO / "conformance" / "tools"
if not (_TOOLS / "gen_resolve_table.py").exists():
    pytest.skip("D2MOO conformance tools not available", allow_module_level=True)
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

grt = pytest.importorskip("gen_resolve_table")

D2CLIENT_GHIDRA_BASE = 0x6FAB0000
D2COMMON_GHIDRA_BASE = 0x6FD50000


class TestModuleAttribution:
    def test_d2client_address_attributes_to_d2client(self):
        # CLIENT_GetRosterSkillId, one of the 104 falsely retired functions.
        assert grt._module_for_address(0x6FAD16D0) == "D2Client.dll"

    def test_d2common_address_attributes_to_d2common(self):
        assert grt._module_for_address(0x6FD866B0) == "D2Common.dll"

    def test_d2game_address_attributes_to_d2game(self):
        assert grt._module_for_address(0x6FC30000) == "D2Game.dll"

    def test_image_base_itself_is_inside_the_range(self):
        assert grt._module_for_address(D2CLIENT_GHIDRA_BASE) == "D2Client.dll"

    def test_unknown_address_raises_rather_than_guessing(self):
        """Emitting an unattributable address anyway is exactly how 3,392
        D2Client globals shipped as faulting pointers."""
        with pytest.raises(grt.AttributionError):
            grt._module_for_address(0x40000000)

    def test_identical_preferred_bases_raise(self):
        """Storm.dll and D2Net.dll both prefer 0x6fbf0000 -- a true tie, since
        neither base is closer. Refuse: picking either rebases against the wrong
        DLL, which is the bad-pointer failure in a new hat."""
        with pytest.raises(grt.AttributionError) as exc:
            grt._module_for_address(0x6FBF1000)
        assert "sharing base" in str(exc.value)

    @pytest.mark.parametrize("addr,expected", [
        (0x6FC30000, "D2Game.dll"),   # inside Storm's declared image too
        (0x6FC01000, "D2Lang.dll"),   # ditto
        (0x6FBFE000, "Storm.dll"),    # past D2Net's end, still inside Storm
    ])
    def test_tightest_range_wins_over_an_oversized_neighbour(self, addr, expected):
        """Storm declares 0x6fbf0000-0x6fc50000, swallowing D2Net's, D2Lang's and
        D2Game's bases. Ghidra loads each DLL at its OWN base, so the closest base
        below the address is the owner."""
        assert grt._module_for_address(addr) == expected

    def test_ranges_do_not_silently_swallow_a_gap(self):
        """Addresses between modules must not be attributed to a neighbour."""
        with pytest.raises(grt.AttributionError):
            grt._module_for_address(0x6FAA5000)   # between D2gfx and D2Client


class TestRvaRoundTrip:
    @pytest.mark.parametrize("addr,module,expected_rva", [
        (0x6FAD16D0, "D2Client.dll", 0x216D0),   # CLIENT_GetRosterSkillId
        (0x6FAD0F20, "D2Client.dll", 0x20F20),   # ProcessPlayerClassCallbacks
        (0x6FBCC4D4, "D2Client.dll", 0x11C4D4),  # g_pRosterPetList
        (0x6FD866B0, "D2Common.dll", 0x366B0),   # STATS_TestStatFlag
    ])
    def test_addr_minus_base_is_the_emitted_rva(self, addr, module, expected_rva):
        assert grt._module_for_address(addr) == module
        base = next(lo for m, lo, _hi in grt.MODULE_RANGES if m == module)
        assert addr - base == expected_rva

    def test_live_base_plus_rva_matches_the_observed_operand(self):
        """Ground truth from the live process, 2026-07-30: Ghidra's
        `mov eax,[0x6fbcc4d4]` reads back as `mov eax,[0x0371c4d4]`, i.e.
        D2Client is at 0x03600000. The rva must reproduce that operand exactly."""
        rva = 0x6FBCC4D4 - D2CLIENT_GHIDRA_BASE
        assert 0x03600000 + rva == 0x0371C4D4


class TestGeneratedHeaders:
    """The committed headers must actually carry module+rva, not absolutes."""

    def _read(self, rel):
        p = _D2MOO / rel
        if not p.exists():
            pytest.skip(f"{rel} not generated")
        return p.read_text(encoding="utf-8", errors="replace")

    def test_patch_table_declares_module_and_rva(self):
        txt = self._read("D2.Detours.patches/1.13c/D2Common_ResolveTable.gen.h")
        assert "const char* module; unsigned int rva;" in txt
        assert "unsigned int addr;" not in txt

    def test_provider_table_declares_module_and_rva(self):
        txt = self._read("conformance/reimpl_provider/provider_globals.gen.h")
        assert "const char* module; unsigned int rva;" in txt
        assert "unsigned int addr;" not in txt

    def test_no_entry_carries_a_ghidra_absolute_address(self):
        """A 0x6f... value in the rva column means the rewrite regressed: those
        are absolute addresses, and an rva that large is not a real offset in any
        of these DLLs (the biggest, D2CMP, is ~0x108000)."""
        for rel in ("D2.Detours.patches/1.13c/D2Common_ResolveTable.gen.h",
                    "conformance/reimpl_provider/provider_globals.gen.h"):
            for line in self._read(rel).splitlines():
                if not line.strip().startswith("{ \""):
                    continue
                rva = line.rsplit(",", 1)[-1].strip().rstrip("},u ")
                if rva.startswith("0x"):
                    assert int(rva, 16) < 0x00800000, f"{rel}: absolute-looking rva in {line.strip()}"

    def test_resolvers_add_the_runtime_base(self):
        patch = self._read("D2.Detours.patches/1.13c/LiveDispatch_CoordFamily.h")
        assert "GetModuleHandleA(g_d2moo_resolve_table[i].module)" in patch
        provider = self._read("conformance/reimpl_provider/provider_runtime.cpp")
        assert "GetModuleHandleA(g_d2moo_provider_globals[mid].module)" in provider


class TestOracleBadTargetGate:
    """The oracle must refuse to call an address that is not mapped executable.

    Without this the call faults, SEH catches it, and the caller sees the same
    "handler-exception" a genuinely wrong ABI produces -- which is how a base
    mistake became 104 terminal ABI verdicts.
    """

    def _oracle_src(self):
        p = _D2MOO / "source" / "D2Debugger" / "src" / "D2Debugger.LiveDispatch.cpp"
        if not p.exists():
            pytest.skip("D2Debugger source not available")
        return p.read_text(encoding="utf-8", errors="replace")

    def test_gate_exists_and_is_applied_to_the_original(self):
        src = self._oracle_src()
        assert "bool IsCallableAddress(" in src
        assert "if (!IsCallableAddress(orig))" in src

    def test_gate_message_carries_the_bad_target_token(self):
        """port_live_prove._classify_prove_failure keys on this token to file the
        failure as ENVIRONMENTAL instead of a verdict about the function."""
        assert "bad-target: original for %s resolved via %s" in self._oracle_src()

    def test_spec_prefers_module_rva_over_absolute_addr(self):
        src = self._oracle_src()
        assert "ResolveModuleRva(mod.c_str()" in src
        # module+rva must be consulted BEFORE the legacy offset/addr fallbacks.
        assert src.index("ResolveModuleRva(mod.c_str()") < src.index('spec.find("offset")')

    def test_status_advertises_the_capability(self):
        """Clients need to detect an older oracle, which silently ignores
        module+rva and calls the absolute address instead."""
        assert '\\"specModuleRva\\":true' in self._oracle_src()

    def test_modules_route_exists(self):
        assert 'seg[0] == "modules"' in self._oracle_src()
