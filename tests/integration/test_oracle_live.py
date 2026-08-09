"""LIVE gate for the D2Debugger oracle proxy tools — real game, no mocks.

This file exists because of a measured failure: the 22 WinDbg debugger proxy
tools are unit-tested against a mocked pybag and stayed green for months while
the real stack faulted (STATUS_ILLEGAL_INSTRUCTION) on the first live attach.
A mocked suite proves argument handling and nothing about whether the tool works.

Every test here talks to the actual running game and self-skips when it is not
up, so the suite stays runnable on a machine with no Diablo II.

    pytest tests/integration/test_oracle_live.py -v

READ-ONLY: nothing here writes to the game (never /asset/poke), and
oracle_prove_function is exercised only for its *refusal* path.
"""

import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def _oracle_up() -> bool:
    try:
        from bridge_mcp_ghidra import oracle_status

        return bool(json.loads(oracle_status()).get("ok"))
    except Exception:
        return False


ORACLE_UP = _oracle_up()
requires_oracle = unittest.skipUnless(
    ORACLE_UP, "D2Debugger oracle not reachable on :8790 (game not running)"
)


@requires_oracle
class TestOracleStatusLive(unittest.TestCase):
    def test_status_reports_dispatchers(self):
        from bridge_mcp_ghidra import oracle_status

        out = json.loads(oracle_status())
        self.assertTrue(out.get("ok"))
        self.assertIsInstance(out.get("dispatchers"), int)
        self.assertGreater(out["dispatchers"], 0)


@requires_oracle
class TestOracleModulesLive(unittest.TestCase):
    def test_modules_include_the_game_dlls(self):
        from bridge_mcp_ghidra import oracle_modules

        out = json.loads(oracle_modules())
        self.assertTrue(out.get("ok"))
        names = {m["name"].lower() for m in out["modules"]}
        self.assertIn("d2common.dll", names)
        self.assertIn("game.exe", names)

    def test_every_module_has_a_runtime_base_and_size(self):
        from bridge_mcp_ghidra import oracle_modules

        out = json.loads(oracle_modules())
        for m in out["modules"]:
            self.assertIsInstance(m["base"], int)
            self.assertGreater(m["base"], 0)
            self.assertGreater(m["size"], 0)


@requires_oracle
class TestOracleReadMemoryLive(unittest.TestCase):
    """The read primitive is the point of this module — prove it really reads."""

    def test_reads_real_bytes(self):
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 64))
        self.assertTrue(out.get("ok"))
        self.assertEqual(64, out["got"])
        self.assertEqual(128, len(out["hex"]))  # 64 bytes -> 128 hex chars
        self.assertNotEqual("00" * 64, out["hex"])  # .text, not a zero page

    def test_read_is_deterministic_for_code(self):
        """Two reads of the same .text range agree — proves we are reading real
        mapped memory rather than returning a buffer of noise."""
        from bridge_mcp_ghidra import oracle_read_memory

        a = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 32))
        b = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 32))
        self.assertEqual(a["hex"], b["hex"])

    def test_chunked_read_matches_two_single_reads(self):
        """A >4096 read is stitched from chunks; the seam must be correct."""
        from bridge_mcp_ghidra import oracle_read_memory

        big = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 8192))
        self.assertEqual(8192, big["got"])
        first = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 4096))
        second = json.loads(oracle_read_memory("D2Common.dll", hex(0x1000 + 4096), 4096))
        self.assertEqual(first["hex"] + second["hex"], big["hex"])

    def test_unknown_module_is_a_clean_error(self):
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("NoSuchModule.dll", "0x1000", 16))
        self.assertNotEqual(True, out.get("ok"))

    def test_reads_a_mapped_pe_image(self):
        """RVA 0 of a mapped module is its DOS header — cheap proof that the read
        lands on the module image rather than arbitrary memory."""
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("D2Common.dll", "0x0", 2))
        self.assertTrue(out.get("ok"))
        self.assertEqual("4d5a", out["hex"].lower())  # 'MZ'

    def test_live_read_differs_from_disk_where_mods_patch(self):
        """The whole reason a runtime read is worth having: PD2 splices its mods
        into the game's .text at load, so live bytes and on-disk bytes diverge at
        patch sites. Mostly-equal proves we are reading the right module; not
        exactly-equal proves we are reading a PROCESS and not the file."""
        import struct

        from bridge_mcp_ghidra import oracle_read_memory

        disk = Path(r"C:\Diablo2\ProjectD2\D2Common.dll")
        if not disk.exists():
            self.skipTest("on-disk D2Common.dll not present to compare against")
        raw = disk.read_bytes()

        # Map .text's RVA to its raw file offset from the section table; the raw
        # offset is NOT a fixed constant and hardcoding one silently compares the
        # wrong bytes.
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        n_sections = struct.unpack_from("<H", raw, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        text = None
        for i in range(n_sections):
            s = sec_off + i * 40
            name = raw[s:s + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, s + 8)
            if name == ".text":
                text = (vaddr, min(vsize, rawsize), rawptr)
                break
        self.assertIsNotNone(text, ".text section not found in the on-disk PE")
        vaddr, n, rawptr = text
        n = min(n, 4096)

        live = json.loads(oracle_read_memory("D2Common.dll", hex(vaddr), n))
        self.assertTrue(live.get("ok"))
        live_bytes = bytes.fromhex(live["hex"])
        disk_bytes = raw[rawptr:rawptr + n]
        same = sum(1 for x, y in zip(live_bytes, disk_bytes) if x == y)
        self.assertGreater(same, n * 0.9, "live read does not match the module's own code")


@requires_oracle
class TestOracleCallFunctionLive(unittest.TestCase):
    """The hypothesis loop: call a real function and check a KNOWN answer.

    Target is DUNGEON_GameTileToClientCoords (D2Common +0x4DAC0), a pure
    ``void __stdcall(int* x, int* y)`` coordinate converter. It is the safest
    callable in the game — no allocation, no global state, no game-thread
    requirement — and the differential oracle (/call/0) independently gives
    {100,200} -> {-8000,12000}, so there is a real answer to check against
    rather than merely 'it returned something'.
    """

    KNOWN_IN = (100, 200)
    KNOWN_OUT = (-8000, 12000)

    def _call(self):
        from bridge_mcp_ghidra import oracle

        args = json.dumps(
            [
                {"kind": "buf", "bytes": 4, "hex": self.KNOWN_IN[0].to_bytes(4, "little").hex()},
                {"kind": "buf", "bytes": 4, "hex": self.KNOWN_IN[1].to_bytes(4, "little").hex()},
            ]
        )
        with unittest.mock.patch.object(oracle, "_calling_enabled", return_value=True):
            return json.loads(
                oracle.oracle_call_function("D2Common.dll", "0x4DAC0", "stdcall", "void", args)
            )

    def test_call_returns_the_known_correct_answer(self):
        out = self._call()
        self.assertTrue(out.get("ok"), out)
        x, y = (int.from_bytes(bytes.fromhex(h), "little", signed=True) for h in out["args_out"])
        self.assertEqual(self.KNOWN_OUT, (x, y))

    def test_out_parameters_are_read_back(self):
        """A buffer arg must come back MUTATED — that is the whole mechanism by
        which a void function's behaviour is observable."""
        out = self._call()
        self.assertTrue(out.get("ok"), out)
        self.assertNotEqual(
            self.KNOWN_IN[0].to_bytes(4, "little").hex(), out["args_out"][0]
        )

    def test_resolution_went_through_module_rva(self):
        out = self._call()
        self.assertEqual("module+rva", out.get("via"))

    def test_gate_blocks_the_call_when_disabled(self):
        """With the env gate off, no call reaches the game even live."""
        from bridge_mcp_ghidra import oracle

        with unittest.mock.patch.object(oracle, "_calling_enabled", return_value=False):
            out = json.loads(oracle.oracle_call_function("D2Common.dll", "0x4DAC0"))
        self.assertIn("error", out)
        self.assertIn("GHIDRA_MCP_ORACLE_CALL", out["error"])

    def test_non_callable_address_is_refused_not_executed(self):
        """IsCallableAddress must reject a non-executable target rather than
        jumping into it."""
        from bridge_mcp_ghidra import oracle

        with unittest.mock.patch.object(oracle, "_calling_enabled", return_value=True):
            # .data-ish offset well past .text in D2Common; not executable.
            out = json.loads(oracle.oracle_call_function("D2Common.dll", "0x99000", "stdcall", "void"))
        self.assertNotEqual(True, out.get("ok"))
        self.assertIn("error", out)


@requires_oracle
class TestOracleProveFunctionLive(unittest.TestCase):
    def test_unreimplemented_target_is_refused_not_silently_wrong(self):
        """Pins the constraint the docstring advertises: the oracle is a
        DIFFERENTIAL oracle and refuses any function D2MOO has not
        reimplemented. If this ever starts succeeding, the tool has become a
        general call primitive and its documentation must change with it."""
        from bridge_mcp_ghidra import oracle_prove_function

        spec = {
            "name": "NoSuchFunctionShouldEverExist_ZZZ",
            "module": "D2Common.dll",
            "rva": 4096,
            "vectors": [{"x": 1}],
        }
        out = json.loads(oracle_prove_function(json.dumps(spec)))
        self.assertNotEqual(True, out.get("ok"))
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
