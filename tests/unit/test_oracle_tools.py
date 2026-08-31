"""Unit tests for the D2Debugger in-process oracle proxy tools.

No Ghidra, no game, no network: every test either exercises pure argument
handling or patches ``bridge_mcp_ghidra.oracle._oracle_request``.

These are deliberately NOT the whole story. The debugger proxy tools were
unit-tested against a mocked pybag and stayed green for months while the real
stack faulted on first live attach, so a mocked suite proves argument handling
and nothing else. The live gate for these tools is
``tests/integration/test_oracle_live.py``.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestOracleEnabled(unittest.TestCase):
    """_oracle_enabled gates registration; the oracle only exists inside a
    Windows game process, so a *local* oracle URL cannot be served elsewhere."""

    def test_disabled_on_non_windows_with_local_url(self):
        from bridge_mcp_ghidra import _oracle_enabled

        self.assertFalse(_oracle_enabled(url="http://127.0.0.1:8790", platform="linux", override=None))

    def test_disabled_on_non_windows_with_localhost_name(self):
        from bridge_mcp_ghidra import _oracle_enabled

        self.assertFalse(_oracle_enabled(url="http://localhost:8790", platform="darwin", override=None))

    def test_enabled_on_non_windows_with_remote_host(self):
        from bridge_mcp_ghidra import _oracle_enabled

        self.assertTrue(_oracle_enabled(url="http://winbox.lan:8790", platform="linux", override=None))

    def test_enabled_on_windows_with_local_url(self):
        from bridge_mcp_ghidra import _oracle_enabled

        self.assertTrue(_oracle_enabled(url="http://127.0.0.1:8790", platform="win32", override=None))

    def test_override_forces_off_even_on_windows(self):
        from bridge_mcp_ghidra import _oracle_enabled

        self.assertFalse(_oracle_enabled(url="http://127.0.0.1:8790", platform="win32", override="0"))

    def test_blank_override_is_ignored(self):
        from bridge_mcp_ghidra import _oracle_enabled

        self.assertFalse(_oracle_enabled(url="http://127.0.0.1:8790", platform="linux", override=""))


class TestOracleToolRegistration(unittest.TestCase):
    def test_functions_always_defined(self):
        import bridge_mcp_ghidra as bridge

        for fn in (bridge.oracle_status, bridge.oracle_modules,
                   bridge.oracle_read_memory, bridge.oracle_call_function,
                   bridge.oracle_prove_function):
            self.assertTrue(callable(fn))

    def test_names_reserved_on_every_platform(self):
        """Reserved in the structural set everywhere so dynamic tool naming is
        platform-stable, exactly like the debugger names."""
        import bridge_mcp_ghidra as bridge

        self.assertTrue(bridge.ORACLE_TOOL_NAMES.issubset(bridge._ALL_STATIC_TOOL_NAMES))

    def test_no_name_collision_with_debugger_tools(self):
        import bridge_mcp_ghidra as bridge

        self.assertEqual(set(), bridge.ORACLE_TOOL_NAMES & bridge.DEBUGGER_TOOL_NAMES)

    @unittest.skipIf(sys.platform.startswith("win"), "oracle tools active on Windows")
    def test_not_registered_on_non_windows(self):
        import bridge_mcp_ghidra as bridge

        self.assertNotIn("oracle_read_memory", bridge.STATIC_TOOL_NAMES)


class TestOracleReadMemoryArgs(unittest.TestCase):
    """Argument handling for oracle_read_memory — all local, no requests."""

    def test_rejects_bad_rva(self):
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("D2Common.dll", "not-a-number", 16))
        self.assertIn("error", out)
        self.assertIn("Invalid rva", out["error"])

    def test_rejects_negative_rva(self):
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("D2Common.dll", "-4", 16))
        self.assertIn("error", out)

    def test_rejects_zero_length(self):
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 0))
        self.assertIn("error", out)

    def test_rejects_oversized_length(self):
        from bridge_mcp_ghidra import oracle_read_memory

        out = json.loads(oracle_read_memory("D2Common.dll", "0x1000", 1 << 20))
        self.assertIn("error", out)
        self.assertIn("maximum", out["error"])

    def test_accepts_hex_and_decimal_rva(self):
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"ok": True, "hex": "00" * 16, "got": 16})
            oracle.oracle_read_memory("D2Common.dll", "0x1000", 16)
            self.assertEqual(req.call_args[0][2]["rva"], hex(0x1000))

            req.reset_mock()
            oracle.oracle_read_memory("D2Common.dll", "4096", 16)
            self.assertEqual(req.call_args[0][2]["rva"], hex(4096))

    def test_chunks_reads_over_4096(self):
        """The server clamps a single /asset/read at 4096; the tool must chunk."""
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"ok": True, "hex": "aa" * 4096, "got": 4096})
            out = json.loads(oracle.oracle_read_memory("D2Common.dll", "0x0", 8192))
            self.assertEqual(2, req.call_count)
            self.assertEqual(8192, out["got"])
            self.assertFalse(out["truncated"])

    def test_short_read_marks_truncated_and_stops(self):
        """A partial read means an unmapped page — return the readable prefix
        rather than pretending the whole range came back."""
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"ok": True, "hex": "bb" * 100, "got": 100})
            out = json.loads(oracle.oracle_read_memory("D2Common.dll", "0x0", 8192))
            self.assertEqual(1, req.call_count)  # stopped after the short chunk
            self.assertEqual(100, out["got"])
            self.assertTrue(out["truncated"])

    def test_error_on_first_chunk_is_surfaced(self):
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"error": "game not reachable"})
            out = json.loads(oracle.oracle_read_memory("D2Common.dll", "0x0", 64))
            self.assertIn("error", out)

    def test_zero_bytes_read_is_an_error_not_an_empty_success(self):
        """Regression: the oracle answers ok:true / got:0 for a module it cannot
        resolve, so a naive pass-through reported SUCCESS with no bytes. An agent
        reads that as 'this address holds no data' when the truth is 'that module
        is not loaded'. Caught by the live gate, pinned here.
        """
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"ok": True, "hex": "", "got": 0})
            out = json.loads(oracle.oracle_read_memory("NoSuchModule.dll", "0x1000", 64))
        self.assertIn("error", out)
        self.assertNotEqual(True, out.get("ok"))
        self.assertIn("not", out["error"].lower())


class TestOracleProveFunctionArgs(unittest.TestCase):
    """oracle_prove_function must reject specs the oracle would reject anyway,
    with a message that explains the differential-only constraint."""

    def test_rejects_non_json_spec(self):
        from bridge_mcp_ghidra import oracle_prove_function

        out = json.loads(oracle_prove_function("{not json"))
        self.assertIn("error", out)

    def test_rejects_missing_name(self):
        from bridge_mcp_ghidra import oracle_prove_function

        out = json.loads(oracle_prove_function(json.dumps({"vectors": [{"x": 1}]})))
        self.assertIn("error", out)
        self.assertIn("name", out["error"])

    def test_rejects_missing_vectors(self):
        from bridge_mcp_ghidra import oracle_prove_function

        out = json.loads(oracle_prove_function(json.dumps({"name": "Foo"})))
        self.assertIn("error", out)
        self.assertIn("vectors", out["error"])

    def test_rejects_empty_vectors(self):
        from bridge_mcp_ghidra import oracle_prove_function

        out = json.loads(oracle_prove_function(json.dumps({"name": "Foo", "vectors": []})))
        self.assertIn("error", out)

    def test_valid_spec_is_forwarded(self):
        from bridge_mcp_ghidra import oracle

        spec = {"name": "Foo", "vectors": [{"x": 1}], "module": "D2Common.dll", "rva": 4096}
        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"ok": True})
            oracle.oracle_prove_function(json.dumps(spec))
            self.assertEqual("/oracle", req.call_args[0][1])
            self.assertEqual(spec, req.call_args[0][2])

    def test_docstring_states_the_reimpl_constraint(self):
        """The tool must not read as a general 'call any function' primitive:
        the oracle refuses any target D2MOO has not reimplemented, and an agent
        that believes otherwise will plan work it cannot do."""
        from bridge_mcp_ghidra import oracle_prove_function

        doc = (oracle_prove_function.__doc__ or "").lower()
        self.assertIn("reimpl", doc)
        self.assertIn("not a general", doc)


class TestOracleCallFunctionGate(unittest.TestCase):
    """Calling into the live game is the one primitive that can do damage a
    restart does not undo, so it must be OFF unless explicitly enabled."""

    def test_disabled_by_default(self):
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_calling_enabled", return_value=False):
            out = json.loads(oracle.oracle_call_function("D2Common.dll", "0x4dac0"))
        self.assertIn("error", out)
        self.assertIn("GHIDRA_MCP_ORACLE_CALL", out["error"])

    def test_gate_reads_the_env_var(self):
        from bridge_mcp_ghidra import _calling_enabled

        self.assertTrue(_calling_enabled(override="1"))
        self.assertTrue(_calling_enabled(override="true"))
        self.assertFalse(_calling_enabled(override="0"))
        self.assertFalse(_calling_enabled(override=""))
        self.assertFalse(_calling_enabled(override=None) if os.getenv("GHIDRA_MCP_ORACLE_CALL") is None else False)

    def test_no_request_is_issued_while_disabled(self):
        """The gate must short-circuit BEFORE any HTTP call reaches the game."""
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_calling_enabled", return_value=False), \
             patch.object(oracle, "_oracle_request") as req:
            oracle.oracle_call_function("D2Common.dll", "0x4dac0")
            req.assert_not_called()


class TestOracleCallFunctionArgs(unittest.TestCase):
    def setUp(self):
        from bridge_mcp_ghidra import oracle

        self._patch = patch.object(oracle, "_calling_enabled", return_value=True)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_rejects_absolute_address_mistaken_for_rva(self):
        """A Ghidra absolute (e.g. 0x6fd51000) is wrong in the live process for
        any relocated module — refuse rather than call into whatever is mapped."""
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            out = json.loads(oracle.oracle_call_function("D2Common.dll", "0x6fd51000"))
            req.assert_not_called()
        self.assertIn("error", out)
        self.assertIn("absolute", out["error"])

    def test_rejects_bad_args_json(self):
        from bridge_mcp_ghidra import oracle

        out = json.loads(oracle.oracle_call_function("D2Common.dll", "0x1000", args="{nope"))
        self.assertIn("error", out)

    def test_rejects_too_many_args(self):
        from bridge_mcp_ghidra import oracle

        nine = json.dumps([{"kind": "i32", "value": 0}] * 9)
        out = json.loads(oracle.oracle_call_function("D2Common.dll", "0x1000", args=nine))
        self.assertIn("error", out)
        self.assertIn("8 slots", out["error"])

    def test_rejects_missing_module(self):
        from bridge_mcp_ghidra import oracle

        out = json.loads(oracle.oracle_call_function("", "0x1000"))
        self.assertIn("error", out)

    def test_forwards_a_valid_call(self):
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "_oracle_request") as req:
            req.return_value = json.dumps({"ok": True})
            oracle.oracle_call_function(
                "D2Common.dll", "0x4dac0", callconv="stdcall", ret="void",
                args=json.dumps([{"kind": "buf", "bytes": 4, "hex": "64000000"}]),
            )
        body = req.call_args[0][2]
        self.assertEqual("/call_original", req.call_args[0][1])
        self.assertEqual("D2Common.dll", body["module"])
        self.assertEqual(hex(0x4DAC0), body["rva"])
        self.assertEqual("stdcall", body["callconv"])
        self.assertEqual(1, len(body["args"]))


class TestOracleRequestSafety(unittest.TestCase):
    def test_refuses_non_loopback_url(self):
        """The oracle exposes arbitrary memory writes and in-process calls, so a
        stray/hostile D2DBG_MCP_URL must never redirect this traffic off-box."""
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle, "ORACLE_URL", "http://evil.example:8790"):
            out = json.loads(oracle._oracle_request("GET", "/status"))
        self.assertIn("error", out)
        self.assertIn("non-loopback", out["error"])

    def test_connection_refused_is_not_an_exception(self):
        """A down game is the normal case (it is relaunched often) — the tool
        must return a readable error, never raise."""
        from bridge_mcp_ghidra import oracle

        with patch.object(oracle.http.client, "HTTPConnection") as conn:
            conn.return_value.request.side_effect = ConnectionRefusedError()
            out = json.loads(oracle._oracle_request("GET", "/status"))
        self.assertIn("error", out)
        self.assertIn("not reachable", out["error"])


if __name__ == "__main__":
    unittest.main()
