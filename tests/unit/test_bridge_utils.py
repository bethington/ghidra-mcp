"""
Unit tests for GhidraMCP bridge utility functions.

These tests run WITHOUT requiring a Ghidra server connection.
They test transport utilities, timeout logic, and discovery functions.
"""

import json
import os
import inspect
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestGetSocketDir(unittest.TestCase):
    """Test socket directory resolution."""

    @patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=False)
    def test_xdg_runtime_dir(self):
        from bridge_mcp_ghidra import get_socket_dir

        result = get_socket_dir()
        self.assertEqual(result, Path("/run/user/1000/ghidra-mcp"))

    def test_tmpdir_fallback(self):
        # Force TMPDIR fallback by:
        #   (a) clearing XDG_RUNTIME_DIR so the function skips the first branch
        #   (b) shadowing os.getuid to return a UID whose /run/user/<uid> won't
        #       exist (CI's ubuntu-latest runner has /run/user/1001 populated,
        #       which would otherwise win before the TMPDIR branch)
        env = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
        env["TMPDIR"] = "/custom/tmp"
        env["USER"] = "testuser"
        with patch.dict(os.environ, env, clear=True), patch(
            "os.getuid", return_value=9_999_999, create=True
        ):
            from bridge_mcp_ghidra import get_socket_dir

            result = get_socket_dir()
            self.assertEqual(result, Path("/custom/tmp/ghidra-mcp-testuser"))


class TestTcpPortScan(unittest.TestCase):
    """Test _scan_tcp_for_project (issue #175 + Copilot review): when UDS
    discovery returns nothing (e.g., AF_UNIX unavailable on the host), the
    bridge must scan a TCP port range to find the matching instance instead
    of giving up on port 8089. Project matching is project-name aware so
    cross-transport behavior is consistent with UDS discovery.

    Tests patch http.client.HTTPConnection (the bridge's stdlib HTTP client)
    rather than `requests`, to keep the bridge dependency footprint minimal.
    """

    def _make_fake_conn(self, port_to_response):
        """Build a HTTPConnection stand-in driven by a {port: (status, body)}
        map. Ports not present raise ConnectionRefusedError to simulate a
        closed port."""

        class FakeResponse:
            def __init__(self, status, body):
                self.status = status
                self._body = body
            def read(self):
                return self._body.encode("utf-8") if isinstance(self._body, str) else self._body

        class FakeConn:
            def __init__(self, host, port, timeout=None):
                self.host = host
                self.port = port
                self._resp = port_to_response.get(port)
                if self._resp is None:
                    raise ConnectionRefusedError(f"no listener on {port}")
            def request(self, method, url):
                pass
            def getresponse(self):
                status, body = self._resp
                return FakeResponse(status, body)
            def close(self):
                pass

        return FakeConn

    def test_scan_finds_exact_project_match(self):
        """The first port responding with a matching project name wins."""
        from unittest.mock import patch
        import bridge_mcp_ghidra as bridge

        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "other"})),
            8090: (200, json.dumps({"project": "wanted"})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = bridge._scan_tcp_for_project("wanted", start_port=8089, range_size=4, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8090")

    def test_scan_returns_none_when_no_match(self):
        """No instance matches the project — return None so connect_instance
        produces a clear error instead of guessing."""
        from unittest.mock import patch
        import bridge_mcp_ghidra as bridge

        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "unrelated"})),
            8090: (200, json.dumps({"project": "alsoNot"})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = bridge._scan_tcp_for_project("wanted", start_port=8089, range_size=4, timeout=0.5)
        self.assertIsNone(result)

    def test_scan_returns_none_when_nothing_listening(self):
        """Every port refuses connection — return None, don't crash."""
        from unittest.mock import patch
        import bridge_mcp_ghidra as bridge

        FakeConn = self._make_fake_conn({})  # empty: every port refuses
        with patch("http.client.HTTPConnection", FakeConn):
            result = bridge._scan_tcp_for_project("wanted", start_port=8089, range_size=4, timeout=0.5)
        self.assertIsNone(result)

    def test_scan_falls_back_to_substring_when_no_exact(self):
        """Substring match is used only when no exact match is found anywhere
        in the scanned range. This mirrors the UDS match order."""
        from unittest.mock import patch
        import bridge_mcp_ghidra as bridge

        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "MyProjectVariant"})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = bridge._scan_tcp_for_project("MyProject", start_port=8089, range_size=4, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8089")

    def test_scan_exact_match_wins_over_earlier_substring(self):
        """If a substring match is found at port N but an exact match exists
        at port N+M, the exact match must win regardless of port order."""
        from unittest.mock import patch
        import bridge_mcp_ghidra as bridge

        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "Diablo2Mod"})),  # substring of "Diablo2"
            8091: (200, json.dumps({"project": "Diablo2"})),     # exact match
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = bridge._scan_tcp_for_project("Diablo2", start_port=8089, range_size=4, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8091")

    def test_scan_unwraps_data_wrapper(self):
        """/mcp/instance_info may be wrapped in {success, data} -- the scan
        must reach the project field either way (uses _unwrap_response_data)."""
        from unittest.mock import patch
        import bridge_mcp_ghidra as bridge

        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"data": {"project": "wanted"}})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = bridge._scan_tcp_for_project("wanted", start_port=8089, range_size=2, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8089")

    def test_scan_empty_project_returns_none(self):
        """Empty project name is a programming error -- return None rather
        than scan + match nothing."""
        import bridge_mcp_ghidra as bridge

        self.assertIsNone(bridge._scan_tcp_for_project(""))
        self.assertIsNone(bridge._scan_tcp_for_project(None))


class TestGetSocketDirCandidates(unittest.TestCase):
    """Test multi-directory socket discovery (issue #170)."""

    def test_candidates_includes_all_relevant_paths(self):
        """When TMPDIR is set the candidate list must include both the
        TMPDIR-derived path AND /tmp, so the bridge can find sockets
        regardless of which side knows about TMPDIR (the Claude Desktop
        spawn-without-TMPDIR case)."""
        env = {k: v for k, v in os.environ.items() if k not in ("XDG_RUNTIME_DIR",)}
        env["TMPDIR"] = "/custom/tmp"
        env["USER"] = "testuser"
        with patch.dict(os.environ, env, clear=True), patch(
            "os.getuid", return_value=9_999_999, create=True
        ):
            from bridge_mcp_ghidra import get_socket_dir_candidates

            # Use pathlib.Path equality, which normalizes separators across OSes.
            paths = get_socket_dir_candidates()
            self.assertIn(
                Path("/custom/tmp/ghidra-mcp-testuser"),
                paths,
                f"TMPDIR-derived path missing: {paths}",
            )
            self.assertIn(
                Path("/tmp/ghidra-mcp-testuser"),
                paths,
                f"/tmp fallback missing: {paths}",
            )

    def test_candidates_dedup(self):
        """Adding the same path twice (via different env hints) must not
        produce duplicates."""
        from bridge_mcp_ghidra import get_socket_dir_candidates

        paths = list(get_socket_dir_candidates())
        self.assertEqual(len(paths), len(set(paths)), f"Duplicate paths: {paths}")

    def test_macos_var_folders_glob_matches_real_layout(self):
        """The macOS per-user temp lives at
        /var/folders/<2-char>/<random>/T/ghidra-mcp-<user> -- two levels
        before T, not one (Copilot review of #195 caught the original
        glob was wrong). Fake the layout via Path.exists/Path.glob mocks
        and assert the candidate list actually includes the hit. Without
        this assertion the test could pass even if the glob never
        matched, because /tmp/ghidra-mcp-<user> is always added too."""
        env = {k: v for k, v in os.environ.items() if k != "TMPDIR"}
        env["USER"] = "testuser"

        fake_hit = Path("/var/folders/xk/randomid123/T/ghidra-mcp-testuser")

        # Patch Path.exists so /var/folders is reachable; Path.glob to
        # return the canonical macOS layout. Leave /private/var/folders
        # absent so we only assert the primary prefix.
        orig_exists = Path.exists
        orig_glob = Path.glob

        def fake_exists(self):
            if self == Path("/var/folders"):
                return True
            if self == Path("/private/var/folders"):
                return False
            return orig_exists(self)

        def fake_glob(self, pattern):
            if self == Path("/var/folders") and pattern == "*/*/T/ghidra-mcp-testuser":
                return iter([fake_hit])
            return orig_glob(self, pattern)

        with patch.dict(os.environ, env, clear=True), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "glob", fake_glob):
            from bridge_mcp_ghidra import get_socket_dir_candidates

            candidates = get_socket_dir_candidates()
            self.assertIn(
                fake_hit, candidates,
                f"macOS /var/folders glob hit must appear in candidates: {candidates}",
            )
            # And the POSIX /tmp fallback must still be there too.
            self.assertIn(Path("/tmp/ghidra-mcp-testuser"), candidates)

    def test_macos_glob_one_level_layout_does_not_match(self):
        """Regression guard: the OLD glob was `*/T/...` (one level), which
        would falsely match /var/folders/xk/T/... but miss the real macOS
        layout. The NEW glob is `*/*/T/...` (two levels). Mock a fake
        old-style layout and assert it does NOT appear in candidates."""
        env = {k: v for k, v in os.environ.items() if k != "TMPDIR"}
        env["USER"] = "testuser"

        one_level_hit = Path("/var/folders/xk/T/ghidra-mcp-testuser")
        orig_exists = Path.exists
        orig_glob = Path.glob

        def fake_exists(self):
            if self == Path("/var/folders"):
                return True
            if self == Path("/private/var/folders"):
                return False
            return orig_exists(self)

        def fake_glob(self, pattern):
            # No matches for the new two-level pattern.
            if self == Path("/var/folders") and pattern == "*/*/T/ghidra-mcp-testuser":
                return iter([])
            # If anything still asked for the old one-level pattern,
            # return a hit — we expect this branch never runs.
            if self == Path("/var/folders") and pattern == "*/T/ghidra-mcp-testuser":
                return iter([one_level_hit])
            return orig_glob(self, pattern)

        with patch.dict(os.environ, env, clear=True), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "glob", fake_glob):
            from bridge_mcp_ghidra import get_socket_dir_candidates

            candidates = get_socket_dir_candidates()
            self.assertNotIn(
                one_level_hit, candidates,
                f"old one-level glob must not match: {candidates}",
            )

    def test_macos_private_var_folders_also_covered(self):
        """macOS symlinks /var → /private/var. If the resolved socket
        appears under /private/var/folders/.../T/ghidra-mcp-<user>, the
        scan must pick it up too."""
        env = {k: v for k, v in os.environ.items() if k != "TMPDIR"}
        env["USER"] = "testuser"

        private_hit = Path("/private/var/folders/xk/randomid123/T/ghidra-mcp-testuser")
        orig_exists = Path.exists
        orig_glob = Path.glob

        def fake_exists(self):
            if self == Path("/var/folders"):
                return False  # only /private/var/folders this time
            if self == Path("/private/var/folders"):
                return True
            return orig_exists(self)

        def fake_glob(self, pattern):
            if self == Path("/private/var/folders") and pattern == "*/*/T/ghidra-mcp-testuser":
                return iter([private_hit])
            return orig_glob(self, pattern)

        with patch.dict(os.environ, env, clear=True), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "glob", fake_glob):
            from bridge_mcp_ghidra import get_socket_dir_candidates

            candidates = get_socket_dir_candidates()
            self.assertIn(
                private_hit, candidates,
                f"/private/var/folders hit must appear in candidates: {candidates}",
            )


class TestDiscoverInstancesMultiDir(unittest.TestCase):
    """End-to-end test of issue #170: discover_instances() must find sockets
    that the plugin wrote under one candidate dir (e.g. $TMPDIR) even when the
    bridge inherited a different effective socket dir.

    Sets up two temp dirs, drops a fake `ghidra-<pid>.sock` in each, monkey-
    patches get_socket_dir_candidates to return both, and verifies:
      1. Both sockets are discovered.
      2. Duplicate-path entries are deduped by absolute path.
      3. The PID-alive check still works (uses the current process PID).
    """

    def test_finds_sockets_across_dirs_and_dedups(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            pid_alive = os.getpid()  # the current process is always alive
            # Drop a socket file under each dir
            (Path(d1) / f"ghidra-{pid_alive}.sock").touch()
            (Path(d2) / f"ghidra-{pid_alive + 1000}.sock").touch()

            # is_pid_alive(pid_alive + 1000) will likely be False; that socket
            # should get cleaned up, not returned.
            from bridge_mcp_ghidra import discover_instances
            import bridge_mcp_ghidra as bridge

            # Patch both `get_socket_dir_candidates` and the UDS info query so
            # the test doesn't actually try to connect.
            with patch.object(
                bridge, "get_socket_dir_candidates",
                return_value=[Path(d1), Path(d2)],
            ), patch.object(
                bridge, "uds_request",
                return_value=("{}", 500),  # info query fails — that's fine
            ), patch.object(
                bridge, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = discover_instances()

            # Exactly one alive socket should be returned; the bogus PID's
            # socket should have been cleaned up.
            self.assertEqual(len(instances), 1)
            self.assertEqual(instances[0]["pid"], pid_alive)

    def test_dedup_when_same_path_appears_twice(self):
        """If two candidate dirs symlink to the same place (or if a symlink
        produces the same absolute path), the same socket must be reported
        only once."""
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            pid_alive = os.getpid()
            (Path(d) / f"ghidra-{pid_alive}.sock").touch()

            from bridge_mcp_ghidra import discover_instances
            import bridge_mcp_ghidra as bridge

            with patch.object(
                bridge, "get_socket_dir_candidates",
                return_value=[Path(d), Path(d)],  # same dir twice
            ), patch.object(
                bridge, "uds_request",
                return_value=("{}", 500),
            ), patch.object(
                bridge, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = discover_instances()

            self.assertEqual(len(instances), 1)


class TestIsPidAlive(unittest.TestCase):
    """Test PID liveness check."""

    def test_current_pid_alive(self):
        from bridge_mcp_ghidra import is_pid_alive

        self.assertTrue(is_pid_alive(os.getpid()))

    def test_nonexistent_pid(self):
        from bridge_mcp_ghidra import is_pid_alive

        self.assertFalse(is_pid_alive(4000000))


class TestGetTimeout(unittest.TestCase):
    """Test per-endpoint timeout calculation."""

    def test_default_timeout(self):
        from bridge_mcp_ghidra import get_timeout

        self.assertEqual(get_timeout("/some_unknown_endpoint"), 30)

    def test_decompile_timeout(self):
        from bridge_mcp_ghidra import get_timeout

        self.assertEqual(get_timeout("/decompile_function"), 45)

    def test_script_timeout(self):
        from bridge_mcp_ghidra import get_timeout

        self.assertEqual(get_timeout("/run_ghidra_script"), 1800)

    def test_batch_rename_scaling(self):
        from bridge_mcp_ghidra import get_timeout

        payload = {"variable_renames": {f"var_{i}": f"new_{i}" for i in range(10)}}
        timeout = get_timeout("/rename_variables", payload)
        self.assertGreater(timeout, 120)

    def test_batch_comments_scaling(self):
        from bridge_mcp_ghidra import get_timeout

        payload = {
            "decompiler_comments": [{"addr": "0x1000", "comment": "test"}] * 5,
            "disassembly_comments": [],
        }
        timeout = get_timeout("/batch_set_comments", payload)
        self.assertGreater(timeout, 120)


class TestBuildToolFunction(unittest.TestCase):
    """Test dynamic tool function builder."""

    def test_builds_callable(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "address": {"type": "string"},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_signature_has_correct_params(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "address": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIn("address", sig.parameters)
        self.assertIn("limit", sig.parameters)
        self.assertEqual(sig.parameters["limit"].default, 100)

    def test_required_params_no_default(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(sig.parameters["name"].default, inspect.Parameter.empty)

    def test_optional_params_default_none(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["name"].default)

    def test_type_annotations(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"},
                "ratio": {"type": "number"},
            },
            "required": ["name", "count", "enabled", "ratio"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        annotations = fn.__annotations__
        self.assertEqual(annotations["name"], str)
        self.assertEqual(annotations["count"], int)
        self.assertEqual(annotations["enabled"], bool)
        self.assertEqual(annotations["ratio"], float)

    def test_empty_schema(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {"type": "object", "properties": {}}
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 0)

    def test_post_query_params_are_not_sent_in_body(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "function_address": {
                    "type": "string",
                    "source": "body",
                    "param_type": "address",
                },
                "prototype": {"type": "string", "source": "body"},
                "program": {"type": "string", "source": "query", "default": ""},
            },
            "required": ["function_address", "prototype"],
        }
        fn = _build_tool_function("/set_function_prototype", "POST", schema)

        with patch("bridge_mcp_ghidra.dispatch_post") as mock_dispatch_post:
            mock_dispatch_post.return_value = "ok"
            result = fn(
                function_address="6FA26FD0",
                prototype="undefined4 __fastcall FUN_6fa26fd0(int param_1, uint param_2)",
                program="/Vanilla/1.13d/D2MCPClient.dll",
            )

        self.assertEqual(result, "ok")
        mock_dispatch_post.assert_called_once_with(
            "/set_function_prototype",
            data={
                "function_address": "0x6fa26fd0",
                "prototype": "undefined4 __fastcall FUN_6fa26fd0(int param_1, uint param_2)",
            },
            query_params={"program": "/Vanilla/1.13d/D2MCPClient.dll"},
        )


class TestToolNameSanitization(unittest.TestCase):
    """Test MCP tool name normalization for strict clients."""

    def test_sanitize_tool_name_replaces_invalid_separators(self):
        from bridge_mcp_ghidra import sanitize_tool_name

        self.assertEqual(sanitize_tool_name("/Debugger.Status "), "debugger_status")
        self.assertEqual(sanitize_tool_name("server/status"), "server_status")
        self.assertEqual(sanitize_tool_name("A::B...C"), "a_b_c")

    def test_sanitize_tool_name_truncates_to_claude_limit(self):
        from bridge_mcp_ghidra import MAX_TOOL_NAME_LENGTH, sanitize_tool_name

        raw = "/" + ("VeryLongToolNameSegment_" * 6)
        sanitized = sanitize_tool_name(raw)

        self.assertLessEqual(len(sanitized), MAX_TOOL_NAME_LENGTH)
        self.assertRegex(sanitized, r"^[a-zA-Z0-9_-]{1,64}$")

    def test_sanitize_tool_name_rejects_empty_names(self):
        from bridge_mcp_ghidra import sanitize_tool_name

        with self.assertRaises(ValueError):
            sanitize_tool_name("///")

    def test_parse_schema_normalizes_nested_endpoint_paths(self):
        from bridge_mcp_ghidra import _parse_schema

        schema = _parse_schema(
            {
                "tools": [
                    {
                        "path": "/server/status",
                        "method": "GET",
                        "params": [],
                    }
                ]
            }
        )
        self.assertEqual(schema[0]["name"], "server_status")
        self.assertEqual(schema[0]["endpoint"], "/server/status")

    def test_parse_schema_suffixes_static_name_collisions(self):
        from bridge_mcp_ghidra import _parse_schema

        schema = _parse_schema(
            {
                "tools": [
                    {
                        "path": "/debugger/status",
                        "method": "GET",
                        "params": [],
                    }
                ]
            }
        )
        self.assertEqual(schema[0]["name"], "debugger_status_2")
        self.assertEqual(schema[0]["sanitized_name"], "debugger_status")
        self.assertTrue(schema[0]["name_collided"])

    def test_parse_schema_suffixes_dynamic_name_collisions(self):
        from bridge_mcp_ghidra import _parse_schema

        schema = _parse_schema(
            {
                "tools": [
                    {"path": "/foo.bar", "method": "GET", "params": []},
                    {"path": "/foo/bar", "method": "GET", "params": []},
                ]
            }
        )
        self.assertEqual([tool["name"] for tool in schema], ["foo_bar", "foo_bar_2"])

    def test_parse_schema_suffixes_truncated_name_collisions_within_limit(self):
        from bridge_mcp_ghidra import MAX_TOOL_NAME_LENGTH, _parse_schema

        raw = "/" + ("LongEndpointSegment_" * 5)
        schema = _parse_schema(
            {
                "tools": [
                    {"path": raw, "method": "GET", "params": []},
                    {"path": raw + "/v2", "method": "GET", "params": []},
                ]
            }
        )

        self.assertLessEqual(len(schema[0]["name"]), MAX_TOOL_NAME_LENGTH)
        self.assertLessEqual(len(schema[1]["name"]), MAX_TOOL_NAME_LENGTH)
        self.assertNotEqual(schema[0]["name"], schema[1]["name"])
        self.assertRegex(schema[0]["name"], r"^[a-zA-Z0-9_-]{1,64}$")
        self.assertRegex(schema[1]["name"], r"^[a-zA-Z0-9_-]{1,64}$")

    def test_active_registry_tool_names_are_valid(self):
        import bridge_mcp_ghidra as bridge

        pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        invalid = [
            name
            for name in bridge.mcp._tool_manager._tools
            if not pattern.fullmatch(name)
        ]
        self.assertEqual(invalid, [])

    def test_registered_dynamic_tool_names_are_valid(self):
        import bridge_mcp_ghidra as bridge

        schema = bridge._parse_schema(
            {
                "tools": [
                    {"path": "/server/status", "method": "GET", "params": []},
                    {"path": "/debugger/status", "method": "GET", "params": []},
                    {"path": "/foo.bar", "method": "GET", "params": []},
                    {"path": "/foo/bar", "method": "GET", "params": []},
                ]
            }
        )

        bridge.register_tools_from_schema(schema, groups=None)
        pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        try:
            invalid = [
                name
                for name in bridge.mcp._tool_manager._tools
                if not pattern.fullmatch(name)
            ]
            self.assertEqual(invalid, [])
            self.assertIn("server_status", bridge.mcp._tool_manager._tools)
            self.assertIn("debugger_status_2", bridge.mcp._tool_manager._tools)
            self.assertIn("foo_bar", bridge.mcp._tool_manager._tools)
            self.assertIn("foo_bar_2", bridge.mcp._tool_manager._tools)
        finally:
            bridge.register_tools_from_schema([], groups=None)


class TestRegisterToolsFromSchema(unittest.TestCase):
    """Test dynamic tool registration from schema."""

    def test_registers_tools(self):
        from bridge_mcp_ghidra import register_tools_from_schema, _dynamic_tool_names

        schema = [
            {
                "name": "test_tool_reg_1",
                "description": "A test tool",
                "endpoint": "/test1",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "test_tool_reg_2",
                "description": "Another test tool",
                "endpoint": "/test2",
                "http_method": "POST",
                "input_schema": {
                    "type": "object",
                    "properties": {"data": {"type": "string"}},
                    "required": ["data"],
                },
            },
        ]
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 2)
        self.assertIn("test_tool_reg_1", _dynamic_tool_names)
        self.assertIn("test_tool_reg_2", _dynamic_tool_names)

    def test_register_skips_bad_tool_and_continues(self):
        import bridge_mcp_ghidra as bridge

        schema = [
            {
                "name": "issue_212_valid_before",
                "description": "",
                "endpoint": "/issue_212_valid_before",
                "http_method": "GET",
                "category": "listing",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "issue_212_bad_signature",
                "description": "",
                "endpoint": "/issue_212_bad_signature",
                "http_method": "GET",
                "category": "listing",
                "input_schema": {
                    "type": "object",
                    "properties": {"bad-param": {"type": "string"}},
                },
            },
            {
                "name": "issue_212_valid_after",
                "description": "",
                "endpoint": "/issue_212_valid_after",
                "http_method": "GET",
                "category": "listing",
                "input_schema": {"type": "object", "properties": {}},
            },
        ]

        try:
            with patch("sys.stderr") as mock_stderr:
                count = bridge.register_tools_from_schema(schema)

            self.assertEqual(count, 2)
            self.assertIn("issue_212_valid_before", bridge._dynamic_tool_names)
            self.assertIn("issue_212_valid_after", bridge._dynamic_tool_names)
            self.assertNotIn("issue_212_bad_signature", bridge._dynamic_tool_names)
            message = mock_stderr.write.call_args.args[0]
            self.assertIn("1 tool(s) failed to register", message)
            self.assertIn("issue_212_bad_signature", message)
            self.assertIn("bad-param", message)
        finally:
            bridge.register_tools_from_schema([])

    def test_clears_previous_tools(self):
        from bridge_mcp_ghidra import register_tools_from_schema, _dynamic_tool_names

        schema1 = [
            {
                "name": "old_tool_clear",
                "description": "",
                "endpoint": "/old",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        schema2 = [
            {
                "name": "new_tool_clear",
                "description": "",
                "endpoint": "/new",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        register_tools_from_schema(schema1)
        self.assertIn("old_tool_clear", _dynamic_tool_names)
        register_tools_from_schema(schema2)
        self.assertNotIn("old_tool_clear", _dynamic_tool_names)
        self.assertIn("new_tool_clear", _dynamic_tool_names)


class TestDispatchErrors(unittest.TestCase):
    """Test dispatch functions when no instance connected."""

    def test_dispatch_get_no_connection(self):
        import bridge_mcp_ghidra as bridge

        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_get("/test")
            data = json.loads(result)
            self.assertIn("error", data)
            self.assertIn("connect_instance", data["error"])
        finally:
            bridge._transport_mode = old

    def test_dispatch_post_no_connection(self):
        import bridge_mcp_ghidra as bridge

        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_post("/test", {"key": "value"})
            data = json.loads(result)
            self.assertIn("error", data)
        finally:
            bridge._transport_mode = old


class TestUnixHTTPConnection(unittest.TestCase):
    """Test UnixHTTPConnection class."""

    def test_sets_socket_path(self):
        from bridge_mcp_ghidra import UnixHTTPConnection

        conn = UnixHTTPConnection("/tmp/test.sock", timeout=10)
        self.assertEqual(conn.socket_path, "/tmp/test.sock")
        self.assertEqual(conn.timeout, 10)


if __name__ == "__main__":
    unittest.main()
