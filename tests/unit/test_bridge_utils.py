"""
Unit tests for ghidra_mcp_bridge utility functions.

These tests run WITHOUT requiring a Ghidra server connection. They test
transport utilities, timeout logic, and discovery functions against the
``ghidra_mcp_bridge`` package.
"""

import asyncio
import json
import os
import inspect
import re
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ghidra_mcp_bridge import connection, discovery, registry, validation
from ghidra_mcp_bridge.config import MAX_TOOL_NAME_LENGTH
from ghidra_mcp_bridge.discovery import _scan_tcp_for_project, discover_instances
from ghidra_mcp_bridge.schema import build_tool_function, parse_schema
from ghidra_mcp_bridge.transport import (
    UnixHTTPConnection,
    get_socket_dir,
    get_socket_dir_candidates,
)
from ghidra_mcp_bridge.validation import is_pid_alive, sanitize_tool_name


class TestGetSocketDir(unittest.TestCase):
    """Test socket directory resolution."""

    @patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=False)
    def test_xdg_runtime_dir(self):
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
        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "other"})),
            8090: (200, json.dumps({"project": "wanted"})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = _scan_tcp_for_project("wanted", start_port=8089, range_size=4, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8090")

    def test_scan_returns_none_when_no_match(self):
        """No instance matches the project — return None so connect_instance
        produces a clear error instead of guessing."""
        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "unrelated"})),
            8090: (200, json.dumps({"project": "alsoNot"})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = _scan_tcp_for_project("wanted", start_port=8089, range_size=4, timeout=0.5)
        self.assertIsNone(result)

    def test_scan_returns_none_when_nothing_listening(self):
        """Every port refuses connection — return None, don't crash."""
        FakeConn = self._make_fake_conn({})  # empty: every port refuses
        with patch("http.client.HTTPConnection", FakeConn):
            result = _scan_tcp_for_project("wanted", start_port=8089, range_size=4, timeout=0.5)
        self.assertIsNone(result)

    def test_scan_falls_back_to_substring_when_no_exact(self):
        """Substring match is used only when no exact match is found anywhere
        in the scanned range. This mirrors the UDS match order."""
        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "MyProjectVariant"})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = _scan_tcp_for_project("MyProject", start_port=8089, range_size=4, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8089")

    def test_scan_exact_match_wins_over_earlier_substring(self):
        """If a substring match is found at port N but an exact match exists
        at port N+M, the exact match must win regardless of port order."""
        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"project": "Diablo2Mod"})),  # substring of "Diablo2"
            8091: (200, json.dumps({"project": "Diablo2"})),     # exact match
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = _scan_tcp_for_project("Diablo2", start_port=8089, range_size=4, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8091")

    def test_scan_unwraps_data_wrapper(self):
        """/mcp/instance_info may be wrapped in {success, data} -- the scan
        must reach the project field either way (uses _unwrap_response_data)."""
        FakeConn = self._make_fake_conn({
            8089: (200, json.dumps({"data": {"project": "wanted"}})),
        })
        with patch("http.client.HTTPConnection", FakeConn):
            result = _scan_tcp_for_project("wanted", start_port=8089, range_size=2, timeout=0.5)
        self.assertEqual(result, "http://127.0.0.1:8089")

    def test_scan_empty_project_returns_none(self):
        """Empty project name is a programming error -- return None rather
        than scan + match nothing."""
        self.assertIsNone(_scan_tcp_for_project(""))
        self.assertIsNone(_scan_tcp_for_project(None))


class TestResolveTcpProject(unittest.TestCase):
    """Test _resolve_tcp_project: reads the canonical project name from a TCP
    instance's /mcp/instance_info so connect_instance's TCP path records the
    project it actually reached, not a substring the caller typed or a stale
    name from a prior UDS session."""

    def test_returns_project_on_success(self):
        with patch.object(discovery, "tcp_request",
                          return_value=(json.dumps({"project": "Diablo2"}), 200)):
            self.assertEqual(
                discovery._resolve_tcp_project("http://127.0.0.1:8089"), "Diablo2"
            )

    def test_unwraps_data_wrapper(self):
        with patch.object(discovery, "tcp_request",
                          return_value=(json.dumps({"data": {"project": "Wrapped"}}), 200)):
            self.assertEqual(
                discovery._resolve_tcp_project("http://127.0.0.1:8089"), "Wrapped"
            )

    def test_non_200_returns_none(self):
        with patch.object(discovery, "tcp_request", return_value=("nope", 500)):
            self.assertIsNone(discovery._resolve_tcp_project("http://127.0.0.1:8089"))

    def test_exception_returns_none(self):
        with patch.object(discovery, "tcp_request",
                          side_effect=ConnectionRefusedError("down")):
            self.assertIsNone(discovery._resolve_tcp_project("http://127.0.0.1:8089"))

    def test_missing_or_empty_project_returns_none(self):
        with patch.object(discovery, "tcp_request",
                          return_value=(json.dumps({"project": ""}), 200)):
            self.assertIsNone(discovery._resolve_tcp_project("http://127.0.0.1:8089"))
        with patch.object(discovery, "tcp_request",
                          return_value=(json.dumps({"pid": 1}), 200)):
            self.assertIsNone(discovery._resolve_tcp_project("http://127.0.0.1:8089"))


class TestConnectInstanceTcpProject(unittest.TestCase):
    """connect_instance's TCP fallback must update _connected_project to the
    instance it reached, never leaving a stale name from a prior UDS session
    (Copilot review item). Otherwise a dropped/reset TCP session would trigger
    reconnect attempts/messages naming the wrong project."""

    def setUp(self):
        from ghidra_mcp_bridge import tools
        self.tools = tools
        # Snapshot and fully restore connection globals -- reset() deliberately
        # preserves _connected_project, which would leak into other tests.
        saved = (
            connection._active_socket,
            connection._active_tcp,
            connection._transport_mode,
            connection._connected_project,
        )

        def _restore():
            (connection._active_socket, connection._active_tcp,
             connection._transport_mode, connection._connected_project) = saved

        self.addCleanup(_restore)
        # Prime a stale UDS session so a leftover project name is present.
        connection.activate_uds("/tmp/ghidra-stale.sock", "StaleUdsProject")

    def _run(self, project):
        return asyncio.run(self.tools.connect_instance(project))

    @patch.dict(os.environ, {}, clear=False)
    def test_tcp_connect_records_resolved_project(self):
        os.environ.pop("GHIDRA_MCP_URL", None)
        with patch.object(self.tools.discovery, "discover_instances", return_value=[]), \
             patch.object(self.tools.discovery, "_scan_tcp_for_project",
                          return_value="http://127.0.0.1:8090"), \
             patch.object(self.tools.discovery, "_resolve_tcp_project",
                          return_value="ResolvedProject"), \
             patch.object(self.tools.registry, "fetch_and_register_schema", return_value=7):
            result = json.loads(self._run("Resolved"))

        self.assertTrue(result["connected"])
        self.assertEqual(result["project"], "ResolvedProject")
        self.assertEqual(connection.connected_project(), "ResolvedProject")
        self.assertEqual(connection.transport_mode(), "tcp")
        self.assertEqual(connection.active_tcp(), "http://127.0.0.1:8090")

    @patch.dict(os.environ, {}, clear=False)
    def test_tcp_connect_falls_back_to_requested_project(self):
        """If instance_info can't be read, record the requested name -- still
        better than a stale UDS leftover."""
        os.environ.pop("GHIDRA_MCP_URL", None)
        with patch.object(self.tools.discovery, "discover_instances", return_value=[]), \
             patch.object(self.tools.discovery, "_scan_tcp_for_project",
                          return_value="http://127.0.0.1:8090"), \
             patch.object(self.tools.discovery, "_resolve_tcp_project", return_value=None), \
             patch.object(self.tools.registry, "fetch_and_register_schema", return_value=3):
            json.loads(self._run("Requested"))

        self.assertEqual(connection.connected_project(), "Requested")

    @patch.dict(os.environ, {}, clear=False)
    def test_failed_tcp_connect_resets_to_fresh_project_not_stale(self):
        """When the schema fetch fails the transport resets but preserves
        _connected_project for reconnect -- it must be the project we just
        tried (not the stale UDS leftover) so reconnect targets the right one."""
        os.environ.pop("GHIDRA_MCP_URL", None)
        with patch.object(self.tools.discovery, "discover_instances", return_value=[]), \
             patch.object(self.tools.discovery, "_scan_tcp_for_project",
                          return_value="http://127.0.0.1:8090"), \
             patch.object(self.tools.discovery, "_resolve_tcp_project",
                          return_value="FreshProject"), \
             patch.object(self.tools.registry, "fetch_and_register_schema",
                          side_effect=RuntimeError("schema boom")):
            result = json.loads(self._run("Fresh"))

        self.assertIn("error", result)
        self.assertEqual(connection.transport_mode(), "none")
        self.assertEqual(connection.connected_project(), "FreshProject")


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
        paths = list(get_socket_dir_candidates())
        self.assertEqual(len(paths), len(set(paths)), f"Duplicate paths: {paths}")

    def test_macos_var_folders_glob_matches_real_layout(self):
        """The macOS per-user temp lives at
        /var/folders/<2-char>/<random>/T/ghidra-mcp-<user> -- two levels
        before T, not one (Copilot review of #195 caught the original
        glob was wrong). Fake the layout via Path.exists/Path.glob mocks
        and assert the candidate list actually includes the hit."""
        env = {k: v for k, v in os.environ.items() if k != "TMPDIR"}
        env["USER"] = "testuser"

        fake_hit = Path("/var/folders/xk/randomid123/T/ghidra-mcp-testuser")

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
            candidates = get_socket_dir_candidates()
            self.assertIn(
                private_hit, candidates,
                f"/private/var/folders hit must appear in candidates: {candidates}",
            )


class TestDiscoverInstancesMultiDir(unittest.TestCase):
    """End-to-end test of issue #170: discover_instances() must find sockets
    that the plugin wrote under one candidate dir (e.g. $TMPDIR) even when the
    bridge inherited a different effective socket dir.

    discover_instances looks up get_socket_dir_candidates / uds_request /
    is_pid_alive as names in the ``discovery`` module, so patch them there.
    """

    def test_finds_sockets_across_dirs_and_dedups(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            pid_alive = os.getpid()  # the current process is always alive
            # Drop a socket file under each dir
            (Path(d1) / f"ghidra-{pid_alive}.sock").touch()
            (Path(d2) / f"ghidra-{pid_alive + 1000}.sock").touch()

            with patch.object(
                discovery, "get_socket_dir_candidates",
                return_value=[Path(d1), Path(d2)],
            ), patch.object(
                discovery, "uds_request",
                return_value=("{}", 500),  # info query fails — that's fine
            ), patch.object(
                discovery, "is_pid_alive",
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

            with patch.object(
                discovery, "get_socket_dir_candidates",
                return_value=[Path(d), Path(d)],  # same dir twice
            ), patch.object(
                discovery, "uds_request",
                return_value=("{}", 500),
            ), patch.object(
                discovery, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = discover_instances()

            self.assertEqual(len(instances), 1)


class TestIsPidAlive(unittest.TestCase):
    """Test PID liveness check."""

    def test_current_pid_alive(self):
        self.assertTrue(is_pid_alive(os.getpid()))

    def test_nonexistent_pid(self):
        self.assertFalse(is_pid_alive(4000000))


class TestIsPidAliveWindows(unittest.TestCase):
    """Windows liveness path (Copilot review): OpenProcess returns a 64-bit
    HANDLE, so the kernel32 prototypes must be declared or ctypes truncates it
    to c_int -- corrupting the result and the value handed to CloseHandle. The
    failure code must come from get_last_error (use_last_error), not a value
    ctypes may have clobbered. These run on any OS because kernel32 is mocked."""

    def setUp(self):
        # _win_kernel32_lib caches the configured lib; isolate each test.
        self._saved_cache = validation._win_kernel32
        validation._win_kernel32 = None

        def _restore():
            validation._win_kernel32 = self._saved_cache

        self.addCleanup(_restore)

    def test_kernel32_prototypes_are_handle_safe(self):
        """_win_kernel32_lib must set 64-bit-safe restype/argtypes and request
        use_last_error so handles aren't truncated on 64-bit Python."""
        import ctypes
        from ctypes import wintypes

        recorded = {}

        class FakeFunc:
            pass

        class FakeWinDLL:
            def __init__(self, name, use_last_error=False):
                recorded["name"] = name
                recorded["use_last_error"] = use_last_error
                self.OpenProcess = FakeFunc()
                self.CloseHandle = FakeFunc()

        with patch.object(ctypes, "WinDLL", FakeWinDLL, create=True):
            lib = validation._win_kernel32_lib()

        self.assertEqual(recorded["name"], "kernel32")
        self.assertTrue(recorded["use_last_error"])
        self.assertIs(lib.OpenProcess.restype, wintypes.HANDLE)
        self.assertEqual(
            lib.OpenProcess.argtypes,
            (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD),
        )
        self.assertIs(lib.CloseHandle.restype, wintypes.BOOL)
        self.assertEqual(lib.CloseHandle.argtypes, (wintypes.HANDLE,))

    def test_kernel32_lib_is_cached(self):
        import ctypes

        calls = []

        class FakeWinDLL:
            def __init__(self, name, use_last_error=False):
                calls.append(name)
                self.OpenProcess = Mock()
                self.CloseHandle = Mock()

        with patch.object(ctypes, "WinDLL", FakeWinDLL, create=True):
            first = validation._win_kernel32_lib()
            second = validation._win_kernel32_lib()

        self.assertIs(first, second)
        self.assertEqual(len(calls), 1)  # configured once, then reused

    def test_open_succeeds_returns_true_and_closes_exact_handle(self):
        import ctypes

        # A handle wider than 32 bits: the call path must hand this exact value
        # to CloseHandle (the declared HANDLE restype prevents truncation).
        big_handle = 0x1_2345_6789
        fake = Mock()
        fake.OpenProcess.return_value = big_handle
        with patch.object(validation.os, "name", "nt"), patch.object(
            validation, "_win_kernel32_lib", return_value=fake
        ), patch.object(ctypes, "get_last_error", return_value=0, create=True):
            self.assertTrue(validation.is_pid_alive(1234))
        fake.OpenProcess.assert_called_once_with(0x1000, False, 1234)
        fake.CloseHandle.assert_called_once_with(big_handle)

    def test_access_denied_means_alive(self):
        import ctypes

        fake = Mock()
        fake.OpenProcess.return_value = 0  # NULL handle
        with patch.object(validation.os, "name", "nt"), patch.object(
            validation, "_win_kernel32_lib", return_value=fake
        ), patch.object(ctypes, "get_last_error", return_value=5, create=True):
            self.assertTrue(validation.is_pid_alive(1234))  # ERROR_ACCESS_DENIED
        fake.CloseHandle.assert_not_called()

    def test_other_error_means_dead(self):
        import ctypes

        fake = Mock()
        fake.OpenProcess.return_value = 0
        with patch.object(validation.os, "name", "nt"), patch.object(
            validation, "_win_kernel32_lib", return_value=fake
        ), patch.object(ctypes, "get_last_error", return_value=87, create=True):
            self.assertFalse(validation.is_pid_alive(1234))
        fake.CloseHandle.assert_not_called()


class TestGetTimeout(unittest.TestCase):
    """Test per-endpoint timeout calculation."""

    def test_default_timeout(self):
        self.assertEqual(connection.get_timeout("/some_unknown_endpoint"), 30)

    def test_decompile_timeout(self):
        self.assertEqual(connection.get_timeout("/decompile_function"), 45)

    def test_script_timeout(self):
        self.assertEqual(connection.get_timeout("/run_ghidra_script"), 1800)

    def test_batch_rename_scaling(self):
        payload = {"variable_renames": {f"var_{i}": f"new_{i}" for i in range(10)}}
        timeout = connection.get_timeout("/rename_variables", payload)
        self.assertGreater(timeout, 120)

    def test_batch_comments_scaling(self):
        payload = {
            "decompiler_comments": [{"addr": "0x1000", "comment": "test"}] * 5,
            "disassembly_comments": [],
        }
        timeout = connection.get_timeout("/batch_set_comments", payload)
        self.assertGreater(timeout, 120)


class TestBuildToolFunction(unittest.TestCase):
    """Test dynamic tool function builder."""

    def test_builds_callable(self):
        schema = {
            "properties": {
                "address": {"type": "string"},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["address"],
        }
        fn = build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_signature_has_correct_params(self):
        schema = {
            "properties": {
                "address": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["address"],
        }
        fn = build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIn("address", sig.parameters)
        self.assertIn("limit", sig.parameters)
        self.assertEqual(sig.parameters["limit"].default, 100)

    def test_required_params_no_default(self):
        schema = {
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        fn = build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(sig.parameters["name"].default, inspect.Parameter.empty)

    def test_optional_params_default_none(self):
        schema = {
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        fn = build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["name"].default)

    def test_type_annotations(self):
        schema = {
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"},
                "ratio": {"type": "number"},
            },
            "required": ["name", "count", "enabled", "ratio"],
        }
        fn = build_tool_function("/test", "GET", schema)
        annotations = fn.__annotations__
        self.assertEqual(annotations["name"], str)
        self.assertEqual(annotations["count"], int)
        self.assertEqual(annotations["enabled"], bool)
        self.assertEqual(annotations["ratio"], float)

    def test_empty_schema(self):
        schema = {"type": "object", "properties": {}}
        fn = build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 0)

    def test_post_query_params_are_not_sent_in_body(self):
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
        fn = build_tool_function("/set_function_prototype", "POST", schema)

        with patch("ghidra_mcp_bridge.connection.dispatch_post") as mock_dispatch_post:
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
        self.assertEqual(sanitize_tool_name("/Debugger.Status "), "debugger_status")
        self.assertEqual(sanitize_tool_name("server/status"), "server_status")
        self.assertEqual(sanitize_tool_name("A::B...C"), "a_b_c")

    def test_sanitize_tool_name_truncates_to_claude_limit(self):
        raw = "/" + ("VeryLongToolNameSegment_" * 6)
        sanitized = sanitize_tool_name(raw)

        self.assertLessEqual(len(sanitized), MAX_TOOL_NAME_LENGTH)
        self.assertRegex(sanitized, r"^[a-zA-Z0-9_-]{1,64}$")

    def test_sanitize_tool_name_rejects_empty_names(self):
        with self.assertRaises(ValueError):
            sanitize_tool_name("///")

    def test_parse_schema_normalizes_nested_endpoint_paths(self):
        schema = parse_schema(
            {"tools": [{"path": "/server/status", "method": "GET", "params": []}]}
        )
        self.assertEqual(schema[0]["name"], "server_status")
        self.assertEqual(schema[0]["endpoint"], "/server/status")

    def test_parse_schema_suffixes_static_name_collisions(self):
        schema = parse_schema(
            {"tools": [{"path": "/debugger/status", "method": "GET", "params": []}]}
        )
        self.assertEqual(schema[0]["name"], "debugger_status_2")
        self.assertEqual(schema[0]["sanitized_name"], "debugger_status")
        self.assertTrue(schema[0]["name_collided"])

    def test_parse_schema_suffixes_dynamic_name_collisions(self):
        schema = parse_schema(
            {
                "tools": [
                    {"path": "/foo.bar", "method": "GET", "params": []},
                    {"path": "/foo/bar", "method": "GET", "params": []},
                ]
            }
        )
        self.assertEqual([tool["name"] for tool in schema], ["foo_bar", "foo_bar_2"])

    def test_parse_schema_suffixes_truncated_name_collisions_within_limit(self):
        raw = "/" + ("LongEndpointSegment_" * 5)
        schema = parse_schema(
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

    def test_registered_dynamic_tool_names_are_valid(self):
        schema = parse_schema(
            {
                "tools": [
                    {"path": "/server/status", "method": "GET", "params": []},
                    {"path": "/debugger/status", "method": "GET", "params": []},
                    {"path": "/foo.bar", "method": "GET", "params": []},
                    {"path": "/foo/bar", "method": "GET", "params": []},
                ]
            }
        )

        registry.register_tools_from_schema(schema)
        pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        try:
            names = registry.dynamic_tool_names()
            invalid = [name for name in names if not pattern.fullmatch(name)]
            self.assertEqual(invalid, [])
            self.assertIn("server_status", names)
            self.assertIn("debugger_status_2", names)
            self.assertIn("foo_bar", names)
            self.assertIn("foo_bar_2", names)
        finally:
            registry.register_tools_from_schema([])


class TestRegisterToolsFromSchema(unittest.TestCase):
    """Test dynamic tool registration from schema."""

    def test_registers_tools(self):
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
        count = registry.register_tools_from_schema(schema)
        self.assertEqual(count, 2)
        self.assertIn("test_tool_reg_1", registry.dynamic_tool_names())
        self.assertIn("test_tool_reg_2", registry.dynamic_tool_names())

    def test_register_skips_bad_tool_and_continues(self):
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
                count = registry.register_tools_from_schema(schema)

            self.assertEqual(count, 2)
            names = registry.dynamic_tool_names()
            self.assertIn("issue_212_valid_before", names)
            self.assertIn("issue_212_valid_after", names)
            self.assertNotIn("issue_212_bad_signature", names)
            message = mock_stderr.write.call_args.args[0]
            self.assertIn("1 tool(s) failed to register", message)
            self.assertIn("issue_212_bad_signature", message)
            self.assertIn("bad-param", message)
        finally:
            registry.register_tools_from_schema([])

    def test_clears_previous_tools(self):
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
        registry.register_tools_from_schema(schema1)
        self.assertIn("old_tool_clear", registry.dynamic_tool_names())
        registry.register_tools_from_schema(schema2)
        self.assertNotIn("old_tool_clear", registry.dynamic_tool_names())
        self.assertIn("new_tool_clear", registry.dynamic_tool_names())


class TestDispatchErrors(unittest.TestCase):
    """Test dispatch functions when no instance connected."""

    def setUp(self):
        connection.reset()

    def test_dispatch_get_no_connection(self):
        result = connection.dispatch_get("/test")
        data = json.loads(result)
        self.assertIn("error", data)
        self.assertIn("connect_instance", data["error"])

    def test_dispatch_post_no_connection(self):
        result = connection.dispatch_post("/test", {"key": "value"})
        data = json.loads(result)
        self.assertIn("error", data)


class TestUnixHTTPConnection(unittest.TestCase):
    """Test UnixHTTPConnection class."""

    def test_sets_socket_path(self):
        conn = UnixHTTPConnection("/tmp/test.sock", timeout=10)
        self.assertEqual(conn.socket_path, "/tmp/test.sock")
        self.assertEqual(conn.timeout, 10)


if __name__ == "__main__":
    unittest.main()
