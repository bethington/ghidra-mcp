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
import asyncio
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


class TestConnectInstanceTcpFallback(unittest.TestCase):
    """Test connect_instance project matching across UDS and TCP discovery."""

    def tearDown(self):
        # connect_instance mutates global connection state; reset it so
        # later tests (e.g. TestDispatchErrors) see a disconnected bridge.
        import bridge_mcp_ghidra as bridge

        bridge.state._active_socket = None
        bridge.state._active_tcp = None
        bridge.state._transport_mode = "none"
        bridge.state._connected_project = None

    def test_projectless_uds_instances_fall_back_to_tcp_scan(self):
        import bridge_mcp_ghidra as bridge

        instances = [{"socket": "/tmp/ghidra-123.sock", "pid": 123}]

        with patch.object(bridge.discovery, "discover_instances", return_value=instances), \
             patch.object(bridge.discovery, "_scan_tcp_for_project", return_value="http://127.0.0.1:8090") as scan, \
             patch.object(bridge.static_tools, "validate_server_url", return_value=True), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=0), \
             patch.object(bridge.static_tools, "os") as mock_os:
            mock_os.getenv.return_value = None
            bridge.state._full_schema = []
            bridge.state._loaded_groups.clear()

            result = asyncio.run(bridge.connect_instance("wanted"))

        data = json.loads(result)
        self.assertTrue(data["connected"])
        self.assertEqual(data["transport"], "tcp")
        self.assertEqual(data["url"], "http://127.0.0.1:8090")
        scan.assert_called_once_with("wanted")

    def test_real_nonmatching_uds_projects_refuse_tcp_fallback(self):
        import bridge_mcp_ghidra as bridge

        instances = [
            {"socket": "/tmp/ghidra-123.sock", "pid": 123, "project": "other"},
            {"socket": "/tmp/ghidra-456.sock", "pid": 456, "project": "also_other"},
        ]

        with patch.object(bridge.discovery, "discover_instances", return_value=instances), \
             patch.object(bridge.discovery, "_scan_tcp_for_project") as scan, \
             patch.object(bridge.static_tools, "os") as mock_os:
            mock_os.getenv.return_value = None

            result = asyncio.run(bridge.connect_instance("wanted"))

        data = json.loads(result)
        self.assertIn("error", data)
        self.assertIn("No instance matching 'wanted'", data["error"])
        self.assertEqual(data["available"], ["other", "also_other"])
        scan.assert_not_called()

    def test_uds_match_connects_via_uds_when_supported(self):
        import bridge_mcp_ghidra as bridge

        instances = [{"socket": "/tmp/ghidra-123.sock", "pid": 123, "project": "wanted"}]

        with patch.object(bridge.discovery, "discover_instances", return_value=instances), \
             patch.object(bridge.transport, "uds_supported", return_value=True), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=0):
            bridge.state._full_schema = []
            bridge.state._loaded_groups.clear()

            result = asyncio.run(bridge.connect_instance("wanted"))

        data = json.loads(result)
        self.assertTrue(data["connected"])
        self.assertEqual(data["transport"], "uds")
        self.assertEqual(data["socket"], "/tmp/ghidra-123.sock")

    def test_windows_uds_match_routes_via_enriched_tcp_url(self):
        """Windows CPython can't dial the socket it matched — the connection
        must go to the TCP url discovery recorded for that exact instance,
        with no port scan (the scan could pick a different instance)."""
        import bridge_mcp_ghidra as bridge

        instances = [{
            "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
            "pid": 9020,
            "project": "diablo2",
            "url": "http://127.0.0.1:8089",
        }]

        with patch.object(bridge.discovery, "discover_instances", return_value=instances), \
             patch.object(bridge.transport, "uds_supported", return_value=False), \
             patch.object(bridge.discovery, "_scan_tcp_for_project") as scan, \
             patch.object(bridge.static_tools, "validate_server_url", return_value=True), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=0), \
             patch.object(bridge.static_tools, "os") as mock_os:
            mock_os.getenv.return_value = None
            bridge.state._full_schema = []
            bridge.state._loaded_groups.clear()

            result = asyncio.run(bridge.connect_instance("diablo2"))

        data = json.loads(result)
        self.assertTrue(data["connected"])
        self.assertEqual(data["transport"], "tcp")
        self.assertEqual(data["url"], "http://127.0.0.1:8089")
        self.assertEqual(bridge.state._connected_project, "diablo2")
        scan.assert_not_called()

    def test_windows_uds_match_without_url_falls_back_to_scan(self):
        """Matched instance but TCP enrichment found no port for it (e.g.
        bound outside the scan range) — fall back to the project-name scan
        rather than refusing outright."""
        import bridge_mcp_ghidra as bridge

        instances = [{
            "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
            "pid": 9020,
            "project": "diablo2",
        }]

        with patch.object(bridge.discovery, "discover_instances", return_value=instances), \
             patch.object(bridge.transport, "uds_supported", return_value=False), \
             patch.object(bridge.discovery, "_scan_tcp_for_project",
                          return_value="http://127.0.0.1:8093") as scan, \
             patch.object(bridge.static_tools, "validate_server_url", return_value=True), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=0), \
             patch.object(bridge.static_tools, "os") as mock_os:
            mock_os.getenv.return_value = None
            bridge.state._full_schema = []
            bridge.state._loaded_groups.clear()

            result = asyncio.run(bridge.connect_instance("diablo2"))

        data = json.loads(result)
        self.assertTrue(data["connected"])
        self.assertEqual(data["transport"], "tcp")
        self.assertEqual(data["url"], "http://127.0.0.1:8093")
        scan.assert_called_once_with("diablo2")


class TestAutoConnectWindowsTcp(unittest.TestCase):
    """_auto_connect with a single discovered instance on a host without
    AF_UNIX must connect over the instance's enriched TCP url instead of
    attempting (and failing) a UDS schema fetch."""

    def tearDown(self):
        import bridge_mcp_ghidra as bridge

        bridge.state._active_socket = None
        bridge.state._active_tcp = None
        bridge.state._transport_mode = "none"
        bridge.state._connected_project = None

    def test_single_instance_auto_connects_via_enriched_url(self):
        import bridge_mcp_ghidra as bridge

        one = [{
            "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
            "pid": 9020,
            "project": "diablo2",
            "url": "http://127.0.0.1:8089",
        }]
        with patch.object(bridge.discovery, "discover_instances", return_value=one), \
             patch.object(bridge.transport, "uds_supported", return_value=False), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=7):
            bridge.state._active_socket = None
            bridge.state._active_tcp = None
            bridge.state._transport_mode = "none"

            bridge._auto_connect()

        self.assertEqual(bridge.state._transport_mode, "tcp")
        self.assertEqual(bridge.state._active_tcp, "http://127.0.0.1:8089")
        self.assertEqual(bridge.state._connected_project, "diablo2")
        self.assertIsNone(bridge.state._active_socket)


class TestTryReconnectTransportRouting(unittest.TestCase):
    """dispatch._try_reconnect (the post-Ghidra-restart recovery path) must
    route by transport capability: UDS when this Python can dial it, the
    instance's enriched TCP url when it can't (Windows CPython), and give up
    cleanly when neither is possible."""

    def setUp(self):
        import bridge_mcp_ghidra as bridge

        bridge.state._active_socket = None
        bridge.state._active_tcp = None
        bridge.state._transport_mode = "none"
        bridge.state._connected_project = "diablo2"

    def tearDown(self):
        import bridge_mcp_ghidra as bridge

        bridge.state._active_socket = None
        bridge.state._active_tcp = None
        bridge.state._transport_mode = "none"
        bridge.state._connected_project = None

    def _instance(self, **extra):
        return {
            "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
            "pid": 9020,
            "project": "diablo2",
            **extra,
        }

    def test_reconnects_via_uds_when_supported(self):
        import bridge_mcp_ghidra as bridge

        inst = self._instance(url="http://127.0.0.1:8089")
        with patch.object(bridge.discovery, "discover_instances", return_value=[inst]), \
             patch.object(bridge.transport, "uds_supported", return_value=True), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=0):
            self.assertTrue(bridge.dispatch._try_reconnect())

        self.assertEqual(bridge.state._transport_mode, "uds")
        self.assertEqual(bridge.state._active_socket, inst["socket"])
        self.assertIsNone(bridge.state._active_tcp)

    def test_reconnects_via_tcp_url_when_uds_unsupported(self):
        import bridge_mcp_ghidra as bridge

        inst = self._instance(url="http://127.0.0.1:8089")
        with patch.object(bridge.discovery, "discover_instances", return_value=[inst]), \
             patch.object(bridge.transport, "uds_supported", return_value=False), \
             patch.object(bridge.registry, "_fetch_and_register_schema", return_value=0):
            self.assertTrue(bridge.dispatch._try_reconnect())

        self.assertEqual(bridge.state._transport_mode, "tcp")
        self.assertEqual(bridge.state._active_tcp, "http://127.0.0.1:8089")
        self.assertIsNone(bridge.state._active_socket)

    def test_gives_up_when_uds_unsupported_and_no_url(self):
        import bridge_mcp_ghidra as bridge

        inst = self._instance()  # no url — TCP enrichment found nothing
        with patch.object(bridge.discovery, "discover_instances", return_value=[inst]), \
             patch.object(bridge.transport, "uds_supported", return_value=False), \
             patch.object(bridge.registry, "_fetch_and_register_schema") as fetch:
            self.assertFalse(bridge.dispatch._try_reconnect())

        fetch.assert_not_called()
        self.assertEqual(bridge.state._transport_mode, "none")


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

    def test_windows_drive_sweep_finds_cross_drive_socket(self):
        """Backward-compat: plugin JARs without the java.io.tmpdir fallback
        resolved the literal "/tmp" against the JVM's working drive (e.g.
        F:\\tmp when Ghidra runs from F:). The mounted-drive sweep must
        return a socket dir at <other-drive>:\\tmp\\ghidra-mcp-<user> and
        exclude drive roots where the dir doesn't exist (exists-gated, so
        the candidate list isn't flooded with 26 junk paths)."""
        from bridge_mcp_ghidra import transport

        cross_drive_dir = Path("F:\\") / "tmp" / "ghidra-mcp-testuser"
        same_drive_dir = Path("C:\\") / "tmp" / "ghidra-mcp-testuser"
        orig_exists = Path.exists

        def fake_exists(self):
            if self == cross_drive_dir:
                return True
            if self == same_drive_dir:
                return False
            return orig_exists(self)

        with patch.object(os, "listdrives", create=True,
                          return_value=["C:\\", "F:\\"]), \
             patch.object(Path, "exists", fake_exists):
            hits = transport._windows_drive_tmp_candidates("testuser")

        self.assertIn(
            cross_drive_dir, hits,
            f"cross-drive socket dir missing: {hits}",
        )
        self.assertNotIn(
            same_drive_dir, hits,
            f"nonexistent drive-sweep dir must be excluded: {hits}",
        )

    @unittest.skipUnless(os.name == "nt", "drive sweep only wired on Windows")
    def test_windows_candidates_include_drive_sweep_hits(self):
        """On Windows, get_socket_dir_candidates() must include whatever
        the drive sweep found."""
        from bridge_mcp_ghidra import transport

        sweep_hit = Path("Q:\\") / "tmp" / "ghidra-mcp-testuser"
        with patch.object(transport, "_windows_drive_tmp_candidates",
                          return_value=[sweep_hit]) as sweep:
            candidates = transport.get_socket_dir_candidates()
        sweep.assert_called_once()
        self.assertIn(sweep_hit, candidates)

    @unittest.skipUnless(os.name != "nt", "POSIX-only negative check")
    def test_posix_does_not_probe_drive_letters(self):
        """The drive sweep is Windows-only: on POSIX the helper must never
        be consulted."""
        from bridge_mcp_ghidra import transport

        with patch.object(transport, "_windows_drive_tmp_candidates",
                          return_value=[]) as sweep:
            transport.get_socket_dir_candidates()
        sweep.assert_not_called()

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
            # the test doesn't actually try to connect. Pin uds_supported to
            # True so the UDS query path runs even on Windows CPython (which
            # lacks AF_UNIX and would otherwise take the TCP enrichment path).
            with patch.object(
                bridge.transport, "get_socket_dir_candidates",
                return_value=[Path(d1), Path(d2)],
            ), patch.object(
                bridge.transport, "uds_supported", return_value=True,
            ), patch.object(
                bridge.transport, "uds_request",
                return_value=("{}", 500),  # info query fails — that's fine
            ), patch.object(
                bridge.validation, "is_pid_alive",
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
                bridge.transport, "get_socket_dir_candidates",
                return_value=[Path(d), Path(d)],  # same dir twice
            ), patch.object(
                bridge.transport, "uds_supported", return_value=True,
            ), patch.object(
                bridge.transport, "uds_request",
                return_value=("{}", 500),
            ), patch.object(
                bridge.validation, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = discover_instances()

            self.assertEqual(len(instances), 1)


class TestDiscoverInstancesWindowsTcpEnrichment(unittest.TestCase):
    """On hosts where Python can't dial UDS (Windows CPython lacks AF_UNIX,
    python/cpython#77589), discover_instances must enrich socket-file hits
    with metadata fetched over the plugin's TCP listener, joined by PID —
    otherwise list_instances shows projectless entries and connect_instance
    can't match by project name."""

    def test_enriches_by_pid_when_uds_unsupported(self):
        import tempfile
        import bridge_mcp_ghidra as bridge

        with tempfile.TemporaryDirectory() as d:
            pid_alive = os.getpid()
            (Path(d) / f"ghidra-{pid_alive}.sock").touch()

            tcp_info = {
                pid_alive: {
                    "url": "http://127.0.0.1:8089",
                    "pid": pid_alive,
                    "project": "diablo2",
                }
            }
            with patch.object(
                bridge.transport, "get_socket_dir_candidates",
                return_value=[Path(d)],
            ), patch.object(
                bridge.transport, "uds_supported", return_value=False,
            ), patch.object(
                bridge.transport, "uds_request",
            ) as uds_req, patch.object(
                bridge.discovery, "_tcp_instances_by_pid", return_value=tcp_info,
            ), patch.object(
                bridge.validation, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = bridge.discover_instances()

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["project"], "diablo2")
        self.assertEqual(instances[0]["url"], "http://127.0.0.1:8089")
        self.assertEqual(instances[0]["pid"], pid_alive)
        uds_req.assert_not_called()

    def test_no_tcp_scan_when_uds_supported(self):
        """When AF_UNIX works, discovery must query over UDS and never pay
        for a TCP port scan."""
        import tempfile
        import bridge_mcp_ghidra as bridge

        with tempfile.TemporaryDirectory() as d:
            pid_alive = os.getpid()
            (Path(d) / f"ghidra-{pid_alive}.sock").touch()

            with patch.object(
                bridge.transport, "get_socket_dir_candidates",
                return_value=[Path(d)],
            ), patch.object(
                bridge.transport, "uds_supported", return_value=True,
            ), patch.object(
                bridge.transport, "uds_request",
                return_value=(json.dumps({"project": "diablo2"}), 200),
            ), patch.object(
                bridge.discovery, "_tcp_instances_by_pid",
            ) as tcp_scan, patch.object(
                bridge.validation, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = bridge.discover_instances()

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["project"], "diablo2")
        tcp_scan.assert_not_called()

    def test_unenriched_when_pid_not_in_tcp_scan(self):
        """A socket whose PID has no TCP responder stays a bare
        {socket, pid} record — discovery must not crash or misattribute."""
        import tempfile
        import bridge_mcp_ghidra as bridge

        with tempfile.TemporaryDirectory() as d:
            pid_alive = os.getpid()
            (Path(d) / f"ghidra-{pid_alive}.sock").touch()

            with patch.object(
                bridge.transport, "get_socket_dir_candidates",
                return_value=[Path(d)],
            ), patch.object(
                bridge.transport, "uds_supported", return_value=False,
            ), patch.object(
                bridge.discovery, "_tcp_instances_by_pid", return_value={},
            ), patch.object(
                bridge.validation, "is_pid_alive",
                side_effect=lambda p: p == pid_alive,
            ):
                instances = bridge.discover_instances()

        self.assertEqual(len(instances), 1)
        self.assertNotIn("project", instances[0])
        self.assertNotIn("url", instances[0])


class TestAutoConnectMultiInstance(unittest.TestCase):
    """When discover_instances() finds >1 UDS instance, _auto_connect must
    log the choose-one message and STOP — not fall through to the TCP
    fallback and silently connect to whatever's on port 8089."""

    def test_multi_uds_does_not_fall_through_to_tcp(self):
        import bridge_mcp_ghidra as bridge

        two = [
            {"project": "ProjA", "socket": "/tmp/a.sock", "pid": 111},
            {"project": "ProjB", "socket": "/tmp/b.sock", "pid": 222},
        ]
        fetch_calls = []
        # Patch the MODULE-QUALIFIED call sites _auto_connect actually uses
        # (static_tools calls discovery.discover_instances() and
        # registry._fetch_and_register_schema(); it reads/writes state._*).
        # Patching the flat bridge.* re-exports would NOT intercept those, so
        # the test would pass vacuously regardless of the code under test.
        with patch.object(bridge.discovery, "discover_instances", return_value=two), \
             patch.object(bridge.registry, "_fetch_and_register_schema",
                          side_effect=lambda *a, **kw: fetch_calls.append(1) or 0):
            # Reset connection state so the test is hermetic.
            bridge.state._active_socket = None
            bridge.state._active_tcp = None
            bridge.state._transport_mode = "none"
            bridge._auto_connect()

        self.assertEqual(
            fetch_calls, [],
            "schema fetch was called — _auto_connect fell through to TCP "
            "after the multi-UDS warning"
        )
        self.assertEqual(bridge.state._transport_mode, "none")
        self.assertIsNone(bridge.state._active_tcp)


class TestDebuggerAttachAddressSync(unittest.TestCase):
    """debugger_attach must read image_base directly from
    /list_open_programs entries (not the plain-text /get_metadata
    endpoint, where json.loads() always failed and the auto-sync
    silently never fired)."""

    def test_uses_image_base_from_list_open_programs(self):
        import bridge_mcp_ghidra as bridge

        programs_payload = json.dumps([
            {"path": "/proj/Foo.exe", "name": "Foo.exe", "image_base": "0x400000"},
            {"path": "/proj/Bar.dll", "name": "Bar.dll", "image_base": "0x10000000"},
        ])
        debugger_calls = []

        def fake_debugger_request(method, path, body=None, **kw):
            debugger_calls.append((method, path, body))
            return '{"status":"ok"}'

        def fake_dispatch_get(path, params=None):
            if path == "/list_open_programs":
                return programs_payload
            raise AssertionError(
                f"unexpected GET {path} — auto-sync must not call "
                "/get_metadata or any other endpoint"
            )

        with patch.object(bridge.debugger, "_debugger_request",
                          side_effect=fake_debugger_request), \
             patch.object(bridge.dispatch, "dispatch_get", side_effect=fake_dispatch_get), \
             patch.object(bridge.state, "_transport_mode", "tcp"):
            bridge.debugger_attach("12345")

        sync = [c for c in debugger_calls if c[1] == "/debugger/sync_modules"]
        self.assertEqual(len(sync), 1, "auto-sync did not fire")
        bases = sync[0][2].get("ghidra_bases", {})
        self.assertEqual(bases.get("/proj/Foo.exe"), "0x400000")
        self.assertEqual(bases.get("/proj/Bar.dll"), "0x10000000")


class TestIsPidAlive(unittest.TestCase):
    """Test PID liveness check."""

    def test_current_pid_alive(self):
        from bridge_mcp_ghidra import is_pid_alive

        self.assertTrue(is_pid_alive(os.getpid()))

    def test_nonexistent_pid(self):
        from bridge_mcp_ghidra import is_pid_alive

        self.assertFalse(is_pid_alive(4000000))


class TestValidateServerUrl(unittest.TestCase):
    """Test TCP server URL validation.

    The contract must match how transport.tcp_request dials the URL: plain
    http.client.HTTPConnection(hostname, port) — no TLS, no port inference.
    """

    def _validate(self, url):
        from bridge_mcp_ghidra import validate_server_url

        return validate_server_url(url)

    def test_accepts_loopback_http_with_explicit_port(self):
        self.assertTrue(self._validate("http://127.0.0.1:8089"))
        self.assertTrue(self._validate("http://localhost:8089"))
        self.assertTrue(self._validate("http://[::1]:8089"))

    def test_rejects_https_scheme(self):
        # The transport never negotiates TLS — https would pass then fail at
        # connection time, so it must be rejected up front.
        self.assertFalse(self._validate("https://127.0.0.1:8089"))

    def test_rejects_missing_port(self):
        # HTTPConnection silently defaults a missing port to 80, never the
        # Ghidra server's actual port.
        self.assertFalse(self._validate("http://127.0.0.1"))
        self.assertFalse(self._validate("http://localhost"))

    def test_rejects_non_local_host(self):
        self.assertFalse(self._validate("http://10.0.10.30:8089"))
        self.assertFalse(self._validate("http://evil.example.com:8089"))

    def test_rejects_malformed_url(self):
        self.assertFalse(self._validate("not a url"))
        self.assertFalse(self._validate(""))


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

        with patch("bridge_mcp_ghidra.dispatch.dispatch_post") as mock_dispatch_post:
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

        # Use a management tool name (always static on every platform) so the
        # collision is independent of debugger gating.
        schema = _parse_schema(
            {
                "tools": [
                    {
                        "path": "/check/tools",
                        "method": "GET",
                        "params": [],
                    }
                ]
            }
        )
        self.assertEqual(schema[0]["name"], "check_tools_2")
        self.assertEqual(schema[0]["sanitized_name"], "check_tools")
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
                    {"path": "/check/tools", "method": "GET", "params": []},
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
            # /check/tools collides with the static management tool check_tools
            self.assertIn("check_tools_2", bridge.mcp._tool_manager._tools)
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
            self.assertIn("issue_212_valid_before", bridge.state._dynamic_tool_names)
            self.assertIn("issue_212_valid_after", bridge.state._dynamic_tool_names)
            self.assertNotIn("issue_212_bad_signature", bridge.state._dynamic_tool_names)
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

        old = bridge.state._transport_mode
        bridge.state._transport_mode = "none"
        try:
            result = bridge.dispatch_get("/test")
            data = json.loads(result)
            self.assertIn("error", data)
            self.assertIn("connect_instance", data["error"])
        finally:
            bridge.state._transport_mode = old

    def test_dispatch_post_no_connection(self):
        import bridge_mcp_ghidra as bridge

        old = bridge.state._transport_mode
        bridge.state._transport_mode = "none"
        try:
            result = bridge.dispatch_post("/test", {"key": "value"})
            data = json.loads(result)
            self.assertIn("error", data)
        finally:
            bridge.state._transport_mode = old


class TestUnixHTTPConnection(unittest.TestCase):
    """Test UnixHTTPConnection class."""

    def test_sets_socket_path(self):
        from bridge_mcp_ghidra import UnixHTTPConnection

        conn = UnixHTTPConnection("/tmp/test.sock", timeout=10)
        self.assertEqual(conn.socket_path, "/tmp/test.sock")
        self.assertEqual(conn.timeout, 10)


class TestDebuggerEnabled(unittest.TestCase):
    """_debugger_enabled gates the WinDbg debugger proxy tools.

    The standalone debugger server (debugger/server.py) wraps dbgeng and only
    runs on Windows, so a *local* debugger URL can never serve on a non-Windows
    host. Registration is gated accordingly to keep the tool list uncluttered.
    """

    def test_disabled_on_non_windows_with_local_url(self):
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertFalse(
            _debugger_enabled(url="http://127.0.0.1:8099", platform="linux", override=None)
        )

    def test_disabled_on_non_windows_with_localhost_name(self):
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertFalse(
            _debugger_enabled(url="http://localhost:8099", platform="darwin", override=None)
        )

    def test_disabled_on_non_windows_with_ipv6_loopback(self):
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertFalse(
            _debugger_enabled(url="http://[::1]:8099", platform="linux", override=None)
        )

    def test_enabled_on_non_windows_with_remote_host(self):
        """A remote Windows host running the server is reachable from Linux."""
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertTrue(
            _debugger_enabled(url="http://winbox.lan:8099", platform="linux", override=None)
        )

    def test_enabled_on_windows_with_local_url(self):
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertTrue(
            _debugger_enabled(url="http://127.0.0.1:8099", platform="win32", override=None)
        )

    def test_override_forces_off_even_on_windows(self):
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertFalse(
            _debugger_enabled(url="http://127.0.0.1:8099", platform="win32", override="0")
        )

    def test_override_forces_on_even_on_linux_local(self):
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertTrue(
            _debugger_enabled(url="http://127.0.0.1:8099", platform="linux", override="1")
        )

    def test_blank_override_is_ignored(self):
        """An empty string (e.g. unset-but-present env) falls back to auto-detect."""
        from bridge_mcp_ghidra import _debugger_enabled

        self.assertFalse(
            _debugger_enabled(url="http://127.0.0.1:8099", platform="linux", override="")
        )


class TestDebuggerToolRegistration(unittest.TestCase):
    """Debugger proxy tools register conditionally; their functions always exist."""

    def test_debugger_function_always_defined(self):
        """The proxy functions stay importable/callable even when not registered."""
        import bridge_mcp_ghidra as bridge

        self.assertTrue(callable(bridge.debugger_attach))

    def test_all_static_names_superset_of_active(self):
        import bridge_mcp_ghidra as bridge

        self.assertTrue(
            bridge.DEBUGGER_TOOL_NAMES.issubset(bridge._ALL_STATIC_TOOL_NAMES)
        )
        self.assertTrue(
            bridge.STATIC_TOOL_NAMES.issubset(bridge._ALL_STATIC_TOOL_NAMES)
        )

    @unittest.skipIf(sys.platform.startswith("win"), "proxies active on Windows")
    def test_inactive_proxy_frees_clean_name_for_trace_rmi_tool(self):
        """With the WinDbg proxies inactive (non-Windows local), Ghidra's own
        TraceRmi /debugger/status (System B) gets the clean name, not _2."""
        import bridge_mcp_ghidra as bridge

        schema = bridge._parse_schema(
            {"tools": [{"path": "/debugger/status", "method": "GET", "params": []}]}
        )
        self.assertEqual(schema[0]["name"], "debugger_status")
        self.assertFalse(schema[0]["name_collided"])

    @unittest.skipIf(sys.platform.startswith("win"), "debugger tools active on Windows")
    def test_debugger_tools_not_registered_on_non_windows(self):
        import bridge_mcp_ghidra as bridge

        self.assertNotIn("debugger_attach", bridge.mcp._tool_manager._tools)
        self.assertNotIn("debugger_attach", bridge.STATIC_TOOL_NAMES)

    @unittest.skipIf(sys.platform.startswith("win"), "debugger tools active on Windows")
    def test_management_tools_still_registered_on_non_windows(self):
        import bridge_mcp_ghidra as bridge

        self.assertIn("list_instances", bridge.mcp._tool_manager._tools)
        self.assertIn("list_instances", bridge.STATIC_TOOL_NAMES)


if __name__ == "__main__":
    unittest.main()
