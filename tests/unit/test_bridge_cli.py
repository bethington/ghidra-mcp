"""Tests for the bridge CLI entry point (python/bridge_mcp_ghidra/cli.py).

cli.py was at 14% coverage: argument parsing, lazy-mode/default-group wiring,
and the DNS-rebinding-protection matrix were exercised only manually. These
tests drive main() with mcp.run and _auto_connect patched out, then assert
the settings that would have governed the real server.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from bridge_mcp_ghidra import cli, state  # noqa: E402
from bridge_mcp_ghidra.server import mcp  # noqa: E402


class _CliHarness(unittest.TestCase):
    """Run cli.main() with side effects stubbed; restore shared state after."""

    def setUp(self):
        self._saved_lazy = state._lazy_mode
        self._saved_groups = set(state._default_groups)
        self._saved_security = getattr(mcp.settings, "transport_security", None)
        self._saved_host = mcp.settings.host
        self._saved_port = mcp.settings.port

    def tearDown(self):
        state._lazy_mode = self._saved_lazy
        state._default_groups = self._saved_groups
        mcp.settings.transport_security = self._saved_security
        mcp.settings.host = self._saved_host
        mcp.settings.port = self._saved_port

    def run_main(self, *argv, env=None):
        """Invoke cli.main() with the given argv; returns the mocks.

        Returns a dict with the ``mcp.run`` mock (stdio path), the
        ``uvicorn.run`` mock and the ``_build_http_app`` mock (HTTP path).
        """
        patches = [
            patch.object(sys, "argv", ["bridge-mcp-ghidra", *argv]),
            patch.object(cli, "_auto_connect"),
            patch.object(mcp, "run"),
            patch.object(cli.uvicorn, "run"),
            patch.object(cli, "_build_http_app"),
        ]
        if env:
            import os

            patches.append(patch.dict(os.environ, env))
        started = []
        for p in patches:
            started.append(p.start())
        try:
            cli.main()
            return {
                "mcp_run": started[2],
                "uvicorn_run": started[3],
                "build_app": started[4],
            }
        finally:
            for p in patches:
                p.stop()


class TestCliArguments(_CliHarness):
    def test_defaults_stdio_and_eager_loading(self):
        mocks = self.run_main()
        mocks["mcp_run"].assert_called_once_with(transport="stdio")
        mocks["uvicorn_run"].assert_not_called()
        self.assertFalse(state._lazy_mode)

    def test_lazy_flag_sets_lazy_mode(self):
        self.run_main("--lazy")
        self.assertTrue(state._lazy_mode)

    def test_no_lazy_overrides_lazy(self):
        self.run_main("--lazy", "--no-lazy")
        self.assertFalse(state._lazy_mode)

    def test_default_groups_parsed_and_stripped(self):
        self.run_main("--default-groups", " function , datatype ,")
        self.assertEqual(state._default_groups, {"function", "datatype"})

    def test_transport_and_port_applied(self):
        mocks = self.run_main("--transport", "streamable-http", "--mcp-port", "9905")
        # HTTP transports run uvicorn directly (with the CORS-wrapped app)
        # instead of delegating to mcp.run.
        mocks["mcp_run"].assert_not_called()
        mocks["build_app"].assert_called_once_with("streamable-http", "127.0.0.1")
        _, kwargs = mocks["uvicorn_run"].call_args
        self.assertEqual(kwargs["host"], "127.0.0.1")
        self.assertEqual(kwargs["port"], 9905)
        self.assertEqual(mcp.settings.port, 9905)

    def test_sse_transport_also_gets_cors_app(self):
        mocks = self.run_main("--transport", "sse", "--mcp-port", "9906")
        mocks["mcp_run"].assert_not_called()
        mocks["build_app"].assert_called_once_with("sse", "127.0.0.1")
        mocks["uvicorn_run"].assert_called_once()

    def test_invalid_transport_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main("--transport", "carrier-pigeon")


class TestCliRebindProtection(_CliHarness):
    def test_loopback_host_leaves_security_untouched(self):
        sentinel = object()
        mcp.settings.transport_security = sentinel
        self.run_main("--mcp-host", "127.0.0.1")
        self.assertIs(mcp.settings.transport_security, sentinel)

    def test_specific_remote_host_enables_protection(self):
        self.run_main("--mcp-host", "192.168.1.50")
        sec = mcp.settings.transport_security
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn("192.168.1.50:*", sec.allowed_hosts)
        self.assertIn("localhost:*", sec.allowed_hosts)

    def test_wildcard_bind_keeps_protection_on(self):
        """0.0.0.0 is the most exposed configuration — protection must stay
        ON with the machine's real hostnames allowed (the old behavior of
        disabling protection entirely was the vulnerability)."""
        self.run_main("--mcp-host", "0.0.0.0")
        sec = mcp.settings.transport_security
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn("localhost:*", sec.allowed_hosts)
        self.assertIn("127.0.0.1:*", sec.allowed_hosts)

    def test_wildcard_bind_extra_hosts_from_env(self):
        self.run_main(
            "--mcp-host", "0.0.0.0",
            env={"GHIDRA_MCP_ALLOWED_HOSTS": "re-lab.internal, bench01"},
        )
        sec = mcp.settings.transport_security
        self.assertIn("re-lab.internal:*", sec.allowed_hosts)
        self.assertIn("bench01:*", sec.allowed_hosts)

    def test_wildcard_bind_explicit_optout_disables_protection(self):
        self.run_main(
            "--mcp-host", "0.0.0.0",
            env={"GHIDRA_MCP_DISABLE_REBIND_PROTECTION": "1"},
        )
        sec = mcp.settings.transport_security
        self.assertFalse(sec.enable_dns_rebinding_protection)


class TestCorsOriginRegex(unittest.TestCase):
    """Origin policy for browser clients (MCP Inspector et al.)."""

    def _match(self, bind_host, origin):
        import re

        return re.match(cli._cors_origin_regex(bind_host), origin) is not None

    def test_loopback_origins_always_allowed_any_port(self):
        for origin in (
            "http://localhost:6274",  # MCP Inspector default UI port
            "http://127.0.0.1:8080",
            "http://localhost",
            "https://localhost:6274",
            "http://[::1]:6274",
        ):
            self.assertTrue(self._match("127.0.0.1", origin), origin)

    def test_foreign_origins_rejected(self):
        for origin in (
            "http://evil.com",
            "http://localhost.evil.com:6274",  # prefix-spoof of localhost
            "http://xlocalhost:6274",
            "null",
        ):
            self.assertFalse(self._match("127.0.0.1", origin), origin)

    def test_remote_bind_allows_the_bind_host(self):
        self.assertTrue(self._match("192.168.1.50", "http://192.168.1.50:6274"))
        self.assertFalse(self._match("192.168.1.50", "http://192.168.1.51:6274"))

    def test_wildcard_bind_allows_machine_hostnames(self):
        import socket

        hn = socket.gethostname()
        if hn:
            self.assertTrue(self._match("0.0.0.0", f"http://{hn}:6274"))

    def test_allowed_hosts_env_extends_origins(self):
        from unittest.mock import patch as _patch

        with _patch.dict(
            "os.environ", {"GHIDRA_MCP_ALLOWED_HOSTS": "re-lab.internal, bench01"}
        ):
            self.assertTrue(self._match("127.0.0.1", "http://re-lab.internal:6274"))
            self.assertTrue(self._match("127.0.0.1", "https://bench01"))

    def test_regex_metacharacters_in_hosts_are_escaped(self):
        # "." in 127.0.0.1 must not match "127a0b0c1"
        self.assertFalse(self._match("127.0.0.1", "http://127a0b0c1:6274"))


class TestHttpAppPreflight(unittest.TestCase):
    """Drive a real CORS preflight through the wrapped Starlette app.

    This is the exact request MCP Inspector's browser sends before every
    POST; before the CORS middleware was added it got a 405 from the
    transport endpoint. The preflight is answered by the middleware
    itself, so no lifespan/session-manager startup is needed.
    """

    PREFLIGHT_HEADERS = {
        "Origin": "http://localhost:6274",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,mcp-session-id,mcp-protocol-version",
    }

    @classmethod
    def setUpClass(cls):
        from starlette.testclient import TestClient

        # No context manager: lifespan must not run (the streamable-http
        # session manager needs a task group; preflights never reach it).
        cls.client = TestClient(cli._build_http_app("streamable-http", "127.0.0.1"))

    def test_preflight_succeeds_for_inspector_origin(self):
        resp = self.client.options("/mcp", headers=self.PREFLIGHT_HEADERS)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.headers["access-control-allow-origin"], "http://localhost:6274"
        )
        self.assertIn("POST", resp.headers["access-control-allow-methods"])
        allow_headers = resp.headers.get("access-control-allow-headers", "").lower()
        self.assertIn("mcp-session-id", allow_headers)

    def test_preflight_rejected_for_foreign_origin(self):
        headers = dict(self.PREFLIGHT_HEADERS, Origin="http://evil.com")
        resp = self.client.options("/mcp", headers=headers)
        self.assertNotIn("access-control-allow-origin", resp.headers)

    def test_session_id_header_exposed_to_scripts(self):
        resp = self.client.options("/mcp", headers=self.PREFLIGHT_HEADERS)
        self.assertEqual(resp.status_code, 200)
        # expose_headers shows up on actual responses, not preflights; the
        # middleware config is what we can assert here without a session
        # manager, so check the app's middleware stack directly.
        from starlette.middleware.cors import CORSMiddleware

        cors = [
            m for m in self.client.app.user_middleware if m.cls is CORSMiddleware
        ]
        self.assertEqual(len(cors), 1)
        self.assertIn("mcp-session-id", cors[0].kwargs["expose_headers"])


class TestWildcardAllowedHosts(unittest.TestCase):
    def test_includes_loopbacks_with_port_wildcards(self):
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("localhost:*", hosts)
        self.assertIn("127.0.0.1:*", hosts)

    def test_ipv6_literals_get_bracketed_forms(self):
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("::1:*", hosts)
        self.assertIn("[::1]:*", hosts)


if __name__ == "__main__":
    unittest.main()
