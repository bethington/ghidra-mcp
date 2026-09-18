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
        # os.environ is patched unconditionally (patch.dict restores the whole
        # mapping on stop) so a test that does not name GHIDRA_MCP_LAZY can
        # clear it below. That var now feeds the lazy default, so a developer
        # who happens to export it would otherwise flip the assertions of every
        # test that says nothing about it.
        import os

        effective_env = dict(env or {})
        patches.append(patch.dict(os.environ, effective_env))
        started = []
        for p in patches:
            started.append(p.start())
        if "GHIDRA_MCP_LAZY" not in effective_env:
            os.environ.pop("GHIDRA_MCP_LAZY", None)
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
    def test_defaults_stdio_and_lazy_loading(self):
        # Lazy is the DEFAULT as of #440: eager advertised all 253 endpoints in
        # one tools/list, which the Gemini API rejects with 400
        # INVALID_ARGUMENT before any tool is called.
        mocks = self.run_main()
        mocks["mcp_run"].assert_called_once_with(transport="stdio")
        mocks["uvicorn_run"].assert_not_called()
        self.assertTrue(state._lazy_mode)

    def test_lazy_flag_sets_lazy_mode(self):
        self.run_main("--lazy")
        self.assertTrue(state._lazy_mode)

    def test_no_lazy_overrides_lazy(self):
        self.run_main("--lazy", "--no-lazy")
        self.assertFalse(state._lazy_mode)

    def test_no_lazy_alone_disables_lazy(self):
        # --no-lazy must win over the new default without needing --lazy first,
        # otherwise the documented escape hatch for clients that ignore
        # tools/list_changed does not actually exist.
        self.run_main("--no-lazy")
        self.assertFalse(state._lazy_mode)

    def test_env_var_disables_lazy_without_argv(self):
        # The second half of the #440 escape hatch. A Docker ENTRYPOINT, a uvx
        # one-liner or a registry-installed server entry may give the user no
        # way to add a flag, and an escape hatch you cannot reach is not one.
        self.run_main(env={"GHIDRA_MCP_LAZY": "0"})
        self.assertFalse(state._lazy_mode)

    def test_env_var_accepts_word_forms(self):
        for value in ("false", "FALSE", "no", "off"):
            with self.subTest(value=value):
                self.run_main(env={"GHIDRA_MCP_LAZY": value})
                self.assertFalse(state._lazy_mode)
        for value in ("1", "true", "yes", "on"):
            with self.subTest(value=value):
                self.run_main(env={"GHIDRA_MCP_LAZY": value})
                self.assertTrue(state._lazy_mode)

    def test_explicit_flag_beats_env_var(self):
        # Both directions: whoever typed the flag meant it.
        self.run_main("--no-lazy", env={"GHIDRA_MCP_LAZY": "1"})
        self.assertFalse(state._lazy_mode)
        self.run_main("--lazy", env={"GHIDRA_MCP_LAZY": "0"})
        self.assertTrue(state._lazy_mode)

    def test_unparseable_env_var_keeps_the_default(self):
        # Guessing here silently picks one of the two client families this
        # setting exists to keep working, so an unknown value is ignored.
        self.run_main(env={"GHIDRA_MCP_LAZY": "maybe"})
        self.assertTrue(state._lazy_mode)

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


class TestBridgeBearerAuth(unittest.TestCase):
    """An exposed bridge must not replay its backend token for strangers."""

    def setUp(self):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        async def endpoint(_request):
            return PlainTextResponse("proxied")

        app = Starlette(routes=[Route("/mcp", endpoint, methods=["POST", "OPTIONS"])])
        self.client = TestClient(cli._BearerAuthMiddleware(app, "bridge-secret"))

    def test_missing_token_is_rejected(self):
        response = self.client.post("/mcp")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_wrong_token_is_rejected(self):
        response = self.client.post("/mcp", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(response.status_code, 401)

    def test_matching_token_reaches_bridge(self):
        response = self.client.post("/mcp", headers={"Authorization": "Bearer bridge-secret"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "proxied")

    def test_cors_preflight_does_not_require_credentials(self):
        response = self.client.options("/mcp")
        self.assertNotEqual(response.status_code, 401)

    def test_remote_http_app_is_wrapped_when_backend_token_is_set(self):
        with patch.object(cli, "AUTH_TOKEN", "bridge-secret"):
            app = cli._build_http_app("streamable-http", "0.0.0.0")
        self.assertIsInstance(app, cli._BearerAuthMiddleware)

    def test_loopback_http_app_preserves_local_unauthenticated_access(self):
        with patch.object(cli, "AUTH_TOKEN", "bridge-secret"):
            app = cli._build_http_app("streamable-http", "127.0.0.1")
        self.assertNotIsInstance(app, cli._BearerAuthMiddleware)


class TestWildcardAllowedHosts(unittest.TestCase):
    def test_includes_loopbacks_with_port_wildcards(self):
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("localhost:*", hosts)
        self.assertIn("127.0.0.1:*", hosts)

    def test_ipv6_literals_get_bracketed_forms(self):
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("::1:*", hosts)
        self.assertIn("[::1]:*", hosts)

    def test_portless_forms_present_for_default_port_proxies(self):
        """A TLS proxy on :443 forwards a PORTLESS Host header.

        `host:*` matches only when the Host header actually carries a
        port, so a `:*`-only allowlist answers 421 Misdirected Request to
        every proxied request -- which reads as a network fault, not a
        policy one.
        """
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("localhost", hosts)
        self.assertIn("127.0.0.1", hosts)


class TestRequestGatesAgree(unittest.TestCase):
    """The two Origin gates must never disagree (#399).

    Every request carries the Origin header past TWO independent checks:
    `CORSMiddleware` (browser-facing, answers the preflight) and the SDK's
    `TransportSecurityMiddleware` (DNS-rebinding, inside the transport
    app). They have different syntaxes, so hand-maintained side by side
    they drift -- and the symptom is a 200 preflight followed by a 421/403
    on the real POST, i.e. the fix LOOKS applied while still being broken.

    These tests use the SDK's own validators as the oracle, so they fail
    if either side is edited alone.
    """

    def _validator(self, bind_host):
        from mcp.server.transport_security import TransportSecurityMiddleware

        return TransportSecurityMiddleware(cli._transport_security(bind_host))

    def _cors_allows(self, bind_host, origin):
        import re

        return re.match(cli._cors_origin_regex(bind_host), origin) is not None

    def test_every_cors_approved_origin_passes_the_rebinding_gate(self):
        for bind_host in ("192.168.1.50", "ghidra.example.com", "0.0.0.0"):
            validator = self._validator(bind_host)
            hosts = cli._policy_hosts(bind_host)
            for host in cli._bracketed(hosts):
                for scheme in ("http", "https"):
                    for origin in (f"{scheme}://{host}", f"{scheme}://{host}:8443"):
                        if not self._cors_allows(bind_host, origin):
                            continue
                        self.assertTrue(
                            validator._validate_origin(origin),
                            f"bind={bind_host}: CORS approved {origin} but the "
                            "DNS-rebinding gate refuses it (403 after a 200 "
                            "preflight)",
                        )

    def test_proxy_host_headers_pass_the_rebinding_gate(self):
        """Portless (proxy on a default port) and ported forms both pass."""
        for bind_host in ("192.168.1.50", "ghidra.example.com"):
            validator = self._validator(bind_host)
            for host in (bind_host, f"{bind_host}:8443", "localhost", "localhost:6274"):
                self.assertTrue(
                    validator._validate_host(host),
                    f"bind={bind_host}: Host {host!r} refused (421)",
                )

    def test_https_origins_are_accepted_behind_tls_termination(self):
        validator = self._validator("ghidra.example.com")
        self.assertTrue(validator._validate_origin("https://ghidra.example.com"))
        self.assertTrue(validator._validate_origin("https://ghidra.example.com:8443"))

    def test_strangers_are_still_refused_by_both_gates(self):
        validator = self._validator("ghidra.example.com")
        self.assertFalse(validator._validate_origin("http://evil.attacker.test"))
        self.assertFalse(validator._validate_host("evil.attacker.test"))
        self.assertFalse(self._cors_allows("ghidra.example.com", "http://evil.attacker.test"))

    def test_allowed_hosts_env_widens_both_gates_together(self):
        """GHIDRA_MCP_ALLOWED_HOSTS is the operator's escape hatch.

        Widening one gate and not the other leaves the client just as
        rejected, only at a different layer.
        """
        with patch.dict("os.environ", {"GHIDRA_MCP_ALLOWED_HOSTS": "re-lab.internal"}):
            validator = self._validator("192.168.1.50")
            self.assertTrue(self._cors_allows("192.168.1.50", "https://re-lab.internal"))
            self.assertTrue(validator._validate_origin("https://re-lab.internal"))
            self.assertTrue(validator._validate_host("re-lab.internal"))


class TestRemoteBindPreflight(unittest.TestCase):
    """A real preflight AND a real POST through an exposed bridge (#399).

    TestHttpAppPreflight covers the loopback bind, where the SDK's
    rebinding gate is off entirely. This drives the configuration where
    both gates are live, which is where they could disagree -- and where
    a preflight-only test would report success over a broken bridge.
    """

    REMOTE = "ghidra.example.com"

    @classmethod
    def setUpClass(cls):
        from starlette.testclient import TestClient

        cls._saved = getattr(mcp.settings, "transport_security", None)
        mcp.settings.transport_security = cli._transport_security(cls.REMOTE)
        # FastMCP builds its StreamableHTTPSessionManager ONCE
        # (`if self._session_manager is None`) and freezes
        # `security_settings` at that moment. Any earlier test that built
        # a streamable-http app -- TestHttpAppPreflight does, on a
        # loopback bind where rebinding protection is off entirely --
        # leaves that permissive manager cached on the shared `mcp`
        # singleton, and every later assertion about the rebinding gate
        # passes without the gate ever running. Dropping the cache is
        # what keeps these tests from being vacuous.
        cls._saved_mgr = mcp._session_manager
        mcp._session_manager = None
        # Entered as a context manager so the lifespan runs: unlike a
        # preflight, a real POST reaches the session manager, which needs
        # its task group started.
        cls._ctx = TestClient(cli._build_http_app("streamable-http", cls.REMOTE))
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)
        mcp._session_manager = cls._saved_mgr
        mcp.settings.transport_security = cls._saved

    def test_the_rebinding_gate_is_actually_live_in_this_fixture(self):
        """Guard the guard: prove the inner gate can still say no.

        Without this, a cached permissive session manager would make
        every other POST assertion in this class pass for the wrong
        reason.
        """
        resp = self._post("evil.attacker.test", f"https://{self.REMOTE}")
        self.assertEqual(resp.status_code, 421)

    def _preflight(self, host, origin):
        return self.client.options(
            "/mcp",
            headers={
                "Host": host,
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, mcp-session-id",
            },
        )

    def _post(self, host, origin):
        return self.client.post(
            "/mcp",
            headers={
                "Host": host,
                "Origin": origin,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            },
        )

    def test_preflight_grants_the_session_id_header(self):
        resp = self._preflight(self.REMOTE, f"https://{self.REMOTE}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.headers["access-control-allow-origin"], f"https://{self.REMOTE}"
        )
        self.assertIn("POST", resp.headers["access-control-allow-methods"])
        self.assertIn(
            "mcp-session-id", resp.headers["access-control-allow-headers"].lower()
        )

    def test_portless_host_and_https_origin_are_not_refused_after_preflight(self):
        """The regression: TLS proxy on :443 got 200 preflight then 421/403.

        Asserting only on the preflight would pass while the bridge was
        still unusable, so this asserts the request the preflight
        authorized actually goes through.
        """
        self.assertEqual(self._preflight(self.REMOTE, f"https://{self.REMOTE}").status_code, 200)
        resp = self._post(self.REMOTE, f"https://{self.REMOTE}")
        self.assertNotEqual(resp.status_code, 421, "portless Host refused: 421")
        self.assertNotEqual(resp.status_code, 403, "https Origin refused: 403")
        self.assertEqual(resp.status_code, 200)

    def test_session_id_is_readable_by_the_browser_on_the_real_response(self):
        resp = self._post(self.REMOTE, f"https://{self.REMOTE}")
        self.assertIn(
            "mcp-session-id", resp.headers["access-control-expose-headers"].lower()
        )
        # Without ACAO on the ACTUAL response the browser discards it, so
        # expose_headers alone does not make the session id readable.
        self.assertEqual(
            resp.headers["access-control-allow-origin"], f"https://{self.REMOTE}"
        )

    def test_loopback_client_still_reaches_an_exposed_bridge(self):
        resp = self._preflight("localhost:8081", "http://localhost:6274")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.headers["access-control-allow-origin"], "http://localhost:6274"
        )

    def test_foreign_origin_gets_no_cors_grant(self):
        resp = self._preflight(self.REMOTE, "http://evil.attacker.test")
        self.assertNotIn("access-control-allow-origin", resp.headers)


if __name__ == "__main__":
    unittest.main()
