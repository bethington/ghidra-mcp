"""Exercise the bridge's real network code paths against live local servers.

Historically transport.py/dispatch.py were tested only through mocks, which
left the actual socket/HTTP code (uds_request, tcp_request, do_request, the
dispatch retry ladder) at ~50% coverage — precisely the code that talks to
Ghidra. These tests run the real request path end-to-end:

* TCP: a ThreadingHTTPServer on 127.0.0.1:<ephemeral>.
* UDS: the same handler served over a real AF_UNIX socket (POSIX runners;
  Windows CPython has no AF_UNIX — see transport.uds_supported()).

No Ghidra required; everything binds loopback/tmp and tears down per class.
"""

import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import bridge_mcp_ghidra as bridge  # noqa: E402
from bridge_mcp_ghidra import dispatch, state, transport  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    """Tiny scriptable endpoint set shared by the TCP and UDS servers."""

    def _reply(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        self.server.hits.setdefault(self.path.split("?")[0], 0)
        self.server.hits[self.path.split("?")[0]] += 1
        if self.path.startswith("/ok"):
            self._reply(200, {"ok": True, "path": self.path})
        elif self.path.startswith("/flaky"):
            # 500 twice, then 200 — drives the dispatch_get retry ladder.
            if self.server.hits["/flaky"] <= 2:
                self._reply(500, {"error": "transient"})
            else:
                self._reply(200, {"ok": True, "recovered": True})
        elif self.path.startswith("/boom"):
            self._reply(500, {"error": "permanent"})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        self.server.hits.setdefault(self.path.split("?")[0], 0)
        self.server.hits[self.path.split("?")[0]] += 1
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        if self.path.startswith("/echo"):
            self._reply(200, {
                "content_type": self.headers.get("Content-Type"),
                "received": json.loads(raw) if raw else None,
                "path": self.path,
            })
        elif self.path.startswith("/boom"):
            self._reply(500, {"error": "write failed"})
        else:
            self._reply(404, {"error": "not found"})

    def log_message(self, *args):  # keep pytest output clean
        pass

    def address_string(self):
        # AF_UNIX client_address is b''/'' — BaseHTTPRequestHandler's
        # default implementation would crash indexing it.
        return "local"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _TcpServerMixin:
    """Start/stop a real HTTP server; expose base_url + hit counters."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.hits = {}
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.server.hits.clear()


class TestTcpRequest(_TcpServerMixin, unittest.TestCase):
    """transport.tcp_request over a real socket."""

    def test_get_returns_body_and_status(self):
        text, status = transport.tcp_request(self.base_url, "GET", "/ok")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(text)["ok"])

    def test_get_encodes_query_params(self):
        text, _ = transport.tcp_request(
            self.base_url, "GET", "ok", params={"program": "D2Common.dll", "n": 5}
        )
        path = json.loads(text)["path"]
        self.assertIn("program=D2Common.dll", path)
        self.assertIn("n=5", path)
        # Endpoint without a leading slash must be normalized to one.
        self.assertTrue(path.startswith("/ok?"))

    def test_post_sends_json_content_type_and_body(self):
        payload = {"address": "0x6fd50000", "name": "GetUnitPosition"}
        text, status = transport.tcp_request(
            self.base_url, "POST", "/echo", json_data=payload
        )
        self.assertEqual(status, 200)
        data = json.loads(text)
        self.assertEqual(data["content_type"], "application/json")
        self.assertEqual(data["received"], payload)

    def test_non_200_is_returned_not_raised(self):
        text, status = transport.tcp_request(self.base_url, "GET", "/boom")
        self.assertEqual(status, 500)
        self.assertIn("permanent", text)

    def test_connection_refused_raises(self):
        dead_url = f"http://127.0.0.1:{_free_port()}"
        with self.assertRaises(OSError):
            transport.tcp_request(dead_url, "GET", "/ok", timeout=2)


class TestDoRequestRouting(_TcpServerMixin, unittest.TestCase):
    """transport.do_request routes by state and refuses when disconnected."""

    def tearDown(self):
        state._active_tcp = None
        state._active_socket = None
        state._transport_mode = "none"

    def test_routes_to_tcp_when_active(self):
        state._transport_mode = "tcp"
        state._active_tcp = self.base_url
        text, status = transport.do_request("GET", "/ok")
        self.assertEqual(status, 200)

    def test_raises_connection_error_when_disconnected(self):
        state._transport_mode = "none"
        with self.assertRaises(ConnectionError):
            transport.do_request("GET", "/ok")


class TestDispatchAgainstLiveServer(_TcpServerMixin, unittest.TestCase):
    """The dispatch retry ladder, driven through a real server."""

    def setUp(self):
        super().setUp()
        state._transport_mode = "tcp"
        state._active_tcp = self.base_url
        state._connected_project = None

    def tearDown(self):
        state._active_tcp = None
        state._transport_mode = "none"
        state._connected_project = None

    def test_get_success_returns_raw_text(self):
        text = dispatch.dispatch_get("/ok")
        self.assertTrue(json.loads(text)["ok"])

    def test_get_retries_5xx_until_success(self):
        # /flaky returns 500 twice then 200; the backoff sleep is patched out
        # so the test doesn't pay 1s+2s of wall clock.
        with patch.object(dispatch.time, "sleep"):
            text = dispatch.dispatch_get("/flaky", retries=3)
        self.assertTrue(json.loads(text).get("recovered"))
        self.assertEqual(self.server.hits["/flaky"], 3)

    def test_get_exhausted_retries_surface_http_error(self):
        with patch.object(dispatch.time, "sleep"):
            text = dispatch.dispatch_get("/boom", retries=2)
        self.assertIn("HTTP 500", json.loads(text)["error"])
        self.assertEqual(self.server.hits["/boom"], 2)

    def test_get_non_retryable_status_returned_immediately(self):
        text = dispatch.dispatch_get("/missing")
        self.assertIn("HTTP 404", json.loads(text)["error"])
        self.assertEqual(self.server.hits["/missing"], 1)

    def test_post_success(self):
        text = dispatch.dispatch_post("/echo", {"k": "v"})
        self.assertEqual(json.loads(text)["received"], {"k": "v"})

    def test_post_5xx_is_never_retried(self):
        # Writes are non-idempotent: a 500 must surface after exactly ONE
        # request — re-sending could double-apply the write.
        text = dispatch.dispatch_post("/boom", {"k": "v"})
        self.assertIn("HTTP 500", json.loads(text)["error"])
        self.assertEqual(self.server.hits["/boom"], 1)

    def test_post_sends_query_params_separately_from_body(self):
        # The @Param(value="program") QUERY convention: program rides the
        # URL, never the JSON body.
        text = dispatch.dispatch_post(
            "/echo", {"name": "x"}, query_params={"program": "D2Game.dll"}
        )
        data = json.loads(text)
        self.assertIn("program=D2Game.dll", data["path"])
        self.assertEqual(data["received"], {"name": "x"})


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "AF_UNIX not available (Windows CPython)")
class TestUdsRequest(unittest.TestCase):
    """transport.uds_request against a real Unix-domain-socket HTTP server.

    Runs on the POSIX CI leg — this is the transport the macOS/Linux bridge
    actually uses in production, previously covered only by mocks.
    """

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.socket_path = str(Path(cls._tmpdir.name) / "ghidra-test.sock")

        class UdsHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            address_family = socket.AF_UNIX

            def server_bind(self):
                # HTTPServer.server_bind derives server_name/port from an
                # (ip, port) tuple; a UDS address is a plain path string.
                socketserver.TCPServer.server_bind(self)
                self.server_name = "uds"
                self.server_port = 0

        cls.server = UdsHTTPServer(cls.socket_path, _Handler)
        cls.server.hits = {}
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmpdir.cleanup()

    def test_get_round_trip(self):
        text, status = transport.uds_request(self.socket_path, "GET", "/ok")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(text)["ok"])

    def test_post_json_round_trip(self):
        text, status = transport.uds_request(
            self.socket_path, "POST", "/echo", json_data={"a": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(text)["received"], {"a": 1})

    def test_missing_socket_raises(self):
        with self.assertRaises(OSError):
            transport.uds_request(
                str(Path(self._tmpdir.name) / "nope.sock"), "GET", "/ok", timeout=2
            )


if __name__ == "__main__":
    unittest.main()
