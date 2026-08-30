"""A strict, catalog-driven fake of the Ghidra plugin's HTTP surface.

Issue #112. The integration tier needs a live Ghidra on :8089 with a binary
open, so CI can only ever run the thin offline tier and an outside contributor
cannot self-verify anything that touches the wire. This module is the missing
half: an HTTP server that answers the documented endpoints, so the bridge --
the real ``bridge_mcp_ghidra`` package, unmodified -- can be driven end to end
with no Ghidra installed.

What makes it a *strict* fake, and why that matters
---------------------------------------------------
The obvious design is a response replayer: record real traffic, play it back.
A replayer can only ever say **yes**. It hands the recorded body to whatever
asks, so a caller that used the wrong HTTP method, invented an endpoint, or put
a query parameter in the JSON body still gets ``200`` and the test still
passes. That is precisely the failure mode this repo has already been bitten by
-- a green suite that cannot go red.

So the fake is built the other way round. Its *behaviour* is derived from the
repo's own machine-checked contract:

* ``tests/endpoints.json``                      -- the routing table (253 endpoints)
* ``tests/conformance/snapshots/mcp_schema.snap`` -- the parameter contract
  (235 tools, each parameter carrying its declared ``source``: ``query`` or
  ``body``)

and only its *payloads* come from recordings (the 119 conformance snapshots,
captured from real Ghidra against the disposable benchmark binaries).

That split is the whole point. The fake refuses:

* an endpoint that is not in the catalog                       -> 404
* a method the catalog does not declare for that path          -> 405
* a parameter the schema does not declare                      -> 400
* a ``source: query`` parameter that arrived in the JSON body  -> 400

The last one is not hypothetical. ``@Param(value = "program")`` defaults to
``ParamSource.QUERY``, so every POST endpoint must send ``program`` as a URL
query parameter; a bridge that puts it in the body targets the server's
*current* program instead of the one the caller named -- a wrong-binary write,
silently successful. Against a replayer that regression is invisible. Here it
is a 400.

What this CANNOT prove
----------------------
Read ``tests/offline/README.md`` before adding a test here. In one line: this
proves the bridge speaks the protocol correctly and that response shapes match
what Ghidra really returned when the snapshots were recorded. It proves nothing
whatsoever about whether Ghidra does the right thing today. Recorded payloads
are frozen -- change a Java service's response shape and this tier stays green
until somebody re-records. Anything that claims more than it verifies is worse
than nothing.

Prior art
---------
``mad-sol-dev/GhidraMCPd`` (Apache-2.0) ships ``tests/fixtures/reference.bin``
plus ``scripts/reference_mcp_server.py``, a FastMCP stub that serves a
fixture-backed client over stdio for smoke tests. No code is taken from it.
The design differs deliberately: their stub substitutes for the *Ghidra client*
and is driven over the MCP layer, which means the bridge's HTTP transport,
dispatch and schema code never execute. This fake sits one layer lower, at the
HTTP boundary, so all of that code is the code under test.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
CATALOG_PATH = TESTS_ROOT / "endpoints.json"
SNAPSHOT_DIR = TESTS_ROOT / "conformance" / "snapshots"
SCHEMA_SNAPSHOT = SNAPSHOT_DIR / "mcp_schema.snap"
SESSION_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "session_responses.json"

# The bridge synthesises this query parameter for POST endpoints that do not
# declare their own `dry_run` (see registry._build_tool_function). It is a
# bridge-side convention rather than a schema-declared parameter, so the
# unknown-parameter check must not trip on it.
BRIDGE_SYNTHETIC_QUERY_PARAMS = frozenset({"dry_run"})

# Endpoints served by the plugin's HTTP layer rather than by an @McpTool, so
# they are absent from both the catalog and the schema.
INFRASTRUCTURE_PATHS = frozenset({"/mcp/schema", "/mcp/instance_info", "/mcp/health"})


# ---------------------------------------------------------------------------
# Snapshot rehydration
# ---------------------------------------------------------------------------

# tests/conformance/runner.py masks volatile values before recording, so a
# handful of snapshots are not valid JSON as stored. Rehydration puts a
# type-correct placeholder back. Any mask that lands *outside* a JSON string
# must be listed here or the snapshot cannot be served; a test asserts that
# every committed snapshot rehydrates to valid JSON, so a new mask that breaks
# parsing fails loudly instead of degrading this fake to a text server.
_UNQUOTED_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r":\s*<MEM>"), ": 0"),
)


def rehydrate(text: str) -> str:
    """Turn a normalized snapshot back into servable JSON."""
    for pattern, replacement in _UNQUOTED_MASKS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Contract loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParamSpec:
    name: str
    source: str  # "query" | "body"
    required: bool


@dataclass(frozen=True)
class EndpointSpec:
    path: str
    method: str
    category: str
    # None when the endpoint is in the catalog but not in the recorded schema
    # snapshot (the 18 headless-only project-management endpoints). Routing
    # still works; parameter contract checking is skipped and said so.
    params: dict[str, ParamSpec] | None


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_contract() -> dict[tuple[str, str], EndpointSpec]:
    """Build the routing + parameter contract from the repo's own artifacts."""
    catalog = _load_json(CATALOG_PATH)["endpoints"]
    schema = _load_json(SCHEMA_SNAPSHOT)["tools"]

    params_by_route: dict[tuple[str, str], dict[str, ParamSpec]] = {}
    for tool in schema:
        specs: dict[str, ParamSpec] = {}
        for p in tool.get("params", []):
            specs[p["name"]] = ParamSpec(
                name=p["name"],
                source=p.get("source", "query"),
                required=bool(p.get("required", False)),
            )
        params_by_route[(tool["path"], tool["method"].upper())] = specs

    contract: dict[tuple[str, str], EndpointSpec] = {}
    for entry in catalog:
        route = (entry["path"], entry["method"].upper())
        contract[route] = EndpointSpec(
            path=entry["path"],
            method=route[1],
            category=entry.get("category", "unknown"),
            params=params_by_route.get(route),
        )
    return contract


def load_snapshots() -> dict[str, str]:
    """Recorded response bodies, keyed by endpoint path."""
    bodies: dict[str, str] = {}
    for snap in sorted(SNAPSHOT_DIR.glob("*.snap")):
        if snap.stem == "mcp_schema":
            continue
        bodies["/" + snap.stem] = rehydrate(snap.read_text(encoding="utf-8"))
    return bodies


def load_session_fixtures() -> dict[str, Any]:
    """Hand-written responses for session-describing endpoints.

    ``tests/conformance/cases.ENVIRONMENT_COUPLED`` deliberately refuses to
    snapshot these: their output describes the *operator's* machine (project
    name, Ghidra Server address, which programs happen to be open), and the
    first recording pass leaked a private server address into a snapshot and
    tripped the repo's own data-egress guard. They are therefore hand-written
    here, and kept in a separate file so nobody mistakes them for recordings.
    """
    return _load_json(SESSION_FIXTURES)


# ---------------------------------------------------------------------------
# Request recording
# ---------------------------------------------------------------------------


@dataclass
class RecordedRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    body: Any
    raw_body: str
    status: int


@dataclass(frozen=True)
class Violation:
    """One contract breach, as a value so tests can assert on the whole set."""

    code: str
    method: str
    path: str
    parameter: str | None = None
    detail: str = ""

    def key(self) -> str:
        """Stable identity, suitable for a committed baseline file."""
        if self.parameter:
            return f"{self.code} {self.method} {self.path} [{self.parameter}]"
        return f"{self.code} {self.method} {self.path}"


@dataclass
class _Fault:
    """One queued fault. Consumed by the next matching request."""

    status: int | None = None
    body: str | None = None
    delay: float = 0.0
    malformed: bool = False
    close_early: bool = False
    times: int = 1
    path: str | None = None


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


class FakeGhidraServer:
    """A strict fake of the Ghidra plugin's HTTP surface.

    Binds an ephemeral loopback port -- never 8089, and never a fixed port, so
    two of these can run side by side and a developer's live Ghidra is never
    touched.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        project: str = "FakeOfflineProject",
        program: str = "Benchmark.dll",
        strict: bool = True,
        strict_required: bool = False,
    ) -> None:
        self.contract = load_contract()
        self.snapshots = load_snapshots()
        self.session = load_session_fixtures()
        self.schema_body = SCHEMA_SNAPSHOT.read_text(encoding="utf-8")
        self.project = project
        self.program = program
        # Two strictness modes, because the fake has two jobs.
        #
        # strict=True (default) -- REFUSE. Used when the caller under test is
        #   the bridge: the bridge must never violate the contract, so a
        #   violation has to be a hard failure at the wire.
        # strict=False -- RECORD AND SERVE. Used when replaying the existing
        #   integration suite, whose calls were written against a live server
        #   that tolerates undeclared parameters. Refusing there would abort
        #   the run at the first violation and hide everything downstream --
        #   one bad `limit=` on /list_functions skipped 18 later tests via a
        #   shared fixture. Recording instead lets the whole suite execute and
        #   yields the complete violation set, which a test then pins against a
        #   committed baseline. The violations are not swallowed; they are the
        #   deliverable.
        self.strict = strict
        # The schema's `required` flag is documented as unreliable -- several
        # program selectors are declared required while the server still falls
        # back to the current program (see registry._build_tool_function). So
        # enforcing it is opt-in: the contract tests turn it on deliberately,
        # replay runs leave it off rather than manufacture failures the real
        # server would not produce.
        self.strict_required = strict_required

        self.requests: list[RecordedRequest] = []
        self.violations: list[Violation] = []
        self._faults: list[_Fault] = []
        self._lock = threading.Lock()

        self._httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        self._httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"http://{host}:{port}"

    def start(self) -> "FakeGhidraServer":
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="fake-ghidra", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "FakeGhidraServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- fault injection ---------------------------------------------------

    def fail_next(
        self, status: int = 500, *, times: int = 1, body: str | None = None,
        path: str | None = None,
    ) -> None:
        """Return ``status`` for the next ``times`` matching requests."""
        with self._lock:
            self._faults.append(
                _Fault(status=status, body=body, times=times, path=path)
            )

    def stall_next(self, seconds: float, *, times: int = 1, path: str | None = None) -> None:
        """Sleep before answering -- drives the client's read timeout."""
        with self._lock:
            self._faults.append(_Fault(delay=seconds, times=times, path=path))

    def malformed_next(self, *, times: int = 1, path: str | None = None) -> None:
        """Answer 200 with a body that is not JSON."""
        with self._lock:
            self._faults.append(_Fault(malformed=True, times=times, path=path))

    def drop_next(self, *, times: int = 1, path: str | None = None) -> None:
        """Accept the request, then close without a complete response."""
        with self._lock:
            self._faults.append(_Fault(close_early=True, times=times, path=path))

    def clear_faults(self) -> None:
        with self._lock:
            self._faults.clear()

    def _take_fault(self, path: str) -> _Fault | None:
        with self._lock:
            for fault in self._faults:
                if fault.path is not None and fault.path != path:
                    continue
                fault.times -= 1
                if fault.times <= 0:
                    self._faults.remove(fault)
                return fault
        return None

    # -- observability -----------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()
            self.violations.clear()
            self._faults.clear()

    def calls_to(self, path: str) -> list[RecordedRequest]:
        return [r for r in self.requests if r.path == path]

    def violation_keys(self) -> list[str]:
        """Sorted, de-duplicated violation identities."""
        return sorted({v.key() for v in self.violations})

    def _record(self, rec: RecordedRequest) -> None:
        with self._lock:
            self.requests.append(rec)

    def _note(self, violation: Violation) -> None:
        with self._lock:
            self.violations.append(violation)

    # -- routing + contract ------------------------------------------------

    def instance_info(self) -> dict[str, Any]:
        info = dict(self.session["/mcp/instance_info"])
        info["project"] = self.project
        info["tcp_port"] = self.port
        return info

    def resolve(self, method: str, path: str, query: dict, body: dict | None):
        """Return ``(status, body_text)`` for one request.

        Kept separate from the HTTP handler so the routing and contract rules
        can be unit-tested without a socket.
        """
        if path == "/mcp/schema":
            if method != "GET":
                return 405, self._err("method_not_allowed", allowed="GET")
            return 200, self.schema_body
        if path in ("/mcp/instance_info", "/mcp/health"):
            # Flat, not wrapped. ServerManager.buildInstanceInfoJson() calls
            # Response.ok(map).toJson(), and Response.Ok.toJson() is just
            # JsonHelper.toJson(data) -- no envelope. The bridge's
            # discovery._unwrap_response_data() tolerates a "data" key, but
            # emitting one here would diverge from the plugin and quietly
            # break any consumer that reads the fields directly.
            payload = (
                self.instance_info()
                if path == "/mcp/instance_info"
                else self.session["/mcp/health"]
            )
            return 200, json.dumps(payload)

        spec = self.contract.get((path, method))
        if spec is None:
            other = sorted(m for (p, m) in self.contract if p == path)
            if other:
                self._note(
                    Violation(
                        "method_not_allowed", method, path,
                        detail=f"{path} accepts {other}, not {method}",
                    )
                )
                if self.strict:
                    return 405, self._err(
                        "method_not_allowed",
                        detail=f"{path} accepts {other}, not {method}",
                        allowed=",".join(other),
                    )
                # Lenient: serve the fixture the endpoint would have returned
                # under its declared method, so the run continues.
                return 200, self._payload_for(self.contract[(path, other[0])])
            self._note(
                Violation(
                    "no_such_endpoint", method, path,
                    detail=f"{path} is not in tests/endpoints.json",
                )
            )
            # Even lenient mode cannot serve this: there is no contract entry
            # and no fixture. 404 is the honest answer, and it is also what a
            # real plugin returns for a path it does not register.
            return 404, self._err(
                "no_such_endpoint", detail=f"{path} is not in tests/endpoints.json"
            )

        violations = self._check_params(spec, query, body)
        for violation in violations:
            self._note(violation)
        if violations and self.strict:
            first = violations[0]
            return 400, self._err(
                first.code, detail=first.detail, parameter=first.parameter
            )

        return 200, self._payload_for(spec)

    def _check_params(
        self, spec: EndpointSpec, query: dict, body: dict | None
    ) -> list[Violation]:
        if spec.params is None:
            # Headless-only endpoint, absent from the recorded schema snapshot.
            # Routing works; there is nothing to check parameters against, and
            # inventing a check would be a guess.
            return []

        found: list[Violation] = []
        body_keys = set(body or {})
        query_keys = set(query) - BRIDGE_SYNTHETIC_QUERY_PARAMS

        for name in sorted(query_keys | body_keys):
            if name not in spec.params:
                found.append(
                    Violation(
                        "unknown_parameter", spec.method, spec.path, parameter=name,
                        detail=(
                            f"{spec.method} {spec.path} does not declare a parameter "
                            f"named '{name}'. Declared: {sorted(spec.params)}"
                        ),
                    )
                )

        # The rule the whole fake exists for. @Param defaults to
        # ParamSource.QUERY, so `program` (and every other query-sourced
        # parameter) must arrive in the URL. Sent in the JSON body it is
        # ignored by the real plugin, which then silently operates on whatever
        # program happens to be current -- a wrong-binary write that reports
        # success.
        for name in sorted(body_keys & set(spec.params)):
            if spec.params[name].source == "query":
                found.append(
                    Violation(
                        "param_in_wrong_place", spec.method, spec.path, parameter=name,
                        detail=(
                            f"'{name}' is declared source=query for {spec.method} "
                            f"{spec.path} but arrived in the JSON body. The real "
                            f"plugin ignores it there and falls back to the current "
                            f"program."
                        ),
                    )
                )
        for name in sorted(query_keys & set(spec.params)):
            if spec.params[name].source == "body" and spec.method == "POST":
                found.append(
                    Violation(
                        "param_in_wrong_place", spec.method, spec.path, parameter=name,
                        detail=(
                            f"'{name}' is declared source=body for {spec.method} "
                            f"{spec.path} but arrived in the query string."
                        ),
                    )
                )

        if self.strict_required:
            supplied = query_keys | body_keys
            missing = sorted(
                n for n, p in spec.params.items() if p.required and n not in supplied
            )
            if missing:
                found.append(
                    Violation(
                        "missing_required_parameter", spec.method, spec.path,
                        detail=f"{spec.method} {spec.path} requires {missing}",
                    )
                )
        return found

    def _payload_for(self, spec: EndpointSpec) -> str:
        recorded = self.snapshots.get(spec.path)
        if recorded is not None:
            return recorded
        hand_written = self.session.get(spec.path)
        if hand_written is not None:
            return json.dumps(hand_written)
        # No fixture. Say so in the payload rather than inventing plausible
        # content: a test that asserts on a synthesized body is asserting on
        # this file, not on Ghidra, and the marker makes that impossible to
        # miss.
        return json.dumps(
            {
                "_fake": "synthesized",
                "_note": (
                    "No recorded fixture for this endpoint. Shape assertions "
                    "against this body prove nothing about Ghidra."
                ),
                "endpoint": spec.path,
                "method": spec.method,
                "category": spec.category,
            }
        )

    @staticmethod
    def _err(code: str, **extra: Any) -> str:
        payload = {"error": code, "_fake": "contract_violation"}
        payload.update({k: v for k, v in extra.items() if v is not None})
        return json.dumps(payload)


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


def _make_handler(server: FakeGhidraServer):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "FakeGhidraMCP/1.0"

        def log_message(self, *args: object) -> None:  # noqa: A003 - stdlib API
            pass  # silence the per-request stderr line

        # -- helpers -------------------------------------------------------

        def _read_body(self) -> tuple[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return "", None
            raw = self.rfile.read(length).decode("utf-8")
            try:
                return raw, json.loads(raw)
            except json.JSONDecodeError:
                return raw, None

        def _send(self, status: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _handle(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query, keep_blank_values=True)
            raw_body, body = self._read_body()

            fault = server._take_fault(path)
            if fault is not None:
                if fault.delay:
                    time.sleep(fault.delay)
                if fault.close_early:
                    server._record(RecordedRequest(method, path, query, body, raw_body, -1))
                    self.close_connection = True
                    return
                if fault.malformed:
                    server._record(RecordedRequest(method, path, query, body, raw_body, 200))
                    self._send(200, "{not json at all")
                    return
                if fault.status is not None:
                    text = fault.body or json.dumps(
                        {"error": "injected_fault", "status": fault.status}
                    )
                    server._record(
                        RecordedRequest(method, path, query, body, raw_body, fault.status)
                    )
                    self._send(fault.status, text)
                    return

            status, text = server.resolve(method, path, query, body)
            server._record(RecordedRequest(method, path, query, body, raw_body, status))
            self._send(status, text)

        # -- verbs ---------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 - stdlib API
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802 - stdlib API
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802 - stdlib API
            self._handle("PUT")

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib API
            self._handle("DELETE")

    return Handler


# ---------------------------------------------------------------------------
# CLI -- run the fake standalone so a contributor can point anything at it
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m tests.offline.fake_ghidra",
        description="Serve a strict fake of the Ghidra plugin's HTTP surface.",
    )
    parser.add_argument("--port", type=int, default=0, help="0 = ephemeral (default)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--lenient",
        action="store_true",
        help="record contract violations instead of refusing them",
    )
    parser.add_argument("--strict-required", action="store_true")
    args = parser.parse_args(argv)

    server = FakeGhidraServer(
        host=args.host,
        port=args.port,
        strict=not args.lenient,
        strict_required=args.strict_required,
    ).start()
    print(f"fake Ghidra plugin on {server.url}")
    print(f"  routes            : {len(server.contract)}")
    print(f"  recorded payloads : {len(server.snapshots)}")
    print(f"export GHIDRA_MCP_URL={server.url}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())
