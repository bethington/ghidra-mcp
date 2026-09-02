"""The test double has to be trustworthy before anything it says means much.

A fake that silently answers 200 to everything makes every suite pointing at it
green and worthless. These tests pin the two properties that give the fake its
value: it serves what Ghidra really returned, and it REFUSES what the catalog
does not describe.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from .fake_ghidra import (
    CATALOG_PATH,
    SCHEMA_SNAPSHOT,
    SNAPSHOT_DIR,
    FakeGhidraServer,
    load_contract,
    rehydrate,
)


def _get(url: str, timeout: float = 10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _post(url: str, payload: dict | None, timeout: float = 10):
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


# ---------------------------------------------------------------------------
# Fixture integrity
# ---------------------------------------------------------------------------


class TestFixtureIntegrity:
    def test_every_json_shaped_snapshot_rehydrates_to_valid_json(self):
        """A new normalization mask must not degrade the fake to a text server.

        tests/conformance/runner.py masks volatile values before recording, and
        a mask that lands outside a JSON string makes the snapshot unparseable.
        Exactly one does today (`"memory":<MEM>`), and fake_ghidra.rehydrate
        knows about it. If somebody adds another, this fails here rather than
        surfacing as a mystery in a replay run.

        Not every endpoint returns JSON -- /check_connection answers a bare
        sentence -- so the check is scoped to snapshots that are JSON-shaped.
        """
        broken = []
        for snap in sorted(SNAPSHOT_DIR.glob("*.snap")):
            text = rehydrate(snap.read_text(encoding="utf-8")).lstrip()
            if not text.startswith(("{", "[")):
                continue
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                broken.append(f"{snap.name}: {exc}")
        assert not broken, (
            "snapshots that do not rehydrate to JSON: "
            + "; ".join(broken)
            + ". Add the mask to fake_ghidra._UNQUOTED_MASKS."
        )

    def test_contract_covers_the_whole_catalog(self):
        contract = load_contract()
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))["endpoints"]
        assert len(contract) == len(catalog)

    def test_schema_is_a_subset_of_the_catalog(self):
        """Every advertised tool must be a catalogued endpoint.

        The reverse does not hold: the catalog also carries headless-only
        project-management endpoints the GUI schema never advertises. Those get
        routing but no parameter contract, and EndpointSpec.params is None to
        say so out loud rather than silently checking nothing.
        """
        contract = load_contract()
        schema = json.loads(SCHEMA_SNAPSHOT.read_text(encoding="utf-8"))["tools"]
        missing = [
            (t["path"], t["method"])
            for t in schema
            if (t["path"], t["method"].upper()) not in contract
        ]
        assert not missing, f"schema advertises endpoints absent from the catalog: {missing}"

        unchecked = sorted(spec.path for spec in contract.values() if spec.params is None)
        # Pinned as a count, not a list, so adding a headless endpoint does not
        # need this test edited -- but a sudden jump does get noticed.
        assert len(unchecked) == len(contract) - len(schema)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestRouting:
    def test_serves_a_recorded_payload_verbatim(self, fake_ghidra):
        status, body = _get(f"{fake_ghidra.url}/list_segments")
        assert status == 200
        recorded = (SNAPSHOT_DIR / "list_segments.snap").read_text(encoding="utf-8")
        assert json.loads(body) == json.loads(recorded)

    def test_unknown_endpoint_is_404(self, fake_ghidra):
        status, body = _get(f"{fake_ghidra.url}/definitely_not_an_endpoint")
        assert status == 404
        assert json.loads(body)["error"] == "no_such_endpoint"

    def test_wrong_method_is_405_and_names_the_right_one(self, fake_ghidra):
        # /disassemble_bytes is POST in the catalog.
        status, body = _get(f"{fake_ghidra.url}/disassemble_bytes")
        assert status == 405
        assert json.loads(body)["allowed"] == "POST"

    def test_schema_endpoint_serves_the_recorded_schema(self, fake_ghidra):
        status, body = _get(f"{fake_ghidra.url}/mcp/schema")
        assert status == 200
        assert json.loads(body) == json.loads(
            SCHEMA_SNAPSHOT.read_text(encoding="utf-8")
        )

    def test_instance_info_is_flat_not_enveloped(self, fake_ghidra):
        """ServerManager.buildInstanceInfoJson is Response.ok(map).toJson(),
        and Response.Ok.toJson() is JsonHelper.toJson(data) -- no wrapper."""
        status, body = _get(f"{fake_ghidra.url}/mcp/instance_info")
        assert status == 200
        info = json.loads(body)
        assert "data" not in info
        for key in ("project", "pid", "tcp_port"):
            assert key in info
        assert info["tcp_port"] == fake_ghidra.port

    def test_endpoint_without_a_recording_says_so(self, fake_ghidra):
        """No fixture must never look like a real answer."""
        status, body = _get(f"{fake_ghidra.url}/list_shadowed_globals")
        assert status == 200
        payload = json.loads(body)
        assert payload["_fake"] == "synthesized"
        assert "prove nothing" in payload["_note"]

    def test_never_binds_a_fixed_port(self):
        """Two fakes must coexist, and neither may be near 8089."""
        a = FakeGhidraServer().start()
        b = FakeGhidraServer().start()
        try:
            assert a.port != b.port
            assert 8089 not in (a.port, b.port)
        finally:
            a.stop()
            b.stop()


# ---------------------------------------------------------------------------
# The contract rules -- the reason this is a strict fake and not a replayer
# ---------------------------------------------------------------------------


class TestContractRules:
    def test_query_sourced_param_in_the_body_is_refused(self, fake_ghidra):
        """The wrong-binary bug, caught at the wire.

        `@Param(value = "program")` defaults to ParamSource.QUERY. A caller
        that puts `program` in the JSON body has it ignored by the real plugin,
        which then operates on whatever program is CURRENT -- a write to the
        wrong binary that reports success. A replaying fake cannot see this;
        this one refuses it.
        """
        status, body = _post(
            f"{fake_ghidra.url}/add_function_tag",
            {"function": "0x10001000", "tags": "crc", "program": "Benchmark.dll"},
        )
        assert status == 400
        payload = json.loads(body)
        assert payload["error"] == "param_in_wrong_place"
        assert payload["parameter"] == "program"

    def test_same_call_with_program_in_the_query_is_accepted(self, fake_ghidra):
        status, _ = _post(
            f"{fake_ghidra.url}/add_function_tag?program=Benchmark.dll",
            {"function": "0x10001000", "tags": "crc"},
        )
        assert status == 200

    def test_undeclared_parameter_is_refused(self, fake_ghidra):
        status, body = _get(f"{fake_ghidra.url}/list_functions?limit=5")
        assert status == 400
        payload = json.loads(body)
        assert payload["error"] == "unknown_parameter"
        assert payload["parameter"] == "limit"

    def test_bridge_synthetic_dry_run_is_not_treated_as_undeclared(self, fake_ghidra):
        """registry._build_tool_function appends `dry_run` as a query param for
        POST tools that do not declare one. It is a bridge convention, not a
        schema parameter, and must not trip the unknown-parameter rule."""
        status, _ = _post(
            f"{fake_ghidra.url}/add_function_tag?program=Benchmark.dll&dry_run=true",
            {"function": "0x10001000", "tags": "crc"},
        )
        assert status == 200

    def test_required_parameters_are_only_enforced_on_request(self, fake_ghidra, strict_fake):
        """The schema's `required` flag is unreliable (program selectors are
        declared required while the server still falls back to the current
        program), so enforcing it by default would manufacture failures the
        real server does not produce."""
        # /analyze_dataflow declares `address` required.
        lenient, _ = _get(f"{fake_ghidra.url}/analyze_dataflow")
        strict, body = _get(f"{strict_fake.url}/analyze_dataflow")
        assert lenient == 200
        assert strict == 400
        assert json.loads(body)["error"] == "missing_required_parameter"


class TestLenientMode:
    def test_lenient_mode_records_instead_of_refusing(self):
        server = FakeGhidraServer(strict=False).start()
        try:
            status, body = _get(f"{server.url}/list_functions?limit=5")
            assert status == 200, "lenient mode must serve the fixture"
            assert json.loads(body)["count"] > 0
            assert server.violation_keys() == ["unknown_parameter GET /list_functions [limit]"]
        finally:
            server.stop()

    def test_lenient_mode_still_404s_an_endpoint_it_cannot_serve(self):
        """Leniency is about not aborting the run, not about inventing data.
        With no catalog entry there is no fixture, so 404 is the honest answer
        -- and it is what a real plugin returns for an unregistered path."""
        server = FakeGhidraServer(strict=False).start()
        try:
            status, _ = _get(f"{server.url}/search_functions_by_name?name=main")
            assert status == 404
            assert server.violation_keys() == [
                "no_such_endpoint GET /search_functions_by_name"
            ]
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Fault injection
# ---------------------------------------------------------------------------


class TestFaultInjection:
    def test_fail_next_returns_the_injected_status_once(self, fake_ghidra):
        fake_ghidra.fail_next(503)
        assert _get(f"{fake_ghidra.url}/check_connection")[0] == 503
        assert _get(f"{fake_ghidra.url}/check_connection")[0] == 200

    def test_fail_next_can_be_scoped_to_one_path(self, fake_ghidra):
        fake_ghidra.fail_next(500, path="/get_version")
        assert _get(f"{fake_ghidra.url}/check_connection")[0] == 200
        assert _get(f"{fake_ghidra.url}/get_version")[0] == 500

    def test_malformed_next_returns_unparseable_json(self, fake_ghidra):
        fake_ghidra.malformed_next()
        status, body = _get(f"{fake_ghidra.url}/check_connection")
        assert status == 200
        with pytest.raises(json.JSONDecodeError):
            json.loads(body)

    def test_requests_are_recorded_for_inspection(self, fake_ghidra):
        _get(f"{fake_ghidra.url}/get_version")
        calls = fake_ghidra.calls_to("/get_version")
        assert len(calls) == 1
        assert calls[0].method == "GET"
        assert calls[0].status == 200
