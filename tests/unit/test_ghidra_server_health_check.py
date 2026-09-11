"""Unit tests for tools/ghidra_server_health_check.py.

Pure Python -- the one network call (`_probe`) is the seam every test replaces.
Nothing here opens a socket or sleeps for real.

This probe is what deploy/startup tasks gate on, so the behaviours that matter
are the ones that decide an exit code: a 200 is success even when the body is
not JSON, a non-200 is a *retryable* failure rather than an immediate verdict,
and running out of retries must return 1 rather than falling off the end of the
loop with a 0.
"""

from __future__ import annotations

import json

import pytest

from tools import ghidra_server_health_check as health


@pytest.fixture(autouse=True)
def _no_real_sleeping(monkeypatch):
    """Retry delays default to 2s; a unit test must never actually wait."""
    slept: list[float] = []
    monkeypatch.setattr(health.time, "sleep", slept.append)
    return slept


def _run(monkeypatch, argv, responses):
    """Drive main() with a scripted sequence of `_probe` outcomes.

    Each entry in `responses` is either a `(status, body)` tuple to return or an
    exception instance to raise.
    """
    calls: list[tuple[str, float]] = []
    queue = list(responses)

    def fake_probe(url, timeout):
        calls.append((url, timeout))
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(health, "_probe", fake_probe)
    monkeypatch.setattr(health.sys, "argv", ["ghidra_server_health_check.py", *argv])
    return health.main(), calls


# --------------------------------------------------------------------------- #
# Success paths
# --------------------------------------------------------------------------- #


def test_healthy_server_returns_zero_and_reports_the_status_field(monkeypatch, capsys):
    body = json.dumps({"status": "connected", "port": 8089})
    code, calls = _run(monkeypatch, [], [(200, body)])

    assert code == 0
    assert len(calls) == 1, "a healthy first attempt must not retry"
    out = capsys.readouterr().out
    assert "STATUS=200" in out
    assert "HEALTH=connected" in out


def test_message_field_is_used_when_status_is_absent(monkeypatch, capsys):
    """The Ghidra endpoint has spelled this both ways across versions."""
    code, _ = _run(monkeypatch, [], [(200, json.dumps({"message": "alive"}))])

    assert code == 0
    assert "HEALTH=alive" in capsys.readouterr().out


def test_json_object_without_either_field_still_reports_ok(monkeypatch, capsys):
    code, _ = _run(monkeypatch, [], [(200, json.dumps({"unrelated": 1}))])

    assert code == 0
    assert "HEALTH=ok" in capsys.readouterr().out


def test_non_json_body_on_a_200_is_still_healthy(monkeypatch, capsys):
    """A 200 is the verdict. An unparseable body must not turn success into
    failure -- the endpoint has returned bare text, and treating that as a
    fault would make deploy gate on the response *format*."""
    code, _ = _run(monkeypatch, [], [(200, "OK")])

    assert code == 0
    out = capsys.readouterr().out
    assert "STATUS=200" in out
    assert "HEALTH=" not in out


def test_json_scalar_body_is_not_treated_as_a_dict(monkeypatch, capsys):
    """`json.loads("7")` succeeds and returns an int; calling .get() on it
    would raise straight out of a health probe."""
    code, _ = _run(monkeypatch, [], [(200, "7")])

    assert code == 0
    assert "HEALTH=" not in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Retry behaviour
# --------------------------------------------------------------------------- #


def test_transient_connection_error_is_retried_until_it_succeeds(monkeypatch, capsys, _no_real_sleeping):
    import urllib.error

    code, calls = _run(
        monkeypatch,
        ["--retries", "3", "--retry-delay", "0.25"],
        [urllib.error.URLError("refused"), (200, "{}")],
    )

    assert code == 0
    assert len(calls) == 2
    assert _no_real_sleeping == [0.25], "the configured delay must be honoured"
    assert "Attempt 1/3 failed" in capsys.readouterr().out


def test_unexpected_status_is_retried_not_immediately_fatal(monkeypatch, capsys):
    """A 503 during startup is the normal case, not a verdict."""
    code, calls = _run(monkeypatch, ["--retries", "2"], [(503, "starting"), (200, "{}")])

    assert code == 0
    assert len(calls) == 2
    assert "Unexpected HTTP status 503" in capsys.readouterr().out


def test_exhausting_retries_returns_one_and_names_the_last_error(monkeypatch, capsys):
    code, calls = _run(
        monkeypatch,
        ["--retries", "3"],
        [OSError("boom-1"), OSError("boom-2"), OSError("boom-final")],
    )

    assert code == 1
    assert len(calls) == 3
    assert "ERROR=boom-final" in capsys.readouterr().out


def test_no_sleep_after_the_final_attempt(monkeypatch, _no_real_sleeping):
    """Sleeping after the last try just adds latency to a run that has already
    decided it failed."""
    code, _ = _run(monkeypatch, ["--retries", "2"], [OSError("a"), OSError("b")])

    assert code == 1
    assert len(_no_real_sleeping) == 1, "one delay between two attempts, none after"


def test_timeout_error_is_caught_like_any_other_transport_failure(monkeypatch):
    code, _ = _run(monkeypatch, ["--retries", "1"], [TimeoutError("slow")])

    assert code == 1


def test_persistent_bad_status_exhausts_retries_and_fails(monkeypatch, capsys):
    code, calls = _run(monkeypatch, ["--retries", "2"], [(500, "err"), (500, "err")])

    assert code == 1
    assert len(calls) == 2
    assert "ERROR=Unexpected HTTP status 500" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Argument handling
# --------------------------------------------------------------------------- #


def test_defaults_target_the_loopback_mcp_port(monkeypatch):
    """127.0.0.1, not `localhost`: on Windows the dual-stack resolution tries
    IPv6 first and Ghidra's HTTP server binds IPv4 only."""
    _, calls = _run(monkeypatch, [], [(200, "{}")])

    assert calls == [("http://127.0.0.1:8089/check_connection", 5.0)]


def test_url_and_timeout_flags_reach_the_probe(monkeypatch):
    _, calls = _run(
        monkeypatch,
        ["--url", "http://10.0.0.5:9000/check_connection", "--timeout", "1.5"],
        [(200, "{}")],
    )

    assert calls == [("http://10.0.0.5:9000/check_connection", 1.5)]


# --------------------------------------------------------------------------- #
# The transport seam itself
# --------------------------------------------------------------------------- #


def test_probe_returns_status_and_a_bounded_decoded_body(monkeypatch):
    """`_probe` caps the read at 4 KiB and decodes with ``errors="replace"``.

    Both matter: the endpoint can return a large listing, and a health probe
    that raises UnicodeDecodeError on a stray byte reports the server dead when
    it is in fact answering fine.
    """
    seen: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def read(self, size):
            seen["size"] = size
            return b"hello \xff world"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(url, timeout):
        seen["url"] = url
        seen["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(health.urllib.request, "urlopen", fake_urlopen)

    status, body = health._probe("http://h/check_connection", 3.0)

    assert status == 200
    assert body == "hello � world", "an undecodable byte must not raise"
    assert seen == {"size": 4096, "url": "http://h/check_connection", "timeout": 3.0}


def test_doctor_request_uses_a_larger_but_bounded_catalog_body_cap(monkeypatch):
    """The generated schema must fit in the doctor response bound without
    turning a network response into an unbounded read."""
    seen: dict[str, object] = {}

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self, size):
            seen["size"] = size
            return b'{"tools":[{"name":"tool"}]}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["authorization"] = request.get_header("Authorization")
        return FakeResponse()

    monkeypatch.setattr(health.urllib.request, "urlopen", fake_urlopen)

    status, body, headers = health._probe_request(
        "http://h/mcp/schema",
        3.0,
        headers={"Authorization": "Bearer secret"},
    )

    assert status == 200
    assert json.loads(body)["tools"]
    assert headers == {"Content-Type": "application/json"}
    assert seen == {
        "size": health.MAX_DOCTOR_BODY_BYTES,
        "url": "http://h/mcp/schema",
        "timeout": 3.0,
        "authorization": "Bearer secret",
    }


# --------------------------------------------------------------------------- #
# Layered doctor mode
# --------------------------------------------------------------------------- #


def _doctor_responses(responses):
    calls = []
    queue = list(responses)

    def fake_probe(url, timeout, method, headers):
        calls.append((url, timeout, method, headers))
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return fake_probe, calls


def _healthy_doctor_responses():
    return [
        (200, "Connected: GhidraMCP plugin running", {}),
        (
            200,
            json.dumps(
                {
                    "pid": 1234,
                    "project": "demo",
                    "project_path": "D:/example/project",
                    "programs": [{"name": "sample", "path": "/sample", "open": True}],
                    "tcp_port": 8089,
                }
            ),
            {},
        ),
        (200, json.dumps({"status": "ok", "active_requests": 0}), {}),
        (200, json.dumps({"tools": [{"name": "check_connection"}], "count": 1}), {}),
    ]


def test_doctor_reports_all_read_only_layers_and_optional_mcp_route():
    responses = _healthy_doctor_responses()
    responses.append((204, "", {"Access-Control-Allow-Origin": "http://localhost"}))
    fake_probe, calls = _doctor_responses(responses)

    report = health.run_doctor(
        "http://127.0.0.1:8089/check_connection",
        mcp_url="http://127.0.0.1:8081/mcp",
        retries=1,
        probe=fake_probe,
        sleep_fn=lambda _delay: None,
    )

    assert report["ok"] is True
    assert report["http_healthy"] is True
    assert report["mcp_initialize_healthy"] is None
    assert report["detected_transport"] == "streamable-http"
    assert [check["name"] for check in report["checks"]] == [
        "url",
        "plugin_connection",
        "instance_info",
        "server_health",
        "schema",
        "mcp_transport",
    ]
    assert calls[-1][2] == "OPTIONS"
    assert calls[-1][3]["Access-Control-Request-Method"] == "POST"
    assert report["checks"][2]["details"]["project_known"] is True
    assert "project_path" not in json.dumps(report)


def test_doctor_routes_headless_health_and_skips_gui_only_instance_probe():
    responses = [
        (200, "Connection OK - GhidraMCP Headless Server v6", {}),
        (200, json.dumps({"status": "healthy", "program_loaded": True}), {}),
        (200, json.dumps({"tools": [{"name": "headless_tool"}], "count": 1}), {}),
    ]
    fake_probe, calls = _doctor_responses(responses)

    report = health.run_doctor(
        retries=1,
        probe=fake_probe,
        sleep_fn=lambda _delay: None,
    )

    assert report["ok"] is True
    assert report["server_kind"] == "headless"
    assert report["http_healthy"] is True
    instance = next(check for check in report["checks"] if check["name"] == "instance_info")
    assert instance["ok"] is True
    assert instance["reason"] == "not_applicable:headless"
    assert [call[0].rsplit("/", 1)[-1] for call in calls] == [
        "check_connection",
        "health",
        "schema",
    ]
    assert all("/mcp/instance_info" not in call[0] for call in calls)
    assert all("/mcp/health" not in call[0] for call in calls)


def test_doctor_applies_optional_bearer_to_all_requests_without_reporting_it():
    responses = _healthy_doctor_responses()
    responses.append((204, "", {"Access-Control-Allow-Origin": "http://localhost"}))
    fake_probe, calls = _doctor_responses(responses)
    token = "secret-doctor-token"

    report = health.run_doctor(
        mcp_url="http://127.0.0.1:8081/mcp",
        auth_token=token,
        retries=1,
        probe=fake_probe,
        sleep_fn=lambda _delay: None,
    )

    assert report["ok"] is True
    assert len(calls) == 5
    assert all(call[3].get("Authorization") == f"Bearer {token}" for call in calls)
    assert token not in json.dumps(report)


def test_doctor_retries_a_transient_status_without_printing_response_body():
    responses = [
        (503, "secret-token-must-not-escape", {}),
        (200, "Connected: ready", {}),
        _healthy_doctor_responses()[1],
        _healthy_doctor_responses()[2],
        _healthy_doctor_responses()[3],
    ]
    fake_probe, _calls = _doctor_responses(responses)
    slept = []

    report = health.run_doctor(
        retries=2,
        retry_delay=0.25,
        probe=fake_probe,
        sleep_fn=slept.append,
    )

    connection = next(check for check in report["checks"] if check["name"] == "plugin_connection")
    assert connection["ok"] is True
    assert connection["attempts"] == 2
    assert slept == [0.25]
    assert "secret-token-must-not-escape" not in json.dumps(report)


def test_doctor_rejects_empty_schema_and_recommends_catalog_diagnosis():
    responses = _healthy_doctor_responses()
    responses[3] = (200, json.dumps({"tools": [], "count": 0}), {})
    fake_probe, _calls = _doctor_responses(responses)

    report = health.run_doctor(retries=1, probe=fake_probe, sleep_fn=lambda _delay: None)

    schema = next(check for check in report["checks"] if check["name"] == "schema")
    assert report["ok"] is False
    assert report["http_healthy"] is True
    assert schema["reason"] == "empty_schema"
    assert schema["details"]["tool_count"] == 0
    assert "catalog" in report["recommended_next_action"]


def test_doctor_classifies_wrong_mcp_path_without_networking_to_it():
    fake_probe, calls = _doctor_responses(_healthy_doctor_responses())

    report = health.run_doctor(
        mcp_url="http://127.0.0.1:8081/not-mcp",
        retries=1,
        probe=fake_probe,
        sleep_fn=lambda _delay: None,
    )

    mcp = next(check for check in report["checks"] if check["name"] == "mcp_transport")
    assert report["ok"] is False
    assert report["detected_transport"] == "unknown"
    assert mcp["reason"] == "unsupported_mcp_path"
    assert len(calls) == 4, "an unsupported path must not trigger an HTTP request"


def test_doctor_rejects_explicit_transport_path_mismatch_without_networking():
    fake_probe, calls = _doctor_responses(_healthy_doctor_responses())

    report = health.run_doctor(
        mcp_url="http://127.0.0.1:8081/sse",
        mcp_transport="streamable-http",
        retries=1,
        probe=fake_probe,
        sleep_fn=lambda _delay: None,
    )

    mcp = next(check for check in report["checks"] if check["name"] == "mcp_transport")
    assert report["ok"] is False
    assert report["detected_transport"] == "streamable-http"
    assert mcp["reason"] == "transport_path_mismatch"
    assert mcp["details"]["path_transport"] == "sse"
    assert len(calls) == 4


def test_doctor_rejects_credentials_and_queries_before_any_probe():
    fake_probe, calls = _doctor_responses([])

    report = health.run_doctor(
        "http://user:password@127.0.0.1:8089/check_connection?token=secret",
        retries=1,
        probe=fake_probe,
        sleep_fn=lambda _delay: None,
    )

    assert report["ok"] is False
    assert report["checks"][0]["name"] == "url"
    assert report["checks"][0]["reason"] == "embedded_credentials_not_allowed"
    assert calls == []


def test_doctor_handles_transport_failure_without_raising_or_echoing_error():
    responses = _healthy_doctor_responses()
    responses[0] = OSError("Bearer secret-token")
    fake_probe, _calls = _doctor_responses(responses)

    report = health.run_doctor(retries=1, probe=fake_probe, sleep_fn=lambda _delay: None)

    connection = next(check for check in report["checks"] if check["name"] == "plugin_connection")
    assert report["ok"] is False
    assert connection["reason"] == "transport_error:OSError"
    assert "secret-token" not in json.dumps(report)


def test_doctor_alias_and_json_mode_use_the_same_report(monkeypatch, capsys):
    expected = {
        "doctor_version": 1,
        "ok": True,
        "http_healthy": True,
        "mcp_initialize_healthy": None,
        "detected_transport": "http-plugin",
        "target": {"base_url": "http://127.0.0.1:8089", "loopback": True, "mcp_path": None},
        "checks": [],
        "recommended_next_action": "next",
    }
    monkeypatch.setattr(health, "run_doctor", lambda *args, **kwargs: expected)
    monkeypatch.setattr(
        health.sys,
        "argv",
        ["ghidra_server_health_check.py", "--doctor", "--format", "json"],
    )

    assert health.main() == 0
    assert json.loads(capsys.readouterr().out) == expected


def test_doctor_reads_bearer_token_from_named_environment(monkeypatch, capsys):
    seen = {}
    expected = {
        "ok": True,
        "detected_transport": "http-plugin",
        "checks": [],
        "recommended_next_action": "next",
    }

    def fake_run_doctor(*args, **kwargs):
        seen["auth_token"] = kwargs.get("auth_token")
        return expected

    monkeypatch.setattr(health, "run_doctor", fake_run_doctor)
    monkeypatch.setenv("TEST_GHIDRA_MCP_TOKEN", "env-secret")
    monkeypatch.setattr(
        health.sys,
        "argv",
        [
            "ghidra_server_health_check.py",
            "--doctor",
            "--auth-token-env",
            "TEST_GHIDRA_MCP_TOKEN",
        ],
    )

    assert health.main() == 0
    assert seen["auth_token"] == "env-secret"
    assert "env-secret" not in capsys.readouterr().out


def test_health_json_format_is_rejected_instead_of_emitting_mixed_json(monkeypatch):
    monkeypatch.setattr(
        health.sys,
        "argv",
        ["ghidra_server_health_check.py", "--format", "json"],
    )

    with pytest.raises(SystemExit) as exc_info:
        health.main()

    assert exc_info.value.code == 2
