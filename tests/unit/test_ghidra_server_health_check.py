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
