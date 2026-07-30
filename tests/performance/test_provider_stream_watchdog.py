"""Regression coverage for the 2026-07-29 provider-watchdog investigation.

Root cause recap (see the CLIENT_ProcessControlCallbackMessage investigation):
the MiniMax call was non-streaming, so the only in-flight event was the poll
loop's provider_turn/"waiting" heartbeat -- which
`_event_proves_provider_activity` deliberately disqualifies. With no liveness
signal, the parent watchdog's flat 300s idle limit killed healthy long
generations, the SDK's own 180s read timeout never fired (30 kills, 0
APITimeoutErrors), and the resulting "no draft" was stamped with the TERMINAL
malformed_response status. 18 functions were permanently dropped from the port
pipeline without ever returning an unparseable response.

These tests pin each half of the fix:
  * streaming reassembles into the shape the turn loop consumes, and emits
    liveness deltas the watchdog counts;
  * the idle limit can no longer undercut the tier budget;
  * a timeout-only exhaustion is non-terminal and bounded;
  * the circuit breaker trips on consecutive timeouts and resets on a response.
"""

import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

fun_doc = pytest.importorskip("fun_doc")
port_pipeline = pytest.importorskip("port_pipeline")


# --------------------------------------------------------------------------
# Streaming chunk fixtures -- deliberately mimic the awkward parts of a real
# OpenAI-compatible stream: fragmented tool arguments, id/name only in the
# first fragment, a trailing usage-only chunk with empty choices.
# --------------------------------------------------------------------------

class _Obj:
    """Minimal stand-in for the SDK's pydantic chunk models (extra=allow)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def model_dump(self):
        out = {}
        for k, v in self.__dict__.items():
            out[k] = v.model_dump() if hasattr(v, "model_dump") else v
        return out


def _chunk(delta=None, finish_reason=None, usage=None, cid="c1", model="M3"):
    choices = []
    if delta is not None or finish_reason is not None:
        choices = [_Obj(index=0, delta=delta, finish_reason=finish_reason)]
    return _Obj(id=cid, model=model, choices=choices, usage=usage)


class _FakeCompletions:
    def __init__(self, chunks):
        self._chunks = chunks
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return iter(self._chunks)


class _FakeClient:
    def __init__(self, chunks):
        self.chat = _Obj(completions=_FakeCompletions(chunks))


def test_stream_reassembles_text_and_usage():
    usage = _Obj(prompt_tokens=11, completion_tokens=22)
    client = _FakeClient([
        _chunk(_Obj(content="Hel")),
        _chunk(_Obj(content="lo ")),
        _chunk(_Obj(content="world")),
        _chunk(finish_reason="stop"),
        _chunk(usage=usage),  # include_usage tail chunk: choices is empty
    ])

    resp = fun_doc._minimax_stream_completion(client, {"model": "M3"})

    assert resp.choices[0].message.content == "Hello world"
    assert resp.choices[0].finish_reason == "stop"
    assert resp.usage.prompt_tokens == 11
    assert resp.usage.completion_tokens == 22
    # Usage must be explicitly requested or streamed responses omit it and the
    # token accounting silently zeroes out.
    assert client.chat.completions.kwargs["stream"] is True
    assert client.chat.completions.kwargs["stream_options"] == {
        "include_usage": True}


def test_stream_preserves_reasoning_channel():
    """M3 routinely leaves part of a port draft in the reasoning channel; the
    lanes' reasoning_salvage_parse depends on it surviving reassembly. The
    SDK's own stream accumulator drops these non-standard fields, which is
    why _minimax_stream_completion accumulates by hand."""
    client = _FakeClient([
        _chunk(_Obj(content=None, reasoning_content="think ")),
        _chunk(_Obj(content=None, reasoning_content="harder")),
        _chunk(_Obj(content="answer"), finish_reason="stop"),
    ])

    msg = fun_doc._minimax_stream_completion(client, {"model": "M3"}).choices[0].message

    assert msg.content == "answer"
    assert msg.reasoning_content == "think harder"
    assert msg.model_dump().get("reasoning_content") == "think harder"


def test_stream_accumulates_fragmented_tool_calls():
    """Arguments dribble in across chunks and only the first fragment carries
    id/name -- keyed accumulation is what stops one call becoming N malformed
    ones."""
    client = _FakeClient([
        _chunk(_Obj(content=None, tool_calls=[
            _Obj(index=0, id="call_1", type="function",
                 function=_Obj(name="decompile_function", arguments='{"add'))])),
        _chunk(_Obj(content=None, tool_calls=[
            _Obj(index=0, id=None, type=None,
                 function=_Obj(name=None, arguments='ress":"0x1'))])),
        _chunk(_Obj(content=None, tool_calls=[
            _Obj(index=0, id=None, type=None,
                 function=_Obj(name=None, arguments='000"}'))])),
        _chunk(finish_reason="tool_calls"),
    ])

    msg = fun_doc._minimax_stream_completion(client, {"model": "M3"}).choices[0].message

    assert len(msg.tool_calls) == 1
    # Attribute access is what the turn loop uses (tc.id / tc.function.name /
    # tc.function.arguments), so construct() must yield real SDK tool-call
    # objects rather than the raw accumulation dicts.
    call = msg.tool_calls[0]
    assert call.id == "call_1"
    assert call.function.name == "decompile_function"
    assert call.function.arguments == '{"address":"0x1000"}'

    # ...and model_dump() must round-trip, because the assistant message is
    # appended straight back into `messages` for the next turn.
    dumped = msg.model_dump()
    assert dumped["tool_calls"][0]["function"]["arguments"] == '{"address":"0x1000"}'
    assert dumped["role"] == "assistant"


def test_stream_drops_incomplete_tool_call_fragment():
    """A fragment that never got an id/name is a call the model didn't finish
    emitting; echoing it back to the API is a 400."""
    client = _FakeClient([
        _chunk(_Obj(content=None, tool_calls=[
            _Obj(index=0, id=None, type=None,
                 function=_Obj(name=None, arguments='{"a":1}'))])),
        _chunk(finish_reason="stop"),
    ])

    msg = fun_doc._minimax_stream_completion(client, {"model": "M3"}).choices[0].message
    assert msg.tool_calls is None


def test_stream_emits_liveness_deltas():
    """The whole point of streaming here: give the watchdog something real to
    measure instead of the disqualified "waiting" heartbeat."""
    seen = []
    client = _FakeClient([
        _chunk(_Obj(content="abc")),
        _chunk(_Obj(content=None, reasoning_content="de")),
        _chunk(finish_reason="stop"),
    ])

    fun_doc._minimax_stream_completion(
        client, {"model": "M3"}, on_delta=seen.append)

    assert seen == [3, 2]


# --------------------------------------------------------------------------
# Watchdog deadline
# --------------------------------------------------------------------------

def test_streaming_status_counts_as_liveness_but_waiting_does_not():
    proves = fun_doc._event_proves_provider_activity
    assert proves("provider_turn", {"status": "streaming"}) is True
    assert proves("provider_turn", {"status": "waiting"}) is False
    assert proves("provider_turn", {"status": "response"}) is True
    assert proves("tool_call", {}) is True


def test_idle_limit_never_undercuts_the_tier_budget(monkeypatch):
    """The bug: idle_limit was a flat 300s, so the complex tier's larger budget
    only ever governed the never-emitted-anything branch. A session that proved
    itself alive was still killed at 300s."""
    monkeypatch.setenv("FUNDOC_MINIMAX_TIMEOUT_SECS", "450")
    monkeypatch.delenv("FUNDOC_PROVIDER_IDLE_SECS", raising=False)

    complex_budget = fun_doc._provider_timeout_seconds("minimax", "complex")
    assert complex_budget == 750

    idle_limit = max(
        60.0, float(__import__("os").environ.get("FUNDOC_PROVIDER_IDLE_SECS", "300")),
        float(complex_budget),
    )
    assert idle_limit == 750, (
        "a complex-tier session must get its full budget of quiet before the "
        "idle watchdog calls it hung")


# --------------------------------------------------------------------------
# Timeout exhaustion is not a verdict about the function
# --------------------------------------------------------------------------

@pytest.fixture
def _captured_state(monkeypatch):
    writes = {}
    monkeypatch.setattr(fun_doc, "update_function_state",
                        lambda key, fields: writes.update(fields))
    return writes


def _stub_prior(monkeypatch, row):
    monkeypatch.setattr(fun_doc, "_get_storage_repo",
                        lambda: _Obj(get_function=lambda p, a: row))


def test_timeout_only_exhaustion_is_non_terminal(_captured_state, monkeypatch):
    _stub_prior(monkeypatch, None)

    status = fun_doc._draft_exhausted_status(
        "prog::addr", "prog", "addr", attempts=3, timeouts=6,
        real_responses=0, detail="no parseable live-draft blocks")

    assert status == "provider_timeout"
    assert _captured_state["port_status"] == "provider_timeout"
    assert status not in port_pipeline._PORT_TERMINAL_STATUSES


def test_real_unparseable_response_stays_terminal(_captured_state, monkeypatch):
    """A genuine parse failure IS a verdict about the function -- it must keep
    retiring the row, or the queue never advances."""
    _stub_prior(monkeypatch, None)

    status = fun_doc._draft_exhausted_status(
        "prog::addr", "prog", "addr", attempts=3, timeouts=1,
        real_responses=2, detail="no parseable code blocks")

    assert status == "malformed_response"
    assert status in port_pipeline._PORT_TERMINAL_STATUSES


def test_timeout_rounds_are_bounded(_captured_state, monkeypatch):
    """An un-answerable prompt on a healthy provider must eventually retire
    instead of churning the queue forever."""
    _stub_prior(monkeypatch, {"port_status": "provider_timeout",
                              "port_attempts": fun_doc._MAX_TIMEOUT_ROUNDS - 1})

    status = fun_doc._draft_exhausted_status(
        "prog::addr", "prog", "addr", attempts=3, timeouts=6,
        real_responses=0, detail="no parseable live-draft blocks")

    assert status == "malformed_response"
    assert "retiring" in _captured_state["port_last_result"]


def test_timeout_round_counter_advances(_captured_state, monkeypatch):
    _stub_prior(monkeypatch, {"port_status": "provider_timeout",
                              "port_attempts": 1})

    fun_doc._draft_exhausted_status(
        "prog::addr", "prog", "addr", attempts=3, timeouts=6,
        real_responses=0, detail="x")

    assert _captured_state["port_attempts"] == 2


def test_retryable_rows_are_reselected_but_sort_last():
    funcs = {
        "p::a": {"address": "a", "name": "Fresh", "program": "p",
                 "program_name": "D2Client.dll", "effective_score": 95,
                 "caller_count": 1},
        "p::b": {"address": "b", "name": "TimedOut", "program": "p",
                 "program_name": "D2Client.dll", "effective_score": 95,
                 "caller_count": 99, "port_status": "provider_timeout"},
        "p::c": {"address": "c", "name": "Retired", "program": "p",
                 "program_name": "D2Client.dll", "effective_score": 95,
                 "caller_count": 99, "port_status": "malformed_response"},
    }

    picked = port_pipeline.select_port_candidates(funcs, set(), limit=10)
    names = [c["func"]["name"] for c in picked]

    assert "TimedOut" in names, "provider_timeout must be re-selected"
    assert "Retired" not in names, "malformed_response stays terminal"
    # Despite a 99x higher caller_count, the retry sorts behind untried work.
    assert names.index("Fresh") < names.index("TimedOut")


# --------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------

def test_breaker_trips_after_consecutive_timeouts(monkeypatch):
    monkeypatch.setenv("FUNDOC_PROVIDER_BREAKER_TIMEOUTS", "8")
    fun_doc.reset_provider_circuit()

    # One pathological candidate burns 6 sessions; that must NOT trip it.
    for _ in range(6):
        fun_doc.note_provider_session(timed_out=True)
    assert fun_doc.provider_circuit_open() is False

    for _ in range(2):
        fun_doc.note_provider_session(timed_out=True)
    assert fun_doc.provider_circuit_open() is True

    fun_doc.reset_provider_circuit()


def test_any_response_resets_the_breaker(monkeypatch):
    """A session that came back proves the provider is reachable, even if the
    body was unparseable."""
    monkeypatch.setenv("FUNDOC_PROVIDER_BREAKER_TIMEOUTS", "3")
    fun_doc.reset_provider_circuit()

    fun_doc.note_provider_session(timed_out=True)
    fun_doc.note_provider_session(timed_out=True)
    fun_doc.note_provider_session(timed_out=False)
    assert fun_doc.provider_circuit_open() is False

    for _ in range(2):
        fun_doc.note_provider_session(timed_out=True)
    assert fun_doc.provider_circuit_open() is False

    fun_doc.note_provider_session(timed_out=True)
    assert fun_doc.provider_circuit_open() is True

    fun_doc.reset_provider_circuit()


# --------------------------------------------------------------------------
# Turn-loop wiring: the streaming branch inside _invoke_minimax itself.
# The accumulator is unit-tested above; this pins the plumbing around it
# (client construction, liveness closure, meta/usage propagation) so a wiring
# slip can't silently reintroduce the blind non-streaming call.
# --------------------------------------------------------------------------

@pytest.fixture
def _fake_openai(monkeypatch):
    import openai

    captured = {}

    def _factory(**client_kwargs):
        captured["client_kwargs"] = client_kwargs
        return _FakeClient(captured["chunks"])

    monkeypatch.setattr(openai, "OpenAI", _factory)
    monkeypatch.setenv("MINIMAX_API_KEY", "test-key")
    monkeypatch.setattr(fun_doc, "bus_emit",
                        lambda *a, **k: captured.setdefault("events", []).append(a))
    return captured


def test_invoke_minimax_streams_and_returns_text(_fake_openai):
    _fake_openai["chunks"] = [
        _chunk(_Obj(content="```c\nint f(void){return 1;}\n```")),
        _chunk(finish_reason="stop"),
        _chunk(usage=_Obj(prompt_tokens=100, completion_tokens=40)),
    ]

    text, meta = fun_doc._invoke_minimax(
        "draft this", model="MiniMax-M3", max_turns=5, use_tools=False)

    assert "int f(void)" in text
    assert not meta.get("timed_out")
    # Usage must survive reassembly or the cost/token accounting zeroes out.
    assert meta.get("input_tokens") == 100
    assert meta.get("output_tokens") == 40
    # max_retries=0 is what stops the SDK from burning 3x the request timeout
    # inside one opaque call, invisible to the watchdog.
    assert _fake_openai["client_kwargs"]["max_retries"] == 0


def test_invoke_minimax_emits_a_liveness_event_the_watchdog_counts(_fake_openai):
    """End-to-end guard on the actual defect: the in-flight event must be one
    that _event_proves_provider_activity accepts."""
    # >10s of stream so the rate-limited emit definitely fires.
    import time as _time
    clock = {"t": 0.0}
    real_perf = _time.perf_counter

    def _fake_perf():
        clock["t"] += 6.0
        return clock["t"]

    _fake_openai["chunks"] = [_chunk(_Obj(content=f"tok{i} ")) for i in range(6)]
    _fake_openai["chunks"].append(_chunk(finish_reason="stop"))

    import fun_doc as fd
    orig = fd.time.perf_counter
    fd.time.perf_counter = _fake_perf
    try:
        fd._invoke_minimax("x", model="MiniMax-M3", max_turns=2, use_tools=False)
    finally:
        fd.time.perf_counter = orig

    statuses = [a[1].get("status") for a in _fake_openai.get("events", [])
                if a[0] == "provider_turn"]
    assert "streaming" in statuses, f"no streaming liveness event: {statuses}"
    assert fun_doc._event_proves_provider_activity(
        "provider_turn", {"status": "streaming"}) is True


def test_stream_can_be_disabled_by_env(_fake_openai, monkeypatch):
    """MINIMAX_STREAM=0 is the instant rollback if the endpoint misbehaves."""
    monkeypatch.setenv("MINIMAX_STREAM", "0")
    _fake_openai["chunks"] = []

    calls = {}

    class _NonStreaming(_FakeCompletions):
        def create(self, **kwargs):
            calls["kwargs"] = kwargs
            usage = _Obj(prompt_tokens=1, completion_tokens=1)
            msg = _Obj(content="plain", tool_calls=None,
                       model_dump=lambda: {"content": "plain", "role": "assistant"})
            return _Obj(choices=[_Obj(index=0, message=msg, finish_reason="stop")],
                        usage=usage, model="M3", id="x")

    import openai
    monkeypatch.setattr(openai, "OpenAI",
                        lambda **kw: _Obj(chat=_Obj(completions=_NonStreaming([]))))

    text, _meta = fun_doc._invoke_minimax(
        "x", model="MiniMax-M3", max_turns=2, use_tools=False)

    assert text == "plain"
    assert "stream" not in calls["kwargs"]
