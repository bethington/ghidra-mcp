"""FROZEN: oracle answering, process alive, game drawing nothing.

Measured 2026-07-31. Two fresh launches in a row came up alive, answering and
blank, and every existing probe called them healthy -- including the in-process
fault observer, because a stalled render thread raises no exception (/crash
stayed null throughout). Distinct from IDLE (parked at a menu, which still
presents) and from WEDGED (oracle gone).
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "fun-doc"))

import oracle_health as oh

# The shipping minimum sample window, captured before any test patches it.
REAL_MIN_SAMPLE_SEC = oh.MIN_PRESENT_SAMPLE_SEC


def _mon(monkeypatch, alive=True, running=True, hits=None, present=None,
         min_sample=0.0):
    """A monitor with every external probe injected.

    `min_sample` is MIN_PRESENT_SAMPLE_SEC for the duration of the test. These
    cases poll back-to-back, so wall time never advances and the shipping
    guard would suppress every verdict; defaulting it to 0 keeps them focused
    on the counter/edge-trigger logic they exist to pin. The guard itself is
    covered by test_back_to_back_polls_are_not_a_freeze, which uses the real
    value.
    """
    m = oh.OracleHealthMonitor(auto_recover=False)
    monkeypatch.setattr(oh, "check_oracle_alive", lambda: alive)
    monkeypatch.setattr(oh, "is_game_running", lambda: running)
    monkeypatch.setattr(oh, "MIN_PRESENT_SAMPLE_SEC", min_sample)
    monkeypatch.setattr(m, "_gameplay_hits_total", lambda: (next(hits) if hits else 1))
    monkeypatch.setattr(oh, "_present_count", (lambda: next(present)) if present else (lambda: None))
    monkeypatch.setattr(m, "_report_crash_if_any", lambda: None)
    return m


def test_flat_present_count_is_frozen(monkeypatch):
    m = _mon(monkeypatch, present=iter([500, 500, 500, 500]))
    s = m.check_once(); assert s["consecutive_not_presenting"] == 0, "no baseline yet"
    s = m.check_once(); assert not s["game_frozen"], "one flat poll is not a freeze"
    s = m.check_once(); assert s["game_frozen"] is True


def test_climbing_frames_are_never_frozen(monkeypatch):
    m = _mon(monkeypatch, present=iter([100, 200, 300, 400]))
    for _ in range(4):
        s = m.check_once()
    assert not s["game_frozen"]
    assert s["present_rate"] is not None and s["present_rate"] > 0


def test_unreadable_probe_is_not_a_freeze(monkeypatch):
    """A dropped HTTP call must not manufacture a fault."""
    m = _mon(monkeypatch, present=None)
    for _ in range(5):
        s = m.check_once()
    assert not s["game_frozen"] and s["consecutive_not_presenting"] == 0


def test_frozen_game_does_not_enable_live_prove(monkeypatch):
    """A frozen game answers the oracle, so reachability alone would keep
    feeding candidates into a game that cannot run them."""
    m = _mon(monkeypatch, present=iter([7, 7, 7, 7]))
    os.environ.pop("FUNDOC_LIVE_PROVE", None)
    m.check_once(); m.check_once(); s = m.check_once()
    assert s["game_frozen"]
    assert os.environ.get("FUNDOC_LIVE_PROVE") is None


def test_frozen_recovers_by_relaunch_not_navigation(monkeypatch):
    """A frozen game cannot be navigated -- the menu pump is on the stalled
    thread -- so it must take the force-close path."""
    m = _mon(monkeypatch, present=iter([9, 9, 9, 9]))
    calls = {"recover": 0, "enter": 0}
    monkeypatch.setattr(m, "_maybe_auto_recover", lambda snap: calls.__setitem__("recover", calls["recover"] + 1))
    monkeypatch.setattr(m, "_maybe_enter_game", lambda snap: calls.__setitem__("enter", calls["enter"] + 1))
    m.check_once(); m.check_once(); m.check_once()
    assert calls["recover"] >= 1, "must force-close a frozen game"
    assert calls["enter"] == 0, "navigation cannot cure a game that draws nothing"


def test_back_to_back_polls_are_not_a_freeze(monkeypatch):
    """Two polls in the same instant read the SAME frame counter on a healthy
    game -- 25-49 fps means a frame every 20-40 ms -- so a flat sample says
    nothing until MIN_PRESENT_SAMPLE_SEC of wall time has passed.

    Regression for 2026-08-02: check_once() has three off-cadence callers
    besides the 45s loop (start()'s first check, the post-relaunch refresh, and
    the dashboard's on-demand health route). Without the elapsed guard, any two
    of them landing together declared a game presenting a steady 25.0/sec
    FROZEN -- which force-closes it.
    """
    m = _mon(monkeypatch, present=iter([500] * 8), min_sample=REAL_MIN_SAMPLE_SEC)
    for _ in range(6):
        s = m.check_once()
    assert not s["game_frozen"], "a sub-frame sample window is not evidence of a hang"
    assert s["consecutive_not_presenting"] == 0


def test_freeze_report_is_edge_triggered(monkeypatch):
    m = _mon(monkeypatch, present=iter([3] * 8))
    events = []
    monkeypatch.setattr(m, "_log_event", lambda n, **k: events.append(n))
    monkeypatch.setattr(m, "_maybe_auto_recover", lambda snap: None)
    for _ in range(6):
        m.check_once()
    assert events.count("game_frozen") == 1, "one report per freeze, not per poll"
