import sys, time
sys.path.insert(0, "fun-doc")
import oracle_health as oh

def mk(**kw):
    return oh.OracleHealthMonitor(auto_recover=False, **kw)

def test_idle_needs_two_polls(monkeypatch):
    m = mk()
    monkeypatch.setattr(oh, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oh, "is_game_running", lambda: True)
    seq = iter([100, 100, 100, 100])
    monkeypatch.setattr(m, "_gameplay_hits_total", lambda: next(seq))
    s = m.check_once(); assert s["consecutive_idle"] == 0, "first poll has no baseline"
    s = m.check_once(); assert s["consecutive_idle"] == 1 and not s["game_idle"]
    s = m.check_once(); assert s["game_idle"] is True

def test_climbing_hits_never_idle(monkeypatch):
    m = mk()
    monkeypatch.setattr(oh, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oh, "is_game_running", lambda: True)
    c = iter([10, 20, 30, 40])
    monkeypatch.setattr(m, "_gameplay_hits_total", lambda: next(c))
    for _ in range(4):
        s = m.check_once()
    assert s["consecutive_idle"] == 0 and not s["game_idle"]

def test_unreadable_dispatchers_is_not_idle(monkeypatch):
    m = mk()
    monkeypatch.setattr(oh, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oh, "is_game_running", lambda: True)
    monkeypatch.setattr(m, "_gameplay_hits_total", lambda: None)
    for _ in range(5):
        s = m.check_once()
    assert not s["game_idle"] and s["consecutive_idle"] == 0

def test_counter_reset_after_outage_is_not_idle(monkeypatch):
    m = mk()
    alive = iter([True, True, False, True, True])
    monkeypatch.setattr(oh, "check_oracle_alive", lambda: next(alive))
    monkeypatch.setattr(oh, "is_game_running", lambda: True)
    hits = iter([500, 600, 5, 9])
    monkeypatch.setattr(m, "_gameplay_hits_total", lambda: next(hits))
    m.check_once(); m.check_once()
    m.check_once()
    s = m.check_once(); assert s["consecutive_idle"] == 0
    s = m.check_once(); assert not s["game_idle"]

def test_unreachable_oracle_is_not_idle(monkeypatch):
    m = mk()
    monkeypatch.setattr(oh, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oh, "is_game_running", lambda: True)
    for _ in range(5):
        s = m.check_once()
    assert not s["game_idle"]

def test_enter_game_skipped_when_nothing_needs_oracle(monkeypatch):
    called = []
    m = oh.OracleHealthMonitor(auto_recover=True, auto_recover_needed=lambda: False)
    monkeypatch.setattr(m, "_navigate_and_load_character", lambda *a: called.append(1) or {"ok": True})
    m._maybe_enter_game({"consecutive_idle": 2})
    assert not called, "must not drive a game nobody is waiting on"

def test_enter_game_requires_outcome(monkeypatch):
    m = oh.OracleHealthMonitor(auto_recover=True)
    monkeypatch.setattr(m, "_navigate_and_load_character", lambda *a: {"ok": True})
    monkeypatch.setattr(m, "_gameplay_started", lambda t: False)
    m._maybe_enter_game({"consecutive_idle": 2})
    assert m.get_state()["relaunch_stage"] == "failed"

def test_enter_game_cooldown(monkeypatch):
    m = oh.OracleHealthMonitor(auto_recover=True)
    n = []
    monkeypatch.setattr(m, "_navigate_and_load_character", lambda *a: n.append(1) or {"ok": True})
    monkeypatch.setattr(m, "_gameplay_started", lambda t: True)
    m._maybe_enter_game({"consecutive_idle": 2})
    m._maybe_enter_game({"consecutive_idle": 2})
    assert len(n) == 1, "second attempt must wait out the cooldown"
