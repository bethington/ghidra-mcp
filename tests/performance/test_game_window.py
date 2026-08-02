"""Coverage for the game-window layout (borderless, pinned, configurable).

Two windows belong to Game.exe and both shipped with a title bar:

    class 'Diablo II'   style 0x14CB0000   caption + sysmenu     <- the game
    class 'D2Debugger'  style 0x14CF0000   caption + resizable   <- the harness

Win32 is the only lever: the game presents through D2Gdi.dll, so there is no
renderer config that could place or unframe the window. (A ddraw.ini writer
lived here until 2026-08-02 on the belief that cnc-ddraw rendered the game; it
never did, and ddraw.dll is no longer even installed.)

The Win32 calls themselves are not tested here -- they need a live game. The
geometry maths is, because that is what silently goes wrong, plus the
`enabled: false` escape hatch, which must short-circuit before any Win32 call.
"""

import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

gw = pytest.importorskip("game_window")

# The real primary at the time this was written.
MON = {"name": "P", "primary": True, "x": 0, "y": 0, "width": 2560, "height": 1380}


def _cfg(**over):
    c = dict(gw.DEFAULTS)
    c["debugger"] = dict(gw.DEFAULTS["debugger"])
    c.update(over)
    return c


@pytest.fixture(autouse=True)
def _fixed_monitor(monkeypatch):
    monkeypatch.setattr(gw, "pick_monitor", lambda spec: dict(MON))


# ---------------------------------------------------------------- anchors ---

@pytest.mark.parametrize("anchor,expected", [
    ("top-left", (0, 0)),
    ("top-right", (2560 - 1068, 0)),
    ("bottom-left", (0, 1380 - 600)),
    ("bottom-right", (2560 - 1068, 1380 - 600)),
    ("bottom-center", ((2560 - 1068) // 2, 1380 - 600)),
    ("center", ((2560 - 1068) // 2, (1380 - 600) // 2)),
])
def test_anchor_positions(anchor, expected):
    assert gw.anchor_position(MON, 1068, 600, anchor) == expected


def test_bottom_edge_touches_the_screen_edge():
    """The requested layout: bottom of the game on the bottom of the screen."""
    g = gw.game_rect(_cfg(anchor="bottom-center"))
    assert g["y"] + g["h"] == MON["y"] + MON["height"]


def test_bottom_center_is_horizontally_centred():
    g = gw.game_rect(_cfg(anchor="bottom-center"))
    left_gap = g["x"] - MON["x"]
    right_gap = (MON["x"] + MON["width"]) - (g["x"] + g["w"])
    assert abs(left_gap - right_gap) <= 1


def test_explicit_xy_overrides_the_anchor():
    g = gw.game_rect(_cfg(anchor="bottom-center", x=17, y=23))
    assert (g["x"], g["y"]) == (17, 23)


def test_anchor_is_resolution_independent():
    """Anchors, not coordinates -- the layout must survive a display change
    without anyone editing numbers."""
    small = {"x": 0, "y": 0, "width": 1280, "height": 720, "primary": True,
             "name": "S"}
    x, y = gw.anchor_position(small, 1068, 600, "bottom-center")
    assert y + 600 == 720
    assert x == (1280 - 1068) // 2


# ------------------------------------------------------------- debugger ----

def test_debugger_fills_the_strip_left_of_the_game():
    """Requested: full vertical space on the left side of the game."""
    cfg = _cfg()
    g = gw.game_rect(cfg)
    d = gw.debugger_rect(cfg, g)
    assert d["x"] == MON["x"]
    assert d["x"] + d["w"] == g["x"], "its right edge must meet the game's left edge"
    assert d["y"] == MON["y"]
    assert d["h"] == MON["height"], "and it must span the full height"


def test_debugger_tracks_the_game_when_the_game_moves():
    """Derived from the game's rect, not hard-coded -- so the pair stays
    coherent if the game's anchor or size changes."""
    cfg = _cfg(anchor="bottom-right")
    g = gw.game_rect(cfg)
    d = gw.debugger_rect(cfg, g)
    assert d["x"] + d["w"] == g["x"]


def test_debugger_right_of_game_region():
    cfg = _cfg()
    cfg["debugger"] = {"region": "right-of-game", "full_height": True}
    g = gw.game_rect(cfg)
    d = gw.debugger_rect(cfg, g)
    assert d["x"] == g["x"] + g["w"]
    assert d["x"] + d["w"] == MON["x"] + MON["width"]


def test_debugger_explicit_xy_wins():
    cfg = _cfg()
    cfg["debugger"] = {"x": 5, "y": 6, "width": 100, "height": 200}
    d = gw.debugger_rect(cfg, gw.game_rect(cfg))
    assert (d["x"], d["y"], d["w"], d["h"]) == (5, 6, 100, 200)


# --------------------------------------------------------------- enabled ---

def test_disabled_skips_the_layout():
    """`enabled: false` must return before any Win32 call, not after."""
    res = gw.apply_layout(_cfg(enabled=False))
    assert "skipped" in res
    assert "game" not in res


# ---------------------------------------------------------------- config ---

def test_config_defaults_when_absent(tmp_path):
    p = tmp_path / "priority_queue.json"
    p.write_text('{"config": {}}', encoding="utf-8")
    cfg = gw.load_config(path=p)
    assert cfg["anchor"] == "bottom-center"
    assert cfg["debugger"]["region"] == "left-of-game"


def test_config_partial_override_keeps_other_defaults(tmp_path):
    p = tmp_path / "priority_queue.json"
    p.write_text('{"config": {"game_window": {"width": 1600}}}', encoding="utf-8")
    cfg = gw.load_config(path=p)
    assert cfg["width"] == 1600
    assert cfg["height"] == gw.DEFAULTS["height"]
    assert cfg["debugger"]["region"] == "left-of-game"


def test_config_unreadable_falls_back_to_defaults(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    assert gw.load_config(path=p) == gw.DEFAULTS
