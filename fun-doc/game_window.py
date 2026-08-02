r"""Deterministic game-window layout: borderless, fixed size, pinned position.

WHY
---
Two visible windows belong to Game.exe, and both shipped with a title bar:

    class 'Diablo II'   style 0x14CB0000   caption + sysmenu      <- the game
    class 'D2Debugger'  style 0x14CF0000   caption + resizable    <- the harness

WIN32 IS THE ONLY LEVER -- there is no renderer config to lean on.

This module used to also write geometry into cnc-ddraw's `ddraw.ini`, on the
belief that cnc-ddraw was the renderer. It never was. The game runs in the GDI
video mode and presents through `D2Gdi.dll`, measured directly with the
D2Debugger hook counters (`GET /capture/probe`): `StretchBlt` fires ~25/sec
with `D2Gdi.dll` as both first and last caller, `BitBlt` zero. `ddraw` was
merely LOADED, never called -- which is why `ddraw.ini`'s `border=false` never
did anything, and why every observed border strip actually came from
`_set_borderless` below.

Since 2026-08-01 the point is moot in a second, harder way: SGD2FreeRes-GDI
made `ddraw.dll` unnecessary and it was deleted from the game folder, so the
file has no reader at all. Writing it was removed rather than left as a
harmless no-op, because a config write that looks like it configures something
is how a false premise survives -- this one outlived its own disproof by a day.

WHAT IT DOES
------------
`apply_layout()` -- after the game is up, enforce the layout with Win32:
    * the GAME window loses WS_CAPTION/WS_THICKFRAME and is moved to the
      configured spot;
    * the D2DEBUGGER window KEEPS its frame -- it is a debug surface you
      still want to drag, resize and close -- but is placed (and sized) so
      the layout is reproducible across relaunches.

CONFIG (priority_queue.json -> config.game_window), all optional:

    {
      "enabled": true,
      "borderless": true,
      "width": 1068, "height": 600,
      "anchor": "bottom-center",          # or explicit "x"/"y"
      "monitor": "primary",
      "debugger": {                       # placed RELATIVE TO THE GAME
        "region": "left-of-game",         # or right-of-game / anchored
        "full_height": true               # or explicit x/y/width/height
      }
    }

Everything is anchored rather than hard-coded: `anchor` resolves against the
chosen monitor's WORK AREA (so "bottom" means the top of the taskbar, not
under it), and the debugger's rect is derived from the game's. Change the
resolution, the monitor, or the game size and the pair stays coherent without
editing coordinates. Explicit `x`/`y` always win.

The default layout: the game sits bottom-centre with its bottom edge on the
screen edge, and the debugger fills the full-height strip to its left.

Pure ctypes -- no new dependency, consistent with is_game_running shelling out
to tasklist rather than pulling in psutil.
"""
from __future__ import annotations

import ctypes
import json
from ctypes import wintypes
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PRIORITY_QUEUE = SCRIPT_DIR / "priority_queue.json"

# Declare DPI awareness ONCE, at import, before any coordinate is read.
#
# Doing it lazily inside monitors() silently changed the units of every
# subsequent GetWindowRect in the SAME process: a window read as 859x508
# before the call read as 1074x635 after, purely because the process had
# become DPI-aware (x1.25 on this 125%-scaled display). Nothing had moved, but
# a before/after comparison said it had -- which is exactly the kind of
# measurement error that sends you fixing the wrong thing.
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PER_MONITOR_AWARE_V2
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

GAME_CLASS = "Diablo II"
DEBUGGER_CLASS = "D2Debugger"

# Win32 constants (avoiding a dependency for five integers).
GWL_STYLE = -16
WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_BORDER = 0x00800000
WS_DLGFRAME = 0x00400000
SWP_NOSIZE = 0x0001
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_FRAMECHANGED = 0x0020

DEFAULTS = {
    "enabled": True,
    "borderless": True,
    "width": 1068,
    "height": 600,
    # Anchored, not hard-coded coordinates: the layout then survives a
    # resolution or monitor change without editing numbers.
    "anchor": "bottom-center",
    "monitor": "primary",
    # The debugger is placed RELATIVE TO THE GAME, so the two stay a coherent
    # pair no matter where the game lands. `left-of-game` + full_height fills
    # the whole strip beside it.
    "debugger": {"region": "left-of-game", "full_height": True},
}

# Anchors resolve against the monitor's WORK AREA, so "bottom" means the top of
# the taskbar rather than underneath it.
_ANCHORS = (
    "top-left", "top-center", "top-right",
    "center-left", "center", "center-right",
    "bottom-left", "bottom-center", "bottom-right",
)


# --------------------------------------------------------------- config ----

def load_config(path=None) -> dict:
    """config.game_window merged over DEFAULTS. Never raises."""
    cfg = dict(DEFAULTS)
    try:
        with open(path or PRIORITY_QUEUE, "r", encoding="utf-8") as f:
            block = (json.load(f).get("config") or {}).get("game_window") or {}
    except (OSError, ValueError):
        return cfg
    dbg = dict(cfg["debugger"])
    dbg.update(block.get("debugger") or {})
    cfg.update({k: v for k, v in block.items() if k != "debugger"})
    cfg["debugger"] = dbg
    return cfg


# ------------------------------------------------------------- monitors ----

def monitors() -> list:
    """[{name, primary, x, y, width, height}] for every display."""
    out = []
    try:
        user32 = ctypes.windll.user32

        MONITORENUMPROC = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.POINTER(wintypes.RECT), ctypes.c_double)

        class MONITORINFOEXW(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD),
                        ("rcMonitor", wintypes.RECT),
                        ("rcWork", wintypes.RECT),
                        ("dwFlags", wintypes.DWORD),
                        ("szDevice", wintypes.WCHAR * 32)]

        def _cb(hmon, hdc, lprc, data):
            mi = MONITORINFOEXW()
            mi.cbSize = ctypes.sizeof(MONITORINFOEXW)
            if user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                r = mi.rcWork          # work area: excludes the taskbar
                out.append({
                    "name": mi.szDevice,
                    "primary": bool(mi.dwFlags & 1),   # MONITORINFOF_PRIMARY
                    "x": r.left, "y": r.top,
                    "width": r.right - r.left,
                    "height": r.bottom - r.top,
                })
            return 1

        user32.EnumDisplayMonitors(0, None, MONITORENUMPROC(_cb), 0)
    except Exception:
        pass
    return out


def pick_monitor(spec) -> dict | None:
    mons = monitors()
    if not mons:
        return None
    if not spec or spec == "primary":
        return next((m for m in mons if m["primary"]), mons[0])
    for m in mons:
        if str(spec).lower() in m["name"].lower():
            return m
    return next((m for m in mons if m["primary"]), mons[0])


def anchor_position(mon, width, height, anchor):
    """Top-left (x, y) placing a width x height window at `anchor` on `mon`."""
    anchor = (anchor or "top-left").lower()
    vert, _, horiz = anchor.partition("-")
    if anchor == "center":
        vert = horiz = "center"
    x = {
        "left": mon["x"],
        "center": mon["x"] + max(0, (mon["width"] - width) // 2),
        "right": mon["x"] + max(0, mon["width"] - width),
    }.get(horiz, mon["x"])
    y = {
        "top": mon["y"],
        "center": mon["y"] + max(0, (mon["height"] - height) // 2),
        "bottom": mon["y"] + max(0, mon["height"] - height),
    }.get(vert, mon["y"])
    return x, y


def game_rect(cfg=None) -> dict:
    """(x, y, w, h) for the GAME window. Explicit x/y win over the anchor."""
    cfg = cfg or load_config()
    mon = pick_monitor(cfg.get("monitor")) or {"x": 0, "y": 0,
                                               "width": 1920, "height": 1080}
    w, h = int(cfg["width"]), int(cfg["height"])
    if cfg.get("x") is not None and cfg.get("y") is not None:
        x, y = int(cfg["x"]), int(cfg["y"])
    else:
        # `corner` is accepted as a synonym so an older config keeps working.
        x, y = anchor_position(mon, w, h,
                               cfg.get("anchor") or cfg.get("corner"))
    return {"x": x, "y": y, "w": w, "h": h, "monitor": mon}


def debugger_rect(cfg=None, game=None) -> dict:
    """(x, y, w, h) for the D2Debugger window, placed RELATIVE TO THE GAME.

    `region: left-of-game` fills the strip beside the game; with
    `full_height` it spans the monitor's whole work area vertically. Deriving
    it from the game's rect rather than from fixed coordinates keeps the pair
    coherent if the game moves or its size changes.
    """
    cfg = cfg or load_config()
    game = game or game_rect(cfg)
    mon = game["monitor"]
    dbg = cfg.get("debugger") or {}

    if dbg.get("x") is not None and dbg.get("y") is not None:
        return {"x": int(dbg["x"]), "y": int(dbg["y"]),
                "w": dbg.get("width"), "h": dbg.get("height")}

    region = (dbg.get("region") or "left-of-game").lower()
    full_h = bool(dbg.get("full_height", True))
    y = mon["y"]
    h = mon["height"] if full_h else None

    if region == "left-of-game":
        x = mon["x"]
        w = max(0, game["x"] - mon["x"])
    elif region == "right-of-game":
        x = game["x"] + game["w"]
        w = max(0, (mon["x"] + mon["width"]) - x)
    else:                                  # anchored fallback
        w = int(dbg.get("width") or 720)
        h = int(dbg.get("height") or 576)
        x, y = anchor_position(mon, w, h, dbg.get("anchor") or dbg.get("corner"))
    if dbg.get("width"):
        w = int(dbg["width"])
    if dbg.get("height"):
        h = int(dbg["height"])
    return {"x": x, "y": y, "w": w, "h": h}


# --------------------------------------------------------------- Win32 ----

def _find_windows(class_name: str) -> list:
    """Visible top-level HWNDs with the given class name."""
    found = []
    try:
        user32 = ctypes.windll.user32
        EnumWindowsProc = ctypes.WINFUNCTYPE(
            ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

        def _cb(hwnd, _l):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buf, 256)
            if buf.value == class_name and user32.IsWindowVisible(hwnd):
                found.append(hwnd)
            return True

        user32.EnumWindows(EnumWindowsProc(_cb), 0)
    except Exception:
        pass
    return found


def _set_borderless(hwnd) -> bool:
    """Strip the frame. Returns True only if the style ACTUALLY changed.

    Read back rather than trusting the call: the game runs ELEVATED, and UIPI
    silently drops SetWindowLong/SetWindowPos sent from a lower integrity
    level. The call "succeeds", the window keeps its title bar, and nothing
    reports a problem -- which is why this must be applied from the elevated
    dashboard, not from an operator shell.
    """
    user32 = ctypes.windll.user32
    style = user32.GetWindowLongW(hwnd, GWL_STYLE)
    new = style & ~(WS_CAPTION | WS_THICKFRAME | WS_BORDER | WS_DLGFRAME)
    if new == style:
        return False
    user32.SetWindowLongW(hwnd, GWL_STYLE, new)
    # SWP_FRAMECHANGED is required or the non-client area is not recalculated
    # and the title bar keeps drawing until something else forces a reframe.
    user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
                        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
                        | SWP_FRAMECHANGED)
    return (user32.GetWindowLongW(hwnd, GWL_STYLE) & WS_CAPTION) == 0


def _place(hwnd, x, y, w=None, h=None) -> None:
    """Move, and resize too when w/h are given."""
    flags = SWP_NOZORDER | SWP_NOACTIVATE
    if w is None or h is None:
        flags |= SWP_NOSIZE
        w = h = 0
    ctypes.windll.user32.SetWindowPos(
        hwnd, 0, int(x), int(y), int(w), int(h), flags)


def apply_layout(cfg=None) -> dict:
    """Enforce the layout on the LIVE windows. Safe to call repeatedly.

    This is the whole mechanism, not a belt-and-braces second pass: nothing
    else in the process sets the game window's style or position.
    """
    cfg = cfg or load_config()
    if not cfg.get("enabled", True):
        return {"skipped": "game_window.enabled is false"}
    res = {"game": None, "debugger": None}

    g = game_rect(cfg)
    for hwnd in _find_windows(GAME_CLASS):
        stripped = _set_borderless(hwnd) if cfg.get("borderless", True) else False
        # Size as well as position: stripping the caption changes the
        # non-client area, so a move-only call leaves the CLIENT area a
        # title-bar shorter than the configured height.
        _place(hwnd, g["x"], g["y"], g["w"], g["h"])
        res["game"] = {"hwnd": int(hwnd), "borderless_applied": stripped,
                       "rect": [g["x"], g["y"], g["w"], g["h"]]}

    # The debugger window KEEPS its frame -- it is a surface you still want to
    # drag, resize and close by hand. Only its position is pinned, so the
    # layout is reproducible without taking away control of it.
    d = debugger_rect(cfg, g)
    for hwnd in _find_windows(DEBUGGER_CLASS):
        _place(hwnd, d["x"], d["y"], d.get("w"), d.get("h"))
        res["debugger"] = {"hwnd": int(hwnd),
                           "rect": [d["x"], d["y"], d.get("w"), d.get("h")],
                           "frame": "kept"}
    return res


def _window_size(hwnd):
    r = wintypes.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(r))
    return r.right - r.left, r.bottom - r.top


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--show", action="store_true",
                    help="print the resolved config and rects without touching any window")
    args = ap.parse_args()
    cfg = load_config()
    print("config:", json.dumps(cfg))
    if args.show:
        g = game_rect(cfg)
        print("game    :", json.dumps(g))
        print("debugger:", json.dumps(debugger_rect(cfg, g)))
        return 0
    print("layout  :", json.dumps(apply_layout(cfg), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
