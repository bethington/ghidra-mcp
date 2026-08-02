"""Which coordinate space does ClipCursor actually use on this machine?

Three theories about this have now been argued and refuted in a row, each
costing a rebuild and a broken game session. So stop theorising: apply a KNOWN
rectangle, then probe the effective bounds by shoving the cursor at the extremes
and reading where it lands. Whatever comes back is the answer, in the same units
the caller used.

Run once DPI-unaware (which is what the game process is) and once per-monitor
aware. If the two disagree, ClipCursor is virtualised and the difference is the
factor; if they agree, it is not, and the panel's rect is simply wrong.

Restores both the clip and the original cursor position.
"""
import ctypes as C
import sys
import time

u = C.windll.user32


class POINT(C.Structure):
    _fields_ = [("x", C.c_long), ("y", C.c_long)]


class RECT(C.Structure):
    _fields_ = [("l", C.c_long), ("t", C.c_long), ("r", C.c_long), ("b", C.c_long)]


AWARE = "--aware" in sys.argv
if AWARE:
    # PER_MONITOR_AWARE_V2, before any window/cursor call.
    u.SetProcessDpiAwarenessContext(C.c_void_p(-4))

print("== %s ==" % ("DPI-AWARE" if AWARE else "DPI-UNAWARE (like the game)"))
print("   IsProcessDPIAware:", u.IsProcessDPIAware())


def pos():
    p = POINT()
    u.GetCursorPos(C.byref(p))
    return p.x, p.y


def probe_bounds():
    """Find the effective clip by pushing the cursor at each extreme."""
    u.SetCursorPos(-100000, -100000)
    time.sleep(0.02)
    lo = pos()
    u.SetCursorPos(100000, 100000)
    time.sleep(0.02)
    hi = pos()
    return lo, hi


saved = pos()
try:
    # Unconfined baseline: the desktop as this process sees it.
    u.ClipCursor(None)
    lo, hi = probe_bounds()
    print("   desktop bounds seen : (%d,%d)..(%d,%d)  = %dx%d"
          % (lo[0], lo[1], hi[0], hi[1], hi[0] - lo[0] + 1, hi[1] - lo[1] + 1))

    # A known rectangle, well inside the primary monitor.
    want = RECT(400, 400, 900, 700)          # 500 x 300
    ok = u.ClipCursor(C.byref(want))
    got = RECT()
    u.GetClipCursor(C.byref(got))
    lo, hi = probe_bounds()
    print("   requested clip      : (400,400)..(900,700)  = 500x300  [ok=%s]" % bool(ok))
    print("   GetClipCursor says  : (%d,%d)..(%d,%d)  = %dx%d"
          % (got.l, got.t, got.r, got.b, got.r - got.l, got.b - got.t))
    print("   cursor actually hits: (%d,%d)..(%d,%d)  = %dx%d"
          % (lo[0], lo[1], hi[0], hi[1], hi[0] - lo[0] + 1, hi[1] - lo[1] + 1))
    sx = (hi[0] - lo[0] + 1) / 500.0
    sy = (hi[1] - lo[1] + 1) / 300.0
    print("   effective/requested : %.3f x %.3f" % (sx, sy))
    print("   origin shift        : %+d, %+d" % (lo[0] - 400, lo[1] - 400))
finally:
    u.ClipCursor(None)
    u.SetCursorPos(saved[0], saved[1])
    print("   (clip released, cursor restored to %d,%d)" % saved)
