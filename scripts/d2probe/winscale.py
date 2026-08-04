"""Is the game window 1:1 with its render source, and is that stable?

The proposed fix rests on deriving the cursor scale from the GAME window rather
than the host. That premise needs two things to hold:

  1. the game window's client size tracks the render source (1068x600 in-world,
     800x600 at the menu), and
  2. it stays that way across a relaunch.

Measured from a per-monitor-DPI-aware process, because the game window is
DPI-UNAWARE (GetDpiForWindow 96) while the host is aware (120) -- an unaware
observer would report the virtualised numbers and hide exactly the discrepancy
being looked for.
"""
import ctypes as C
import json
import sys
import urllib.request

u = C.windll.user32
u.SetProcessDpiAwarenessContext(C.c_void_p(-4))     # BEFORE any window query
u.FindWindowW.restype = C.c_void_p


class RECT(C.Structure):
    _fields_ = [("l", C.c_long), ("t", C.c_long), ("r", C.c_long), ("b", C.c_long)]


def win(title):
    h = u.FindWindowW(None, title)
    if not h:
        return None
    h = C.c_void_p(h)
    wr, cr = RECT(), RECT()
    u.GetWindowRect(h, C.byref(wr))
    u.GetClientRect(h, C.byref(cr))
    return {
        "pos": (wr.l, wr.t),
        "win": (wr.r - wr.l, wr.b - wr.t),
        "client": (cr.r, cr.b),
        "dpi": u.GetDpiForWindow(h),
    }


def get(p):
    with urllib.request.urlopen("http://127.0.0.1:8790" + p, timeout=6) as r:
        return json.loads(r.read())


label = sys.argv[1] if len(sys.argv) > 1 else "sample"
print("===", label, "===")

g = win("Diablo II")
d = win("D2Debugger")

try:
    geo = get("/input/geometry")
    tex = tuple(geo["tex"])
    panel_client = tuple(geo["client"])
    panel_dpi = geo["dpi"]
except Exception as e:
    tex = panel_client = None
    panel_dpi = "?"
    print("  (/input/geometry unavailable: %s)" % e)

if g:
    print("  GAME   client %dx%d  win %dx%d at %s  dpi=%d"
          % (g["client"][0], g["client"][1], g["win"][0], g["win"][1], g["pos"], g["dpi"]))
else:
    print("  GAME   window not found")

if d:
    print("  HOST   client %dx%d  dpi=%d" % (d["client"][0], d["client"][1], d["dpi"]))

if tex:
    print("  RENDER source (tex) %dx%d" % tex)
    print("  panel sees host client %dx%d dpi=%s" % (panel_client[0], panel_client[1], panel_dpi))

if g and tex and tex[0]:
    rx = g["client"][0] / tex[0]
    ry = g["client"][1] / tex[1]
    print()
    print("  GAME-client / RENDER-source = %.4f x %.4f" % (rx, ry))
    verdict = "1:1 (no compensation needed)" if abs(rx - 1.0) < 0.02 else \
              "SCALED by %.3f (compensation needed)" % rx
    print("  ->", verdict)

# What the panel's own scale factor would be, from the numbers it uses.
if d and panel_client:
    s_host = d["client"][1] / panel_client[1] if panel_client[1] else float("nan")
    print()
    print("  panel S (host physical / host logical) = %.4f" % s_host)
    print("  (this is what ImGuiToCursorScale computes)")
