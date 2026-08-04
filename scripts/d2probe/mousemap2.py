"""Reproduce the cursor-scaling mismatch and measure the ratio at each stage.

The pipeline has three independently readable stages:

    OS cursor (we set it)                          SetCursorPos
      -> panel RouteMouse output                   /input/state "screen"
         (RouteMouse stores the game coords it     (D2VInput_SetScreenPos is
          just routed)                              called only on route)
      -> what the game actually consumed           D2Client g_nMouseX/Y via
                                                   /asset/read module+rva

If stage2 == stage3 but both disagree with stage1, the panel's geometry math is
wrong. If stage2 is right and stage3 differs, the message path is wrong. The
SLOPE of stage3 vs stage1 is the ratio the operator feels.

Foregrounding: a plain SetForegroundWindow from a background process is refused
(measured last time -- the whole sweep read the game's idle 320,240). Attach to
the current foreground thread's input state first, which is the documented
workaround, and verify by reading GetForegroundWindow back rather than trusting
the call.
"""
import ctypes as C
import json
import struct
import time
import urllib.request

u = C.windll.user32
k = C.windll.kernel32
ORACLE = "http://127.0.0.1:8790"


class POINT(C.Structure):
    _fields_ = [("x", C.c_long), ("y", C.c_long)]


def get(p):
    with urllib.request.urlopen(ORACLE + p, timeout=6) as r:
        return json.loads(r.read())


def post(p, b):
    rq = urllib.request.Request(ORACLE + p, json.dumps(b).encode(),
                                {"Content-Type": "application/json"})
    with urllib.request.urlopen(rq, timeout=6) as r:
        return json.loads(r.read())


def routed():
    """Stage 2: the game coords RouteMouse last produced."""
    s = get("/input/state")["screen"]
    return s[0], s[1]


def game_mouse():
    """Stage 3: D2Client's own view."""
    r = post("/asset/read", {"module": "D2Client.dll", "rva": 0x11b824, "len": 8})
    b = bytes.fromhex(r["hex"])
    y, x = struct.unpack("<ii", b)
    return x, y


def force_foreground(hwnd):
    fg = u.GetForegroundWindow()
    if fg == hwnd:
        return True
    cur = k.GetCurrentThreadId()
    fg_tid = u.GetWindowThreadProcessId(fg, None) if fg else 0
    if fg_tid:
        u.AttachThreadInput(cur, fg_tid, True)
    u.BringWindowToTop(C.c_void_p(hwnd))
    u.SetForegroundWindow(C.c_void_p(hwnd))
    if fg_tid:
        u.AttachThreadInput(cur, fg_tid, False)
    time.sleep(0.3)
    return u.GetForegroundWindow() == hwnd


u.FindWindowW.restype = C.c_void_p
u.GetForegroundWindow.restype = C.c_void_p
h = u.FindWindowW(None, "D2Debugger")
if not h:
    raise SystemExit("D2Debugger window not found")
ok = force_foreground(h)
print("foreground:", "OK" if ok else "FAILED (results may be static)")

g = get("/input/geometry")
img, drawn, tex, cl = g["img"], g["drawn"], g["tex"], g["client"]
print("geometry: img=%s drawn=%s tex=%s client=%s dpi=%s" % (img, drawn, tex, cl, g["dpi"]))

saved = POINT()
u.GetCursorPos(C.byref(saved))

# ---- 1. find the image's vertical band in CURSOR space ---------------------
# Scan down a column and note where RouteMouse starts/stops producing output.
probe_x = 1100
band = []
try:
    for y in range(200, 1440, 40):
        u.SetCursorPos(probe_x, y)
        time.sleep(0.12)
        r1 = routed()
        u.SetCursorPos(probe_x, y + 20)
        time.sleep(0.12)
        r2 = routed()
        if r1 != r2:                     # routing responded to a 20px nudge
            band.append(y)
    if not band:
        print("no y produced routing output at x=%d -- image not under this column?" % probe_x)
    else:
        print("image responds for cursor y in ~[%d..%d]" % (band[0], band[-1] + 20))

    # ---- 2. horizontal sweep at mid-band -----------------------------------
    ymid = (band[0] + band[-1]) // 2 if band else 1000
    rows = []
    print()
    print("%-10s %-16s %-16s" % ("OS x", "routed (panel)", "game (D2Client)"))
    for x in range(560, 1560, 80):
        u.SetCursorPos(x, ymid)
        time.sleep(0.16)
        r = routed()
        gm = game_mouse()
        rows.append((x, r, gm))
        print("  %-8d (%4d,%4d)      (%4d,%4d)" % (x, r[0], r[1], gm[0], gm[1]))

    # ---- 3. fit the slopes --------------------------------------------------
    pts = [(x, r[0], gm[0]) for (x, r, gm) in rows]
    # keep only where routing responded (inside the image)
    resp = [p for i, p in enumerate(pts)
            if i > 0 and p[1] != pts[i - 1][1]]
    if len(resp) >= 3:
        xs = [p[0] for p in resp]
        rs = [p[1] for p in resp]
        gs = [p[2] for p in resp]
        n = len(resp)
        def slope(a, b):
            ma = sum(a) / n; mb = sum(b) / n
            num = sum((a[i] - ma) * (b[i] - mb) for i in range(n))
            den = sum((a[i] - ma) ** 2 for i in range(n))
            return num / den if den else float("nan")
        s_panel = slope(xs, rs)
        s_game = slope(xs, gs)
        print()
        print("SLOPES (game px per OS-cursor px):")
        print("  panel-routed vs OS : %.4f" % s_panel)
        print("  game-consumed vs OS: %.4f" % s_game)
        print("  panel vs game agree: %s" % ("YES" if abs(s_panel - s_game) < 0.02 else "NO"))
        print()
        print("interpretation: 1.000 = correct;")
        print("  1.25 = image occupies 1/1.25 of assumed width (fix under-applied)")
        print("  0.80 = fix over-applied / double-applied")
    else:
        print("too few in-image samples to fit a slope")
finally:
    u.SetCursorPos(saved.x, saved.y)
    print("\n(cursor restored)")
