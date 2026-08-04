"""Measure the OS-cursor -> in-game-cursor mapping, empirically.

The panel converts a hover position into game coordinates as a FRACTION of the
drawn image:  (io.MousePos - imgPos) / drawn * texSize. That is DPI-proof only
if all three terms share a coordinate space. The suspicion is that they do not:
ImGui's Win32 backend feeds io.MousePos from GetCursorPos (LOGICAL, because the
process is DPI-virtualised) while imgPos/drawn are ImGui layout values, and
ImGui's viewport here is 2560x1440 -- PHYSICAL.

So: park the OS cursor at known points over the image and read what the game
actually believes its mouse position is, straight out of D2Client's own
globals. Fit the relationship. If the slope comes out at ~1.0 the theory is
wrong; if it comes out near 1.25 (or 0.8) the mismatch is exactly the DPI ratio
and the fix is a single conversion where the rect and the position leave ImGui
space.

D2Client mouse globals: absolute 0x6fbcb828 (X) / 0x6fbcb824 (Y) against the
module's 0x6fab0000 preferred base -> rva 0x11b828 / 0x11b824. Read via the
oracle so the live base is resolved for us (D2Client does NOT load at its
preferred base -- see the module+rva rule).
"""
import ctypes as C
import json
import struct
import time
import urllib.request

ORACLE = "http://127.0.0.1:8790"
u = C.windll.user32


class POINT(C.Structure):
    _fields_ = [("x", C.c_long), ("y", C.c_long)]


def get(path):
    with urllib.request.urlopen(ORACLE + path, timeout=6) as r:
        return json.loads(r.read())


def post(path, body):
    req = urllib.request.Request(ORACLE + path, json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=6) as r:
        return json.loads(r.read())


def game_mouse():
    """(x, y) as D2Client itself believes them."""
    r = post("/asset/read", {"module": "D2Client.dll", "rva": 0x11b824, "len": 8})
    b = bytes.fromhex(r["hex"])
    y, x = struct.unpack("<ii", b)      # 0x824 = Y, 0x828 = X
    return x, y


g = get("/input/geometry")
img, drawn, tex = g["img"], g["drawn"], g["tex"]
print("panel (ImGui space): img=(%d,%d) drawn=%dx%d tex=%dx%d"
      % (img[0], img[1], drawn[0], drawn[1], tex[0], tex[1]))
print("host client (Win32/logical): %dx%d" % tuple(g["client"]))
print()

saved = POINT()
u.GetCursorPos(C.byref(saved))

# Sample along the image in ImGui space, then ALSO at the same numbers treated
# as logical, and see which one the game agrees with.
fracs = [0.25, 0.50, 0.75]
print("%-28s %-18s %-18s" % ("OS cursor (logical)", "game says", "expected(ImGui frac)"))
try:
    for f in fracs:
        # Target expressed as a fraction of the drawn image, in ImGui space.
        tx = img[0] + drawn[0] * f
        ty = img[1] + drawn[1] * 0.5
        # Place the OS cursor at those raw numbers (i.e. treat them as logical).
        u.SetCursorPos(int(tx), int(ty))
        time.sleep(0.12)
        gx, gy = game_mouse()
        exp_x = int(tex[0] * f)
        print("  (%4d,%4d)               (%4d,%4d)        (%4d, ~%d)"
              % (int(tx), int(ty), gx, gy, exp_x, tex[1] // 2))
finally:
    u.SetCursorPos(saved.x, saved.y)
    print("\n(cursor restored to %d,%d)" % (saved.x, saved.y))
