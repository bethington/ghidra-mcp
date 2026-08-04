# d2probe — Diablo II headless viability harness

Measures which parts of Diablo II's presentation stack survive an environment
with no interactive desktop and no audio hardware, i.e. whether the game can run
in a container or Session 0 service for unattended conformance proving.

Committed because it is the measurement harness behind a conclusion the project
now relies on, and it was previously living in `C:\tmp` — one disk cleanup from
gone, with no way to re-derive the finding except by rebuilding the experiment.

## The finding

Measured 2026-08-01:

- **Video survives.** The GDI render path (`StretchBlt` from an 8bpp palettized
  DIB) works in Session 0 and with no display attached.
- **Audio does not.** DirectSound fails with `DSERR_NODRIVER` when no audio
  device is present. That is the blocker, and the identified fix is a shim
  `dsound.dll` rather than anything in the game.

The raw evidence is kept alongside the scripts: `session0_result.txt`,
`nodevice_result.txt`, `noaudio_result.txt`, `baseline_session1.txt`. Each
records the context it ran in (session, window station, desktop) followed by the
per-subsystem results, so a later run can be compared against the same shape.

## Contents

| File | Purpose |
| --- | --- |
| `probe.cpp`, `build.bat` | The probe itself — exercises GDI, DirectDraw and DirectSound init and reports each outcome. Build artifacts (`probe.exe`, `probe.obj`) are deliberately not committed. |
| `session0.bat`, `run_session0.bat` | Run the probe as a Session 0 service, the case that matters for containers. |
| `nodevice_test.ps1`, `noaudio_svc.ps1` | Remove/disable the audio device and re-probe, isolating DirectSound from the rest. |
| `*_result.txt`, `*_done.txt` | Captured output from each configuration. |
| `mousemap.py`, `mousemap2.py`, `clipspace.py`, `winscale.py` | Coordinate-space checks — screen vs client vs clip space, and DPI scaling. Relevant because virtual input has to land in the right space when there is no real cursor. |
| `exports.bat`, `exp2.bat`, `disabled_endpoints.txt` | Export-surface scratch from the same investigation. |

## Caveat

This belongs to the D2 headless-container effort rather than to ghidra-mcp
proper. It is filed here because being in the wrong repository is strictly
better than being in no repository; move it if that effort gets its own home.
