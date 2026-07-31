"""ScyllaHide ensure-injection -- make the anti-anti-debug hook a property of
ATTACHING, not of which launcher happened to start the game.

WHY THIS MODULE EXISTS
----------------------
PD2's `Game.exe` defends itself with API-based anti-debug (`IsDebuggerPresent`,
`NtQueryInformationProcess`, `ThreadHideFromDebugger`, code-checksum breakpoint
detection). ScyllaHide neutralises those so software breakpoints actually STICK
-- and `call_function` depends on a return-catch breakpoint, so without it the
debugger is quietly unreliable rather than obviously broken.

Until now exactly ONE launcher injected it (`start-oracle.ps1`), and that is not
the launcher the conformance work uses. Every oracle-side path -- and the
watchdog's own unattended recovery (`oracle_health` -> `LaunchPD2-Oracle.bat`) --
started the game without it. Measured 2026-07-30: not injected in the live
process, last injection logged three weeks earlier.

Injection is POST-LAUNCH by design (`InjectorCLI pid:<pid>`), so it composes with
every launcher instead of having to be added to each one. Attaching is the moment
we actually need the hook, so that is where we ensure it.

CONTRACT
--------
`ensure()` never raises and never fails an attach. A debugger that refuses to
attach because a hardening step failed is worse than one that attaches and says
so -- but it must SAY so, loudly (see feedback_loud_failures): a silent absence
is precisely what makes "my breakpoints don't stick" cost an afternoon.

Config (env):
    SCYLLAHIDE_DIR          directory holding InjectorCLIx86.exe + HookLibraryx86.dll
                            (default: <repo>/tools/scyllahide)
    SCYLLAHIDE_AUTO_INJECT  "0" to detect-and-warn only, never inject
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = _REPO_ROOT / "tools" / "scyllahide"

# The injected hook library, by target architecture. Presence of one of these in
# the target's module list is the ONLY reliable "is it hooked?" signal -- the
# injector's own exit code says nothing about whether the DLL survived.
HOOK_MODULES = {"x86": "HookLibraryx86.dll", "x64": "HookLibraryx64.dll"}
INJECTORS = {"x86": "InjectorCLIx86.exe", "x64": "InjectorCLIx64.exe"}

# Statuses ensure() can return. Only "present" and "injected" mean the target is
# actually hardened; everything else must surface a warning to the caller.
OK_STATUSES = ("present", "injected")


def scyllahide_dir() -> Path:
    return Path(os.environ.get("SCYLLAHIDE_DIR") or DEFAULT_DIR)


def auto_inject_enabled() -> bool:
    return os.environ.get("SCYLLAHIDE_AUTO_INJECT", "1") != "0"


def hook_module_name(arch: str = "x86") -> str:
    return HOOK_MODULES.get(arch, HOOK_MODULES["x86"])


def is_injected(module_names, arch: str = "x86") -> bool:
    """True when the hook library is already in the target's module list.

    Case-insensitive and basename-only: dbgeng reports module names in several
    spellings (bare name, full path, no extension) depending on how the module
    was loaded.
    """
    want = hook_module_name(arch).lower()
    want_stem = want.rsplit(".", 1)[0]
    for raw in module_names or ():
        name = str(raw).replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name == want or name.rsplit(".", 1)[0] == want_stem:
            return True
    return False


def tool_paths(arch: str = "x86", directory=None):
    """(injector, hook_library) as Paths, or (None, None) when either is absent.

    The binaries are third-party and gitignored, so "not installed" is an
    expected state, not a bug -- callers degrade to a warning.
    """
    d = Path(directory) if directory else scyllahide_dir()
    inj = d / INJECTORS.get(arch, INJECTORS["x86"])
    hook = d / HOOK_MODULES.get(arch, HOOK_MODULES["x86"])
    if inj.exists() and hook.exists():
        return inj, hook
    return None, None


def inject(pid: int, arch: str = "x86", directory=None, timeout: float = 30.0) -> dict:
    """Run InjectorCLI against a live PID. Returns {ok, detail}; never raises.

    cwd is the ScyllaHide directory so InjectorCLI picks up `scylla_hide.ini`
    (its settings come from the ini next to it, not from argv), and stdin is fed
    a newline because the injector ends with a "press any key" that would
    otherwise hang the caller forever.
    """
    inj, hook = tool_paths(arch, directory)
    if not inj:
        d = Path(directory) if directory else scyllahide_dir()
        return {"ok": False, "detail": (
            f"ScyllaHide binaries not found in {d} (need {INJECTORS.get(arch)} + "
            f"{HOOK_MODULES.get(arch)}). They are third-party and gitignored -- see "
            f"tools/scyllahide/README.md, or set SCYLLAHIDE_DIR.")}
    try:
        proc = subprocess.run(
            [str(inj), f"pid:{pid}", str(hook)],
            cwd=str(inj.parent), input="\n", capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": f"InjectorCLI timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "detail": f"InjectorCLI could not be started: {exc}"}
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    # Exit code alone is not trustworthy here; the caller re-checks the module
    # list, which is the only real proof the library is loaded.
    return {"ok": proc.returncode == 0, "detail": out[-400:] or f"exit {proc.returncode}"}


def ensure(pid, module_names, *, arch: str = "x86", directory=None,
           refresh_modules=None) -> dict:
    """Make sure the target is hardened. Returns a status dict; never raises.

    status:
      present      already injected -- nothing to do
      injected     we injected it, and re-verified it in the module list
      unverified   the injector reported success but the hook is NOT in the
                   module list. Treated as NOT hardened, deliberately: the whole
                   point is that breakpoints silently fail, so an unconfirmed
                   injection must not read as success.
      unavailable  binaries not installed
      failed       injector ran and failed
      disabled     SCYLLAHIDE_AUTO_INJECT=0 and it was not already present
      skipped      no pid to work with

    `refresh_modules` is an optional zero-arg callable returning a fresh module
    name list, used to verify after injecting.
    """
    hook = hook_module_name(arch)
    if is_injected(module_names, arch):
        return {"status": "present", "hook": hook,
                "detail": f"{hook} already loaded in the target"}
    if not pid:
        return {"status": "skipped", "hook": hook, "detail": "no target pid"}
    if not auto_inject_enabled():
        return {"status": "disabled", "hook": hook,
                "detail": "SCYLLAHIDE_AUTO_INJECT=0 and the hook is not loaded"}

    inj, _ = tool_paths(arch, directory)
    if not inj:
        d = Path(directory) if directory else scyllahide_dir()
        return {"status": "unavailable", "hook": hook,
                "detail": f"ScyllaHide binaries not found in {d}"}

    logger.info("ScyllaHide: injecting %s into PID %s", hook, pid)
    res = inject(pid, arch, directory)
    fresh = None
    if refresh_modules is not None:
        try:
            fresh = refresh_modules()
        except Exception as exc:  # noqa: BLE001 -- verification must not break attach
            logger.warning("ScyllaHide: module re-check failed: %s", exc)
    if fresh is not None and is_injected(fresh, arch):
        return {"status": "injected", "hook": hook,
                "detail": f"injected {hook} into PID {pid}"}
    if res["ok"] and fresh is None:
        # Could not verify (no refresh hook supplied). Report the injector's own
        # view rather than claiming more than we checked.
        return {"status": "injected", "hook": hook,
                "detail": f"injector reported success for PID {pid} (unverified)"}
    if res["ok"]:
        return {"status": "unverified", "hook": hook,
                "detail": (f"injector reported success but {hook} is not in the target's "
                           f"module list -- treat breakpoints as unreliable. {res['detail']}")}
    return {"status": "failed", "hook": hook, "detail": res["detail"]}


def warning_for(status: dict):
    """A single operator-facing sentence when the target is NOT hardened, else None.

    Names the consequence, not just the condition: "breakpoints may silently fail"
    is what the reader needs, because that is the symptom they will actually hit.
    """
    if not status or status.get("status") in OK_STATUSES:
        return None
    return (
        f"ScyllaHide is NOT active in this target ({status.get('status')}: "
        f"{status.get('detail')}). PD2's anti-debug can strip or detect software "
        f"breakpoints, so breakpoints (and call_function's return-catch) may "
        f"silently fail. Fix: install/inject ScyllaHide (tools/scyllahide/README.md) "
        f"and re-attach, or run start-oracle.ps1."
    )
