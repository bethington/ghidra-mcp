"""Debugger proxy tools — forward to the standalone debugger server.

Each tool proxies an HTTP request to ``debugger/server.py`` on
``GHIDRA_DEBUGGER_URL`` (see :data:`bridge_mcp_ghidra.config.DEBUGGER_URL`).
"""

import http.client
import json
import os
import sys
from urllib.parse import urlencode, urlparse

from . import config
from . import dispatch
from . import state
from .config import DEBUGGER_URL, DEBUGGER_TOOL_NAMES, logger
from .server import mcp

# Hosts for which a debugger server is local to this machine. On a non-Windows
# host a local debugger server can never run (dbgeng/WinDbg is Windows-only), so
# debugger proxy tools pointing at one of these are not registered.
_LOCAL_DEBUGGER_HOSTS = {"", "127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _debugger_enabled(
    url: str = DEBUGGER_URL,
    platform: str = sys.platform,
    override: str | None = None,
) -> bool:
    """Whether to register the WinDbg debugger proxy tools on this host.

    The standalone debugger server (debugger/server.py) wraps dbgeng/WinDbg via
    pybag and only runs on Windows. Registering ~22 proxy tools that can never
    work just clutters the tool list, so registration is gated:

      - GHIDRA_DEBUGGER_TOOLS=1/0 (or true/false/yes/no/on/off) forces on/off.
      - On Windows the server can run locally -> enabled.
      - On non-Windows a *local* DEBUGGER_URL can never be served -> disabled;
        a *remote* host (a Windows box running the server) -> enabled.

    The tool *functions* are always defined regardless; only their MCP
    registration is gated. Call-time failures (server down) are handled
    separately by _debugger_request().
    """
    if override is None:
        override = os.getenv("GHIDRA_DEBUGGER_TOOLS")
    if override is not None and override.strip():
        return override.strip().lower() in {"1", "true", "yes", "on"}
    if platform.startswith("win"):
        return True
    host = (urlparse(url).hostname or "").lower()
    return host not in _LOCAL_DEBUGGER_HOSTS


_DEBUGGER_ACTIVE = _debugger_enabled()
if _DEBUGGER_ACTIVE:
    config.STATIC_TOOL_NAMES |= DEBUGGER_TOOL_NAMES


def _debugger_tool(*dargs, **dkwargs):
    """Decorator: register a debugger proxy tool only when the backend is usable.

    When the debugger is inactive on this host the decorated function is left
    untouched (still importable / directly callable / unit-testable) but is not
    exposed as an MCP tool, keeping the tool list uncluttered on non-Windows.
    """
    if _DEBUGGER_ACTIVE:
        return mcp.tool(*dargs, **dkwargs)

    def _skip(fn):
        return fn

    return _skip


def _debugger_request(
    method: str,
    path: str,
    body: dict | None = None,
    query: dict | None = None,
    timeout: int = 30,
) -> str:
    """Send a request to the debugger server. Returns JSON string."""
    parsed = urlparse(DEBUGGER_URL)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        url = path
        if query:
            url += "?" + urlencode(query)
        headers = {"Content-Type": "application/json"} if body else {}
        conn.request(
            method, url, body=json.dumps(body) if body else None, headers=headers
        )
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        if resp.status >= 400:
            try:
                err = json.loads(data)
                return json.dumps({"error": err.get("error", data)})
            except Exception:
                return json.dumps({"error": data})
        return data
    except ConnectionRefusedError:
        return json.dumps(
            {
                "error": f"Debugger server not running at {DEBUGGER_URL}. "
                "Start it with: uv run python -m debugger (or: python -m debugger)"
            }
        )
    except Exception as e:
        return json.dumps({"error": f"Debugger request failed: {e}"})
    finally:
        conn.close()


@_debugger_tool()
def debugger_attach(target: str) -> str:
    """Attach the debugger to a running process for live dynamic analysis.

    Connects to the target process via dbgeng (WinDbg engine). After attaching,
    use debugger_modules() to see loaded DLLs and debugger_set_breakpoint() to
    set breakpoints.

    Args:
        target: Process name (e.g. "Game.exe") or PID.
    """
    result = _debugger_request("POST", "/debugger/attach", {"target": target})

    # Auto-sync address map if Ghidra is connected
    if state._transport_mode != "none":
        try:
            # Fetch image bases from Ghidra for all open programs
            programs_text = dispatch.dispatch_get("/list_open_programs")
            if programs_text:
                programs_data = json.loads(programs_text)
                programs = (
                    programs_data
                    if isinstance(programs_data, list)
                    else programs_data.get("programs", [])
                )
                # image_base is already present on each /list_open_programs
                # entry (ProgramScriptService.listOpenPrograms emits it) —
                # use it directly. The previous /get_metadata round-trip
                # was dead: that endpoint returns plain text, so
                # json.loads() always raised, the bare except swallowed
                # it, and ghidra_bases stayed empty so auto-sync never
                # fired.
                ghidra_bases = {}
                for prog in programs:
                    if isinstance(prog, str):
                        # Legacy plain-string list shape — no image_base
                        # available without a second call. Skip; the
                        # operator can run debugger_resolve_ordinal /
                        # sync manually.
                        continue
                    prog_path = prog.get("path") or prog.get("name") or ""
                    image_base = prog.get("image_base") or prog.get("imageBase")
                    if prog_path and image_base:
                        ghidra_bases[prog_path] = image_base
                if ghidra_bases:
                    _debugger_request(
                        "POST", "/debugger/sync_modules", {"ghidra_bases": ghidra_bases}
                    )
                    logger.info(
                        "debugger_attach: auto-synced %d Ghidra image base(s) "
                        "to the debugger address map",
                        len(ghidra_bases),
                    )
                else:
                    logger.info(
                        "debugger_attach: no Ghidra image bases available "
                        "from /list_open_programs — address-map auto-sync "
                        "skipped (set up manually via debugger_resolve_ordinal "
                        "or /debugger/sync_modules)"
                    )
        except Exception as e:
            logger.warning(f"Auto-sync address map failed (non-fatal): {e}")

    return result


@_debugger_tool()
def debugger_detach() -> str:
    """Detach from the debugged process. The process continues running."""
    return _debugger_request("POST", "/debugger/detach")


@_debugger_tool()
def debugger_status() -> str:
    """Get debugger connection status, loaded modules, active traces/watches."""
    return _debugger_request("GET", "/debugger/status")


@_debugger_tool()
def debugger_modules() -> str:
    """List loaded modules (DLLs) with runtime and Ghidra base addresses.

    Shows each module's name, runtime base, Ghidra base (if mapped),
    and the address offset between them.
    """
    return _debugger_request("GET", "/debugger/modules")


@_debugger_tool()
def debugger_resolve_ordinal(dll: str, ordinal: int) -> str:
    """Resolve a DLL ordinal export to its runtime and Ghidra addresses.

    Uses the ordinal export tables from dll_exports/*.txt combined with
    the current runtime address map.

    Args:
        dll: DLL name (e.g. "D2Common.dll").
        ordinal: Ordinal number (e.g. 10624).
    """
    return _debugger_request(
        "GET", "/debugger/ordinal", query={"dll": dll, "ordinal": str(ordinal)}
    )


@_debugger_tool()
def debugger_set_breakpoint(
    ghidra_address: str,
    module: str = "",
    bp_type: str = "software",
    oneshot: bool = False,
) -> str:
    """Set a breakpoint at a Ghidra address. Auto-translates to runtime address.

    Args:
        ghidra_address: Address in Ghidra (e.g. "0x6FD9F450").
        module: DLL name for disambiguation (e.g. "D2Common.dll").
        bp_type: "software" (INT3) or "hardware" (debug register).
        oneshot: If true, breakpoint is removed after first hit.
    """
    return _debugger_request(
        "POST",
        "/debugger/breakpoint",
        {
            "ghidra_address": ghidra_address,
            "module": module,
            "type": bp_type,
            "oneshot": oneshot,
        },
    )


@_debugger_tool()
def debugger_remove_breakpoint(bp_id: int) -> str:
    """Remove a breakpoint by its ID.

    Args:
        bp_id: Breakpoint ID returned by debugger_set_breakpoint.
    """
    return _debugger_request("DELETE", f"/debugger/breakpoint/{bp_id}")


@_debugger_tool()
def debugger_list_breakpoints() -> str:
    """List all active breakpoints with their addresses and status."""
    return _debugger_request("GET", "/debugger/breakpoints")


@_debugger_tool()
def debugger_continue() -> str:
    """Resume execution of the debugged process.

    Returns immediately. The process runs until a breakpoint is hit,
    an exception occurs, or debugger_interrupt() is called.
    """
    return _debugger_request("POST", "/debugger/go")


@_debugger_tool()
def debugger_step_into(count: int = 1) -> str:
    """Single-step into the next instruction(s). Follows calls.

    Args:
        count: Number of instructions to step (default 1).
    """
    return _debugger_request("POST", "/debugger/step_into", {"count": count})


@_debugger_tool()
def debugger_step_over(count: int = 1) -> str:
    """Step over the next instruction(s). Steps over calls.

    Args:
        count: Number of instructions to step (default 1).
    """
    return _debugger_request("POST", "/debugger/step_over", {"count": count})


@_debugger_tool()
def debugger_registers() -> str:
    """Read all CPU registers. Must be stopped at a breakpoint.

    Returns EAX-EDI, ESP, EBP, EIP, EFLAGS for x86.
    """
    return _debugger_request("GET", "/debugger/registers")


@_debugger_tool()
def debugger_read_memory(
    address: str, size: int = 64, address_type: str = "runtime", module: str = ""
) -> str:
    """Read memory from the debugged process.

    Returns hex dump and 32-bit DWORD interpretation of the memory region.

    Args:
        address: Memory address (hex, e.g. "0x6FD9F450").
        size: Number of bytes to read (max 4096).
        address_type: "runtime" for live address, "ghidra" to auto-translate.
        module: DLL name when address_type="ghidra" for disambiguation.
    """
    return _debugger_request(
        "GET",
        "/debugger/memory",
        query={
            "address": address,
            "size": str(size),
            "address_type": address_type,
            "module": module,
        },
    )


@_debugger_tool()
def debugger_stack_trace(depth: int = 20) -> str:
    """Get the call stack backtrace with return addresses mapped to Ghidra symbols.

    Args:
        depth: Maximum number of stack frames (default 20).
    """
    return _debugger_request("GET", "/debugger/stack", query={"depth": str(depth)})


@_debugger_tool()
def debugger_read_args(
    convention: str = "__stdcall", count: int = 4, arg_names: str = ""
) -> str:
    """Read function arguments at the current breakpoint based on calling convention.

    Reads arguments from registers and stack according to the calling convention.
    Must be stopped at a function entry point.

    Args:
        convention: __stdcall, __fastcall, __thiscall, or __cdecl.
        count: Number of arguments to read.
        arg_names: Comma-separated names for readability (e.g. "pUnit,nSkillId").
    """
    return _debugger_request(
        "GET",
        "/debugger/read_args",
        query={"convention": convention, "count": str(count), "arg_names": arg_names},
    )


@_debugger_tool()
def debugger_trace_function(
    ghidra_address: str,
    module: str = "",
    convention: str = "__stdcall",
    arg_count: int = 4,
    arg_names: str = "",
    capture_return: bool = False,
    max_hits: int = 0,
) -> str:
    """Start non-breaking tracing on a function. Logs every call with arguments
    WITHOUT stopping the game.

    The handler reads arguments and auto-resumes execution in ~0.5ms,
    invisible at the game's 25fps. Use debugger_trace_log() to read results.

    Args:
        ghidra_address: Function address in Ghidra.
        module: DLL name (e.g. "D2Common.dll").
        convention: __stdcall, __fastcall, __thiscall, __cdecl.
        arg_count: Number of arguments to capture.
        arg_names: Comma-separated arg names (e.g. "pUnit,nSkillId,nWeaponSpeed").
        capture_return: Also capture return value (EAX).
        max_hits: Stop tracing after N hits (0 = unlimited).
    """
    return _debugger_request(
        "POST",
        "/debugger/trace/start",
        {
            "ghidra_address": ghidra_address,
            "module": module,
            "convention": convention,
            "arg_count": arg_count,
            "arg_names": arg_names,
            "capture_return": capture_return,
            "max_hits": max_hits,
        },
    )


@_debugger_tool()
def debugger_trace_stop(trace_id: int = -1) -> str:
    """Stop a function trace. Use trace_id=-1 to stop all traces.

    Args:
        trace_id: ID returned by debugger_trace_function, or -1 for all.
    """
    return _debugger_request("POST", "/debugger/trace/stop", {"trace_id": trace_id})


@_debugger_tool()
def debugger_trace_log(trace_id: int = -1, last_n: int = 50) -> str:
    """Read the trace log. Shows timestamped function calls with arguments.

    Args:
        trace_id: Filter by trace ID, or -1 for all traces.
        last_n: Number of most recent entries to return.
    """
    return _debugger_request(
        "GET",
        "/debugger/trace/log",
        query={"trace_id": str(trace_id), "last_n": str(last_n)},
    )


@_debugger_tool()
def debugger_trace_list() -> str:
    """List all active and completed traces with hit counts."""
    return _debugger_request("GET", "/debugger/trace/list")


@_debugger_tool()
def debugger_watch_memory(
    ghidra_address: str, size: int = 4, access: str = "write", module: str = ""
) -> str:
    """Set a hardware watchpoint on a memory range to monitor read/write access.

    Limited to 4 simultaneous watchpoints (x86 debug register limit).
    Use debugger_watch_log() to see hits.

    Args:
        ghidra_address: Start address in Ghidra.
        size: Bytes to watch (1, 2, or 4).
        access: "read", "write", or "readwrite".
        module: DLL name for address resolution.
    """
    return _debugger_request(
        "POST",
        "/debugger/watch/start",
        {
            "ghidra_address": ghidra_address,
            "module": module,
            "size": size,
            "access": access,
        },
    )


@_debugger_tool()
def debugger_watch_stop(watch_id: int = -1) -> str:
    """Stop a memory watchpoint. Use watch_id=-1 to stop all.

    Args:
        watch_id: ID returned by debugger_watch_memory, or -1 for all.
    """
    return _debugger_request("POST", "/debugger/watch/stop", {"watch_id": watch_id})


@_debugger_tool()
def debugger_watch_log(watch_id: int = -1, last_n: int = 50) -> str:
    """Read the watchpoint hit log. Shows memory accesses with values and accessors.

    Args:
        watch_id: Filter by watch ID, or -1 for all.
        last_n: Number of most recent entries.
    """
    return _debugger_request(
        "GET",
        "/debugger/watch/log",
        query={"watch_id": str(watch_id), "last_n": str(last_n)},
    )
