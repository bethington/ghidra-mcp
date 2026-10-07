"""Debugger proxy tools — forward to an external debugger server.

Each tool proxies an HTTP request to an external dbgeng (WinDbg engine)
debugger server — not part of this repo — on ``GHIDRA_DEBUGGER_URL`` (see
:data:`bridge_mcp_ghidra.config.DEBUGGER_URL`).

The tools are OFF BY DEFAULT: they register only when ``GHIDRA_DEBUGGER_URL``
is explicitly set or ``GHIDRA_DEBUGGER_TOOLS`` is truthy. See
:func:`_debugger_enabled`.
"""

import http.client
import inspect
import json
import os
from urllib.parse import urlencode, urlparse

from . import config
from . import dispatch
from . import state
from .config import (
    DEBUGGER_URL,
    DEBUGGER_URL_EXPLICIT,
    DEBUGGER_TOOL_NAMES,
    DESTRUCTIVE_TOOL,
    READ_ONLY_TOOL,
    WRITE_TOOL,
    logger,
)
from .server import mcp
from .validation import validate_server_url

_TRUTHY = {"1", "true", "yes", "on"}


def _debugger_enabled(
    url_explicit: bool = DEBUGGER_URL_EXPLICIT,
    override: str | None = None,
    url: str = DEBUGGER_URL,
) -> bool:
    """Whether to register the 22 debugger proxy tools in this process.

    The proxies forward to an external dbgeng/WinDbg debugger server that is
    not part of this repo. Most users never run one, and registering 22 tools
    that can only ever answer "server not running" clutters every client's
    tool list, so the tools are OFF BY DEFAULT:

      - ``GHIDRA_DEBUGGER_TOOLS`` set and non-blank decides outright:
        1/true/yes/on -> enabled, anything else (0/false/no/off) -> disabled.
        It wins over the URL, so ``GHIDRA_DEBUGGER_TOOLS=0`` turns the tools
        off even with a URL configured.
      - Otherwise the tools register only when ``GHIDRA_DEBUGGER_URL`` was
        explicitly set in the environment AND the call path would accept it.
        The built-in default URL does not count: having a default port is not
        evidence that a server exists. A non-loopback URL does not register
        either, because _debugger_request refuses every non-loopback URL
        (these primitives attach to processes and write memory), so it would
        advertise 22 tools that every call rejects. To reach a debugger on
        another machine, forward its port to loopback and set
        ``GHIDRA_DEBUGGER_TOOLS=1``.

    The host platform plays no part: being on Windows says nothing about
    whether a debugger server is running.

    The tool *functions* are always defined regardless; only their MCP
    registration is gated. Call-time failures (server down) are handled
    separately by _debugger_request().
    """
    if override is None:
        override = os.getenv("GHIDRA_DEBUGGER_TOOLS")
    if override is not None and override.strip():
        return override.strip().lower() in _TRUTHY
    if not url_explicit:
        return False
    if not validate_server_url(url):
        logger.warning(
            "GHIDRA_DEBUGGER_URL=%s is not a loopback http://host:port URL; the debugger "
            "proxy refuses those, so its tools are not registered. Forward the port to "
            "127.0.0.1 and point GHIDRA_DEBUGGER_URL there, or set GHIDRA_DEBUGGER_TOOLS=1.",
            url,
        )
        return False
    return True


_DEBUGGER_ACTIVE = _debugger_enabled()
if _DEBUGGER_ACTIVE:
    config.STATIC_TOOL_NAMES |= DEBUGGER_TOOL_NAMES


def _debugger_tool(*dargs, **dkwargs):
    """Decorator: register a debugger proxy tool only when the backend is usable.

    When the debugger is disabled (the default) the decorated function is left
    untouched (still importable / directly callable / unit-testable) but is not
    exposed as an MCP tool, keeping the tool list uncluttered by default.
    """
    if _DEBUGGER_ACTIVE:
        registrar = mcp.tool(*dargs, **dkwargs)

        def _register(fn):
            async def _async_wrapper(*args, **kwargs):
                return await state.run_blocking_ghidra_call(fn, *args, **kwargs)

            _async_wrapper.__name__ = fn.__name__
            _async_wrapper.__doc__ = fn.__doc__
            _async_wrapper.__annotations__ = fn.__annotations__
            _async_wrapper.__signature__ = inspect.signature(fn)
            registrar(_async_wrapper)
            return fn

        return _register

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
    # The debugger server exposes powerful primitives (attach, read/write
    # memory, breakpoints). Refuse to proxy to a non-loopback URL even though
    # GHIDRA_DEBUGGER_URL is operator-set — mirrors the Ghidra TCP URL policy
    # and stops a stray/hostile env value from redirecting debugger traffic.
    if not validate_server_url(DEBUGGER_URL):
        return json.dumps(
            {
                "error": f"Refusing to use non-loopback debugger URL: {DEBUGGER_URL}. "
                "GHIDRA_DEBUGGER_URL must be http://<127.0.0.1|localhost|::1>:<port>."
            }
        )
    parsed = urlparse(DEBUGGER_URL)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    cancel_handle = state.get_request_cancel_handle()
    if cancel_handle is not None and not cancel_handle.register_connection(conn):
        return json.dumps({"error": f"Debugger request aborted before start: {path}"})
    try:
        conn.connect()
        if cancel_handle is not None and cancel_handle.aborted:
            return json.dumps({"error": f"Debugger request aborted before send: {path}"})
        url = path
        if query:
            url += "?" + urlencode(query)
        headers = {"Content-Type": "application/json"} if body else {}
        if cancel_handle is not None:
            with cancel_handle.hold_send_window(conn) as can_send:
                if not can_send:
                    return json.dumps({"error": f"Debugger request aborted before send: {path}"})
                conn.request(method, url, body=json.dumps(body) if body else None, headers=headers)
        else:
            conn.request(method, url, body=json.dumps(body) if body else None, headers=headers)
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
                "Start your external debugger server, or point GHIDRA_DEBUGGER_URL "
                "at the address it listens on."
            }
        )
    except Exception as e:
        return json.dumps({"error": f"Debugger request failed: {e}"})
    finally:
        if cancel_handle is not None:
            cancel_handle.unregister_connection(conn)
        conn.close()


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
def debugger_attach(target: str) -> str:
    """Attach the debugger to a running process for live dynamic analysis.

    Connects to the target process via dbgeng (WinDbg engine). After attaching,
    use debugger_modules() to see loaded DLLs and debugger_set_breakpoint() to
    set breakpoints.

    Args:
        target: Process name (e.g. "target.exe") or PID.
    """
    result = _debugger_request("POST", "/debugger/attach", {"target": target})

    # Auto-sync address map if Ghidra is connected
    if state._transport_mode != "none":
        try:
            # Fetch image bases from Ghidra for all open programs
            programs_text = dispatch.dispatch_get("/list_open_programs")
            if programs_text:
                programs_data = json.loads(programs_text)
                programs = programs_data if isinstance(programs_data, list) else programs_data.get("programs", [])
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
                    _debugger_request("POST", "/debugger/sync_modules", {"ghidra_bases": ghidra_bases})
                    logger.info(
                        "debugger_attach: auto-synced %d Ghidra image base(s) " "to the debugger address map",
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


@_debugger_tool(annotations=DESTRUCTIVE_TOOL, structured_output=False)
def debugger_detach() -> str:
    """Detach from the debugged process. The process continues running."""
    return _debugger_request("POST", "/debugger/detach")


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_status() -> str:
    """Get debugger connection status, loaded modules, active traces/watches."""
    return _debugger_request("GET", "/debugger/status")


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_modules() -> str:
    """List loaded modules (DLLs) with runtime and Ghidra base addresses.

    Shows each module's name, runtime base, Ghidra base (if mapped),
    and the address offset between them.
    """
    return _debugger_request("GET", "/debugger/modules")


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_resolve_ordinal(dll: str, ordinal: int) -> str:
    """Resolve a DLL ordinal export to its runtime and Ghidra addresses.

    The lookup is performed by the external debugger server, using whatever
    export data it holds for ``dll``, and the result is mapped through the
    current runtime <-> Ghidra address map. Fails if the server has no export
    information for that module.

    Args:
        dll: DLL name (e.g. "example.dll").
        ordinal: Ordinal number (e.g. 1).
    """
    return _debugger_request("GET", "/debugger/ordinal", query={"dll": dll, "ordinal": str(ordinal)})


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
def debugger_set_breakpoint(
    ghidra_address: str,
    module: str = "",
    bp_type: str = "software",
    oneshot: bool = False,
) -> str:
    """Set a breakpoint at a Ghidra address. Auto-translates to runtime address.

    Args:
        ghidra_address: Address in Ghidra (e.g. "0x6FD9F450").
        module: DLL name for disambiguation (e.g. "example.dll").
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


@_debugger_tool(annotations=DESTRUCTIVE_TOOL, structured_output=False)
def debugger_remove_breakpoint(bp_id: int) -> str:
    """Remove a breakpoint by its ID.

    Args:
        bp_id: Breakpoint ID returned by debugger_set_breakpoint.
    """
    return _debugger_request("DELETE", f"/debugger/breakpoint/{bp_id}")


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_list_breakpoints() -> str:
    """List all active breakpoints with their addresses and status."""
    return _debugger_request("GET", "/debugger/breakpoints")


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
def debugger_continue() -> str:
    """Resume execution of the debugged process.

    Returns immediately. The process runs until a breakpoint is hit
    or an exception occurs.
    """
    return _debugger_request("POST", "/debugger/go")


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
def debugger_step_into(count: int = 1) -> str:
    """Single-step into the next instruction(s). Follows calls.

    Args:
        count: Number of instructions to step (default 1).
    """
    return _debugger_request("POST", "/debugger/step_into", {"count": count})


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
def debugger_step_over(count: int = 1) -> str:
    """Step over the next instruction(s). Steps over calls.

    Args:
        count: Number of instructions to step (default 1).
    """
    return _debugger_request("POST", "/debugger/step_over", {"count": count})


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_registers() -> str:
    """Read all CPU registers. Must be stopped at a breakpoint.

    Returns EAX-EDI, ESP, EBP, EIP, EFLAGS for x86.
    """
    return _debugger_request("GET", "/debugger/registers")


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_read_memory(address: str, size: int = 64, address_type: str = "runtime", module: str = "") -> str:
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


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_stack_trace(depth: int = 20) -> str:
    """Get the call stack backtrace with return addresses mapped to Ghidra symbols.

    Args:
        depth: Maximum number of stack frames (default 20).
    """
    return _debugger_request("GET", "/debugger/stack", query={"depth": str(depth)})


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_read_args(convention: str = "__stdcall", count: int = 4, arg_names: str = "") -> str:
    """Read function arguments at the current breakpoint based on calling convention.

    Reads arguments from registers and stack according to the calling convention.
    Must be stopped at a function entry point.

    Args:
        convention: __stdcall, __fastcall, __thiscall, or __cdecl.
        count: Number of arguments to read.
        arg_names: Comma-separated names for readability (e.g. "pContext,nIndex").
    """
    return _debugger_request(
        "GET",
        "/debugger/read_args",
        query={"convention": convention, "count": str(count), "arg_names": arg_names},
    )


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
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
    WITHOUT stopping the target process.

    The handler reads arguments and auto-resumes execution in ~0.5ms, so the
    overhead is negligible for most targets. Use debugger_trace_log() to read
    results.

    Args:
        ghidra_address: Function address in Ghidra.
        module: DLL name (e.g. "example.dll").
        convention: __stdcall, __fastcall, __thiscall, __cdecl.
        arg_count: Number of arguments to capture.
        arg_names: Comma-separated arg names (e.g. "pContext,nIndex,nFlags").
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


@_debugger_tool(annotations=DESTRUCTIVE_TOOL, structured_output=False)
def debugger_trace_stop(trace_id: int = -1) -> str:
    """Stop a function trace. Use trace_id=-1 to stop all traces.

    Args:
        trace_id: ID returned by debugger_trace_function, or -1 for all.
    """
    return _debugger_request("POST", "/debugger/trace/stop", {"trace_id": trace_id})


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
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


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
def debugger_trace_list() -> str:
    """List all active and completed traces with hit counts."""
    return _debugger_request("GET", "/debugger/trace/list")


@_debugger_tool(annotations=WRITE_TOOL, structured_output=False)
def debugger_watch_memory(ghidra_address: str, size: int = 4, access: str = "write", module: str = "") -> str:
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


@_debugger_tool(annotations=DESTRUCTIVE_TOOL, structured_output=False)
def debugger_watch_stop(watch_id: int = -1) -> str:
    """Stop a memory watchpoint. Use watch_id=-1 to stop all.

    Args:
        watch_id: ID returned by debugger_watch_memory, or -1 for all.
    """
    return _debugger_request("POST", "/debugger/watch/stop", {"watch_id": watch_id})


@_debugger_tool(annotations=READ_ONLY_TOOL, structured_output=False)
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
