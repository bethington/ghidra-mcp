"""D2Debugger in-process oracle proxy tools — ask the RUNNING game a question.

Everything else this bridge exposes reasons about the binary *at rest*:
disassembly, hashes, byte signatures, plate text. That makes the whole pipeline
structurally blind to anything which only exists at runtime — live module bases,
populated function-pointer tables, the actual contents of a global right now.
These tools close that gap by proxying to the D2Debugger oracle, an HTTP server
compiled *into* the running Game.exe (D2MOO's ``D2Debugger.dll``) on
:data:`bridge_mcp_ghidra.config.ORACLE_URL`.

Two properties make it usable from here where an external debugger is not:

* **No elevation needed on this side.** Game.exe runs elevated and denies a
  non-elevated caller even ``PROCESS_QUERY_LIMITED_INFORMATION``, but loopback
  TCP is not gated by integrity level, so this HTTP surface answers anyway.
* **It does not stop the game.** These are reads against a live, running process;
  nothing suspends, so the game keeps rendering while the agent asks questions.

TWO CALLING TOOLS, AND THEY ANSWER DIFFERENT QUESTIONS
------------------------------------------------------
``oracle_prove_function`` wraps ``POST /oracle``, which is a *differential*
oracle: it resolves the original AND a reimplementation, calls both over a vector
set, and diffs. It hard-fails ``reimpl not found (provider must export this name)``
for anything D2MOO has not reimplemented, so it reaches roughly the shadow-manifest
population — it answers "does our reimplementation match?", not "what does this do?".

``oracle_call_function`` wraps ``POST /call_original``, which calls the original
ONLY and needs no reimpl, so it reaches any callable address in the live game.
That is what closes the documentation loop: form a claim about a function, call it
with chosen inputs, and confirm or refute against the running game rather than
against another model's opinion.

Calling is the dangerous half of this module (reading and hooking are not). A
totally-wrong address faults and is contained; a SLIGHTLY wrong one runs real code
from mid-function and can corrupt live state or a save file, which no restart
undoes. So ``oracle_call_function`` is OFF unless ``GHIDRA_MCP_ORACLE_CALL=1``,
and it refuses absolute addresses by default — see its docstring.
"""

import http.client
import inspect
import json
import os
import sys
from urllib.parse import urlparse

from . import state
from . import config
from .config import ORACLE_URL, ORACLE_TOOL_NAMES, logger
from .server import mcp
from .validation import validate_server_url

# The oracle is Diablo II specific and lives inside a Windows game process, so a
# local one can only exist on Windows. Same shape as debugger._debugger_enabled().
_LOCAL_ORACLE_HOSTS = {"", "127.0.0.1", "localhost", "::1", "0.0.0.0"}

# /asset/read reads at most this many bytes per HTTP call (server-side clamp).
_ORACLE_READ_CHUNK = 4096
# Ceiling for a single oracle_read_memory call, so one tool call cannot try to
# stream a whole module back through an MCP response.
_ORACLE_READ_MAX = 64 * 1024


def _calling_enabled(override: str | None = None) -> bool:
    """Whether oracle_call_function may actually issue a call.

    Reading the game is safe and always on. CALLING is not: a mis-resolved entry
    can run real code from the middle of a function and corrupt live state or a
    save file — damage a crash-and-relaunch does not undo. Requiring an explicit
    ``GHIDRA_MCP_ORACLE_CALL=1`` means the primitive can never fire because an
    agent guessed a tool name; enabling it is a deliberate operator act.
    """
    if override is None:
        override = os.getenv("GHIDRA_MCP_ORACLE_CALL")
    return bool(override) and override.strip().lower() in {"1", "true", "yes", "on"}


def _oracle_enabled(
    url: str = ORACLE_URL,
    platform: str = sys.platform,
    override: str | None = None,
) -> bool:
    """Whether to register the oracle proxy tools on this host.

    - ``GHIDRA_MCP_ORACLE_TOOLS=1/0`` (true/false/yes/no/on/off) forces on/off.
    - On Windows the game (and therefore the in-process oracle) can run locally.
    - Off Windows a *loopback* oracle can never exist; a *remote* host might.

    The tool functions are always defined (importable / unit-testable); only MCP
    registration is gated.
    """
    if override is None:
        override = os.getenv("GHIDRA_MCP_ORACLE_TOOLS")
    if override is not None and override.strip():
        return override.strip().lower() in {"1", "true", "yes", "on"}
    if platform.startswith("win"):
        return True
    host = (urlparse(url).hostname or "").lower()
    return host not in _LOCAL_ORACLE_HOSTS


_ORACLE_ACTIVE = _oracle_enabled()
if _ORACLE_ACTIVE:
    config.STATIC_TOOL_NAMES |= ORACLE_TOOL_NAMES


def _oracle_tool(*dargs, **dkwargs):
    """Register an oracle proxy tool only where the oracle can exist."""
    if _ORACLE_ACTIVE:
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


def _oracle_request(
    method: str,
    path: str,
    body: dict | None = None,
    timeout: int = 20,
) -> str:
    """Send one request to the in-process oracle. Returns a JSON string.

    Never raises: a dead game is the normal case (the game is relaunched often),
    so every failure comes back as ``{"error": ...}`` for the agent to read.
    """
    # The oracle exposes arbitrary memory writes and in-process calls. Refuse a
    # non-loopback URL outright, exactly as the debugger proxy does, so a stray
    # or hostile env value cannot redirect this traffic off-box.
    if not validate_server_url(ORACLE_URL):
        return json.dumps(
            {
                "error": f"Refusing to use non-loopback oracle URL: {ORACLE_URL}. "
                "D2DBG_MCP_URL must be http://<127.0.0.1|localhost|::1>:<port>."
            }
        )
    parsed = urlparse(ORACLE_URL)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        payload = json.dumps(body) if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        if resp.status >= 400:
            try:
                err = json.loads(data)
                return json.dumps({"error": err.get("error", data), "status": resp.status})
            except Exception:
                return json.dumps({"error": data, "status": resp.status})
        return data
    except ConnectionRefusedError:
        return json.dumps(
            {
                "error": f"D2Debugger oracle not reachable at {ORACLE_URL}. The game "
                "is not running, or it is running without the D2Debugger build. "
                "This is expected between relaunches; retry shortly."
            }
        )
    except Exception as e:
        return json.dumps({"error": f"Oracle request failed: {e}"})
    finally:
        conn.close()


@_oracle_tool()
def oracle_status() -> str:
    """Check whether the live game + in-process oracle are up, and what they hold.

    Call this FIRST before any other oracle tool — the game is relaunched often
    (crashes, redeploys, recovery), so "is it up right now" is a real question.

    Returns the oracle's own status: dispatcher count, how many are bound to a
    reimplementation, the loaded provider, capture counters, and character-select
    state. An ``error`` field means the game is down or was built without
    D2Debugger.
    """
    return _oracle_request("GET", "/status")


@_oracle_tool()
def oracle_modules() -> str:
    """List every module loaded in the LIVE game, with its RUNTIME base address.

    Use this before any address arithmetic that crosses into the running game.
    A module's live base is NOT its Ghidra image base: D2Common and D2Game load
    at their preferred base, but D2Client frequently does not, and several
    modules (D2Game, D2Net, D2Lang) are routinely relocated. Sending a Ghidra
    absolute address into the game therefore points at unmapped memory.

    Always convert: ``live_address = module_base_from_here + rva``, where the rva
    comes from Ghidra (``ghidra_address - ghidra_image_base``).

    Note that names can be ambiguous — D2MOO loads its own reimplementation
    copies of D2Common/D2Client/SGD2FreeRes alongside the game's, so the same
    name can appear twice with different bases and sizes. Prefer matching on
    base address when it matters.
    """
    return _oracle_request("GET", "/modules")


@_oracle_tool()
def oracle_read_memory(module: str, rva: str, length: int = 256) -> str:
    """Read raw bytes out of the LIVE game process (no elevation, no suspend).

    This is the runtime counterpart to Ghidra's static ``read_memory``, and the
    two answer different questions. Ghidra shows the bytes on disk; this shows
    what is actually mapped right now — which is where you can see relocations
    applied, mod patches spliced in, and, most usefully, DATA THAT IS ONLY
    POPULATED AT RUNTIME. A function-pointer table that reads as zeros or
    ``undefined`` statically holds real, resolvable target addresses here.

    Args:
        module: Module name as reported by oracle_modules (e.g. "D2Common.dll").
        rva: Offset from that module's base — hex ("0x4dac0") or decimal.
            This is ``ghidra_address - ghidra_image_base``, never a Ghidra
            absolute address.
        length: Bytes to read (1..65536). Reads are chunked automatically.

    Returns JSON with ``hex`` (the bytes), ``got`` (how many were readable), and
    ``requested``. A short ``got`` is not an error — it means the read ran into
    an unmapped page, and the readable prefix is returned.
    """
    try:
        rva_int = int(str(rva), 16) if str(rva).lower().startswith("0x") else int(str(rva), 0)
    except (TypeError, ValueError):
        return json.dumps({"error": f"Invalid rva: {rva!r} (use 0x-hex or decimal)"})
    if rva_int < 0:
        return json.dumps({"error": f"Invalid rva: {rva!r} (must be non-negative)"})
    try:
        want = int(length)
    except (TypeError, ValueError):
        return json.dumps({"error": f"Invalid length: {length!r}"})
    if want < 1:
        return json.dumps({"error": "length must be >= 1"})
    if want > _ORACLE_READ_MAX:
        return json.dumps(
            {"error": f"length {want} exceeds per-call maximum {_ORACLE_READ_MAX}; read in pieces"}
        )

    out: list[str] = []
    got = 0
    offset = 0
    while offset < want:
        chunk = min(_ORACLE_READ_CHUNK, want - offset)
        raw = _oracle_request(
            "POST", "/asset/read", {"module": module, "rva": hex(rva_int + offset), "len": chunk}
        )
        try:
            payload = json.loads(raw)
        except Exception:
            return json.dumps({"error": f"Unparseable oracle response: {raw[:200]}"})
        if payload.get("error"):
            # Nothing read at all -> surface the transport/game error as-is.
            if not out:
                return raw
            break
        if not payload.get("ok"):
            if not out:
                return json.dumps(
                    {"error": f"Oracle refused the read (module {module!r} loaded?)", "detail": payload}
                )
            break
        piece = payload.get("hex", "") or ""
        out.append(piece)
        n = len(piece) // 2
        got += n
        if n < chunk:  # hit an unmapped page; readable prefix is what we have
            break
        offset += chunk

    # Nothing readable at all is a FAILED read, not an empty one. The oracle
    # answers ok:true / got:0 for a module it cannot resolve (GetModuleHandleA
    # returns null and it reads nothing), so reporting success here would tell an
    # agent "that address holds no data" when the truth is "that module is not
    # loaded, check oracle_modules" -- a wrong answer dressed as a fact.
    if got == 0:
        return json.dumps(
            {
                "error": (
                    f"Read nothing at {module}+{hex(rva_int)}. The module is probably not "
                    f"loaded in the game (check oracle_modules for exact names), or the "
                    f"address is unmapped."
                ),
                "module": module,
                "rva": hex(rva_int),
                "requested": want,
                "got": 0,
            }
        )

    return json.dumps(
        {
            "ok": True,
            "module": module,
            "rva": hex(rva_int),
            "requested": want,
            "got": got,
            "truncated": got < want,
            "hex": "".join(out),
        }
    )


@_oracle_tool()
def oracle_call_function(
    module: str,
    rva: str,
    callconv: str = "stdcall",
    ret: str = "void",
    args: str = "[]",
    on_game_thread: bool = False,
) -> str:
    """Call a function in the LIVE game and observe what it actually does.

    This is how a claim gets tested instead of asserted. Decompilation tells you
    what a function looks like; this tells you what it does. Unlike
    oracle_prove_function it needs no reimplementation, so it reaches any callable
    address in the running process.

    DISABLED by default. Set ``GHIDRA_MCP_ORACLE_CALL=1`` to enable. Calling is
    the one primitive here that can do damage a restart does not undo: a slightly
    wrong entry address executes real code from mid-function and can corrupt live
    game state or a character save. Back up the save directory first.

    Before calling anything, confirm the target really is a function ENTRY (its
    prologue, from Ghidra) — not an address you inferred. Prefer functions you
    believe are pure; a mutator changes the running game.

    Args:
        module: Module name from oracle_modules (e.g. "D2Common.dll").
        rva: Offset from that module's base, hex ("0x4dac0") or decimal — i.e.
            ``ghidra_address - ghidra_image_base``. NEVER a Ghidra absolute
            address: several modules relocate at load, so an absolute points at
            unmapped memory or, worse, the wrong code.
        callconv: cdecl | stdcall | fastcall | thiscall. Take this from the
            DISASSEMBLY (a bare RET is cdecl; ``RET n`` is callee-cleans), not
            from a guess — a wrong convention skews ESP and can crash the game.
        ret: void | i8 | u8 | i16 | u16 | i32 | u32 | i64 | u64.
        args: JSON array string, max 8. Scalar: ``{"kind":"i32","value":100}``.
            Pointer/out-param: ``{"kind":"buf","bytes":4,"hex":"64000000"}`` —
            a buffer is allocated, optionally seeded from ``hex``, its ADDRESS is
            passed, and its contents are returned in ``args_out`` so you can see
            what the callee wrote.
        on_game_thread: Marshal onto the game's own thread. Needed for functions
            that touch live game state racing the render thread; slower.

    Returns JSON with ``ret`` (masked to the declared width), ``args_out`` (hex
    per buffer arg, null for scalars), and the resolved ``address``.
    """
    if not _calling_enabled():
        return json.dumps(
            {
                "error": "Calling into the live game is disabled. Set "
                "GHIDRA_MCP_ORACLE_CALL=1 to enable it. This gate exists because a "
                "mis-resolved entry address can corrupt live game state or a save "
                "file — damage that relaunching does not undo. Back up the save "
                "directory before enabling."
            }
        )
    try:
        parsed_args = json.loads(args) if isinstance(args, str) else (args or [])
    except Exception as e:
        return json.dumps({"error": f"args must be a JSON array string: {e}"})
    if not isinstance(parsed_args, list):
        return json.dumps({"error": "args must be a JSON array"})
    if len(parsed_args) > 8:
        return json.dumps({"error": f"too many args ({len(parsed_args)}); the oracle allows 8 slots"})
    if not module:
        return json.dumps({"error": "module is required (see oracle_modules)"})
    try:
        rva_int = int(str(rva), 16) if str(rva).lower().startswith("0x") else int(str(rva), 0)
    except (TypeError, ValueError):
        return json.dumps({"error": f"Invalid rva: {rva!r} (use 0x-hex or decimal)"})
    if rva_int < 0:
        return json.dumps({"error": f"Invalid rva: {rva!r} (must be non-negative)"})
    # A Ghidra image base arriving here means the caller passed an ABSOLUTE
    # address. Several D2 modules relocate, so that address is wrong in the live
    # process -- refuse rather than call into whatever happens to be mapped there.
    if rva_int >= 0x10000000:
        return json.dumps(
            {
                "error": f"rva {rva!r} looks like an absolute address, not a module offset. "
                "Pass ghidra_address - ghidra_image_base; live module bases differ "
                "from Ghidra's (see oracle_modules)."
            }
        )

    return _oracle_request(
        "POST",
        "/call_original",
        {
            "module": module,
            "rva": hex(rva_int),
            "callconv": callconv,
            "ret": ret,
            "args": parsed_args,
            "onGameThread": bool(on_game_thread),
        },
        timeout=40,
    )


@_oracle_tool()
def oracle_prove_function(spec: str) -> str:
    """Differentially prove one function: call the ORIGINAL and D2MOO's REIMPL and diff.

    IMPORTANT — this is not a general "call this function" tool, and it cannot be
    used to test a hypothesis about an arbitrary function. The oracle resolves a
    reimplementation as well as the original and returns
    ``reimpl not found (provider must export this name)`` when D2MOO has not
    reimplemented the target. It therefore reaches roughly the shadow-manifest
    population, not the whole Ghidra database. Check ``oracle_status`` — the
    ``provider`` field reports how many dispatchers are bound.

    The original is resolved by, in order of precedence: ``module``+``rva``
    (PREFERRED — resolved against the RUNTIME base, so it is correct even for a
    relocated module), then ``offset`` (D2Common-relative), then ``addr``
    (absolute; WRONG for any relocated module), then the function ``name``.

    Args:
        spec: JSON object as a string. Required keys: ``name`` (the provider's
            export name) and ``vectors`` (a non-empty array of input sets, max
            4096). Strongly recommended: ``module`` + ``rva`` to pin the original.
            Optional: ``callconv`` (cdecl|stdcall|fastcall|thiscall, default
            stdcall), ``ret`` (default "void"), ``args`` (max 8 slots, each with
            ``id`` and ``kind``: i32|buf|ptr|out|synth|synth2|handle),
            ``compare`` (channels to diff, e.g. ["ret"]), ``onGameThread``.

    Returns the oracle's per-vector comparison, including match/mismatch counts.
    """
    try:
        parsed = json.loads(spec) if isinstance(spec, str) else spec
    except Exception as e:
        return json.dumps({"error": f"spec must be a JSON object string: {e}"})
    if not isinstance(parsed, dict):
        return json.dumps({"error": "spec must be a JSON object"})
    if not parsed.get("name"):
        return json.dumps({"error": "spec.name is required (the provider's export name)"})
    vectors = parsed.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return json.dumps({"error": "spec.vectors is required and must be a non-empty array"})
    return _oracle_request("POST", "/oracle", parsed, timeout=60)


logger.debug("oracle proxy tools %s", "registered" if _ORACLE_ACTIVE else "not registered")
