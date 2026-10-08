"""Mutable connection and tool-registration state shared across the bridge.

All cross-module readers and writers reference these names through this module
object (e.g. ``state._transport_mode``) so a single source of truth is mutated.
Functions in other modules never use ``global`` on these names — they assign
``state.<name> = ...`` instead.
"""

import asyncio
import atexit
import concurrent.futures
import contextvars
import os
import threading
import weakref
from dataclasses import dataclass, field
from functools import partial
from contextlib import contextmanager

from .config import CORE_GROUPS, MAX_CONCURRENT_GHIDRA_REQUESTS, logger

# --------------------------------------------------------------------------
# Connection state
# --------------------------------------------------------------------------

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"
_connected_project: str | None = None  # Project name for auto-reconnect
_connection_generation = 0
_executor_lock = threading.Lock()


@dataclass(frozen=True)
class ConnectionSnapshot:
    mode: str
    active_socket: str | None
    active_tcp: str | None
    connected_project: str | None
    generation: int


class RequestCancelHandle:
    """Shared cancellation handle for one in-flight worker request."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._aborted = False
        self._connections: set[object] = set()

    def register_connection(self, conn: object) -> bool:
        with self._lock:
            if self._aborted:
                try:
                    conn.close()
                except Exception:
                    pass
                return False
            self._connections.add(conn)
            return True

    def unregister_connection(self, conn: object) -> None:
        with self._lock:
            self._connections.discard(conn)

    def abort(self) -> None:
        with self._lock:
            self._aborted = True
            conns = list(self._connections)
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass

    @property
    def aborted(self) -> bool:
        with self._lock:
            return self._aborted

    def run_if_not_aborted(self, func, /, *args, **kwargs):
        """Run a small critical section only if the request is still live."""
        with self._lock:
            if self._aborted:
                return None
            return func(*args, **kwargs)

    @contextmanager
    def hold_send_window(self, conn: object):
        """Prevent abort() from closing `conn` while a request send starts."""
        with self._lock:
            if self._aborted or conn not in self._connections:
                yield False
            else:
                yield True


def _create_worker_pool() -> concurrent.futures.ThreadPoolExecutor:
    return concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_CONCURRENT_GHIDRA_REQUESTS,
        thread_name_prefix="GhidraMCP-Bridge",
    )


# Shared worker pool for blocking bridge-side I/O. The executor itself is the
# process-wide concurrency limit, so embedded/multi-loop use cannot exceed the
# configured request cap.
_ghidra_executor = _create_worker_pool()

# Connection routing is captured at request admission time and propagated via a
# context variable into the worker thread.
_request_connection: contextvars.ContextVar[ConnectionSnapshot | None] = contextvars.ContextVar(
    "ghidra_request_connection", default=None
)
_request_cancel_handle: contextvars.ContextVar[RequestCancelHandle | None] = contextvars.ContextVar(
    "ghidra_request_cancel_handle", default=None
)

# Multiple failed in-flight requests can notice the same Ghidra restart. Schema
# discovery and dynamic tool registration mutate shared state and must happen
# once at a time even though normal HTTP requests may proceed concurrently.
_reconnect_lock = threading.RLock()

# Dynamic tool registration reaches into FastMCP internals and mutates shared
# name/group state. Keep those mutations serialized even though normal Ghidra
# requests are concurrent.
_tool_registry_lock = threading.RLock()
_active_request_handles_lock = threading.Lock()
_active_request_handles: set[RequestCancelHandle] = set()

# --------------------------------------------------------------------------
# Strict program routing
# --------------------------------------------------------------------------

# When GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1, the bridge refuses any
# program-scoped call that omits a program selector, so a forgotten one fails
# loudly instead of silently running against the server's mutable "current
# program" and hitting the wrong binary. Off by default. (Full rationale in
# commit 6f85c5e / README.)
_require_selectors: bool = False


def _init_require_selectors() -> None:
    """Read GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS once, at import. Set it to 1 to enable."""
    global _require_selectors
    _require_selectors = (os.getenv("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS") or "").strip() == "1"
    if _require_selectors:
        logger.info(
            "Strict program routing enabled (GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1); "
            "program-scoped calls missing a program selector will be refused"
        )


_init_require_selectors()


def get_connection_snapshot() -> ConnectionSnapshot:
    """Capture the current global connection target atomically."""
    with _reconnect_lock:
        return ConnectionSnapshot(
            mode=_transport_mode,
            active_socket=_active_socket,
            active_tcp=_active_tcp,
            connected_project=_connected_project,
            generation=_connection_generation,
        )


def get_request_connection_snapshot() -> ConnectionSnapshot | None:
    """Get the request-bound connection snapshot, if one is active."""
    return _request_connection.get()


def get_request_cancel_handle() -> RequestCancelHandle | None:
    """Get the request-bound cancellation handle, if one is active."""
    return _request_cancel_handle.get()


def set_connection_snapshot(
    mode: str,
    *,
    active_socket: str | None = None,
    active_tcp: str | None = None,
    connected_project: str | None = None,
) -> ConnectionSnapshot:
    """Install a new global connection target and advance the generation."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project, _connection_generation
    with _reconnect_lock:
        _active_socket = active_socket
        _active_tcp = active_tcp
        _transport_mode = mode
        _connected_project = connected_project
        _connection_generation += 1
        return ConnectionSnapshot(
            mode=_transport_mode,
            active_socket=_active_socket,
            active_tcp=_active_tcp,
            connected_project=_connected_project,
            generation=_connection_generation,
        )


def maybe_promote_connection_snapshot(
    previous: ConnectionSnapshot, candidate: ConnectionSnapshot
) -> ConnectionSnapshot | None:
    """Install `candidate` only if the global connection still equals `previous`."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project, _connection_generation
    with _reconnect_lock:
        current = ConnectionSnapshot(
            mode=_transport_mode,
            active_socket=_active_socket,
            active_tcp=_active_tcp,
            connected_project=_connected_project,
            generation=_connection_generation,
        )
        if current != previous:
            return None
        _active_socket = candidate.active_socket
        _active_tcp = candidate.active_tcp
        _transport_mode = candidate.mode
        _connected_project = candidate.connected_project
        _connection_generation += 1
        return ConnectionSnapshot(
            mode=_transport_mode,
            active_socket=_active_socket,
            active_tcp=_active_tcp,
            connected_project=_connected_project,
            generation=_connection_generation,
        )


def build_connection_snapshot(
    *,
    mode: str,
    active_socket: str | None = None,
    active_tcp: str | None = None,
    connected_project: str | None = None,
    generation: int = 0,
) -> ConnectionSnapshot:
    """Construct an explicit connection snapshot without mutating global state."""
    return ConnectionSnapshot(
        mode=mode,
        active_socket=active_socket,
        active_tcp=active_tcp,
        connected_project=connected_project,
        generation=generation,
    )


def _capture_request_connection_snapshot() -> ConnectionSnapshot:
    """Capture a request-bound snapshot atomically with route/schema switches."""
    with _tool_registry_lock:
        return get_connection_snapshot()


def remember_tools_changed_session(session) -> None:
    """Remember one MCP session that can receive tools/list_changed.

    Must be called from the session's own event loop — the loop is captured
    here so a worker thread can later dispatch the notification back onto it.

    Registration used to happen ONLY inside connect_instance/load_tool_group/
    unload_tool_group/import_file, which are tools the client has to call
    first. That made the whole notification path dead in the one situation it
    exists for: a bridge started BEFORE Ghidra registers 35 static tools, the
    background retry succeeds seconds later and calls
    notify_tools_changed_from_worker() — into an EMPTY target list, because no
    static tool had been invoked yet. The client is never told, so the session
    runs to its end showing 35 of 273 tools while Ghidra is healthy. Capturing
    at tools/list (see server.py) fixes that: every client lists tools right
    after initialize, so a target always exists before the retry can win.
    """
    if session is None:
        return
    remember_resource_interest(session, tools_changed=True)


def remember_tools_changed_context(ctx) -> None:
    """Remember the MCP session behind a FastMCP Context, if it has one."""
    if ctx is None or getattr(ctx, "_request_context", None) is None:
        return
    remember_tools_changed_session(ctx.request_context.session)


def notify_tools_changed_from_worker() -> None:
    """Best-effort tools/list_changed notification from a worker thread.

    Shares the session registry below, which holds sessions by weakref and
    prunes on a failed send — this list used to be its own strong-reference
    list that only noticed a *closed loop*, so a dropped session stayed in it
    (and stayed alive) until the process exited.
    """
    for loop, session, _entry in iter_resource_interest(require_tools_changed=True):
        if not schedule_on_session_loop(loop, session.send_tool_list_changed()):
            drop_resource_interest(session)


# --------------------------------------------------------------------------
# Resource subscription / cache-interest bookkeeping
# --------------------------------------------------------------------------
#
# A client's `resources/read` cache is keyed by URI whether or not it ever
# called `resources/subscribe`. We therefore track both subscribed and merely
# read URIs, and only emit `resources/updated` for URIs a session already
# knows about — so a write cannot storm every connected client with URIs it
# never asked for.
#
# Held by weakref so a dropped session (stdio EOF, HTTP session GC) does not
# pin the ServerSession forever the way the strong-reference tools/list_changed
# list this replaced did. Failed sends also prune the entry.

_RESOURCE_NOTIFY_TIMEOUT_SECONDS = 2.0


@dataclass
class ResourceSessionInterest:
    """One MCP session's interest in Ghidra resource URIs."""

    loop: asyncio.AbstractEventLoop
    session_ref: weakref.ref
    subscribed_uris: set[str] = field(default_factory=set)
    read_uris: set[str] = field(default_factory=set)
    # tools/list_changed goes to every session that ran a tool, not only the
    # ones that touched a resource, so it needs its own flag rather than
    # "has any interest".
    wants_tools_changed: bool = False


_resource_interest_lock = threading.Lock()
_resource_interest: dict[int, ResourceSessionInterest] = {}


def _drop_resource_interest(session_id: int) -> None:
    with _resource_interest_lock:
        _resource_interest.pop(session_id, None)


def remember_resource_interest(
    session,
    *,
    uri: str | None = None,
    subscribed: bool = False,
    read: bool = False,
    tools_changed: bool = False,
) -> None:
    """Record that ``session`` cares about ``uri`` (subscribe and/or read)."""
    if session is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if loop.is_closed():
        return

    session_id = id(session)
    with _resource_interest_lock:
        entry = _resource_interest.get(session_id)
        if entry is None or entry.session_ref() is None:
            try:
                ref = weakref.ref(
                    session, lambda _ref, sid=session_id: _drop_resource_interest(sid)
                )
            except TypeError:
                # Bookkeeping is best-effort and must never break the call that
                # triggered it. A real ServerSession is weak-referenceable; a
                # substitute that is not simply goes untracked.
                logger.debug("Session %r cannot be tracked (no weakref support)", type(session))
                return
            entry = ResourceSessionInterest(loop=loop, session_ref=ref)
            _resource_interest[session_id] = entry
        else:
            entry.loop = loop
        if uri:
            if subscribed:
                entry.subscribed_uris.add(uri)
            if read:
                entry.read_uris.add(uri)
        if tools_changed:
            entry.wants_tools_changed = True


def forget_resource_subscription(session, uri: str) -> None:
    """Drop a single subscription; read interest is kept (cache may still hold it)."""
    if session is None:
        return
    with _resource_interest_lock:
        entry = _resource_interest.get(id(session))
        if entry is None:
            return
        entry.subscribed_uris.discard(uri)


def iter_resource_interest(
    *,
    uri: str | None = None,
    require_subscription: bool = False,
    require_tools_changed: bool = False,
) -> list[tuple[asyncio.AbstractEventLoop, object, ResourceSessionInterest]]:
    """Live ``(loop, session, entry)`` triples, optionally filtered to a URI.

    Dead weakrefs and closed loops are pruned as a side effect.
    """
    with _resource_interest_lock:
        items = list(_resource_interest.items())
    live: list[tuple[asyncio.AbstractEventLoop, object, ResourceSessionInterest]] = []
    stale_ids: list[int] = []
    for session_id, entry in items:
        session = entry.session_ref()
        if session is None or entry.loop.is_closed():
            stale_ids.append(session_id)
            continue
        if require_tools_changed and not entry.wants_tools_changed:
            continue
        if uri is not None:
            known = entry.subscribed_uris if require_subscription else (
                entry.subscribed_uris | entry.read_uris
            )
            if uri not in known:
                continue
        live.append((entry.loop, session, entry))
    if stale_ids:
        with _resource_interest_lock:
            for session_id in stale_ids:
                current = _resource_interest.get(session_id)
                if current is not None and current.session_ref() is None:
                    _resource_interest.pop(session_id, None)
                elif current is not None and current.loop.is_closed():
                    _resource_interest.pop(session_id, None)
    return live


def known_resource_uris(session=None) -> set[str]:
    """URIs this session (or every session) has read or subscribed to."""
    with _resource_interest_lock:
        if session is not None:
            entry = _resource_interest.get(id(session))
            if entry is None:
                return set()
            return set(entry.subscribed_uris | entry.read_uris)
        out: set[str] = set()
        for entry in _resource_interest.values():
            if entry.session_ref() is None:
                continue
            out |= entry.subscribed_uris
            out |= entry.read_uris
        return out


# Strong refs for same-loop sends; a bare create_task may be collected mid-send.
_same_loop_sends: set[asyncio.Task] = set()


def schedule_on_session_loop(loop: asyncio.AbstractEventLoop, coro) -> bool:
    """Run ``coro`` on ``loop`` from any thread; await the future with a short timeout.

    Returns True on success. Failures (closed loop, timeout, send error) return
    False so the caller can prune — unlike ``notify_tools_changed_from_worker``,
    which fire-and-forgets and only notices ``loop.is_closed()``.
    """
    if loop.is_closed():
        return False
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is loop:
        # Already on the session loop: blocking on the future here would
        # deadlock, so schedule and return. In-request paths should await the
        # coroutine themselves — this branch only covers callers that cannot
        # know which thread they are on.
        task = loop.create_task(coro)
        _same_loop_sends.add(task)
        task.add_done_callback(_same_loop_sends.discard)
        return True
    try:
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        future.result(timeout=_RESOURCE_NOTIFY_TIMEOUT_SECONDS)
        return True
    except Exception as e:
        logger.debug("Resource notification on session loop failed: %s", e)
        return False


def drop_resource_interest(session) -> None:
    """Forget a session entirely (used after a failed send)."""
    if session is None:
        return
    _drop_resource_interest(id(session))


def _get_worker_pool() -> concurrent.futures.ThreadPoolExecutor:
    global _ghidra_executor
    with _executor_lock:
        if _ghidra_executor is None:
            _ghidra_executor = _create_worker_pool()
        return _ghidra_executor


async def run_in_worker(func, /, *args, done_callback=None, **kwargs):
    """Run blocking bridge code in a worker thread."""
    context = contextvars.copy_context()
    work = partial(context.run, func, *args, **kwargs)
    future = _get_worker_pool().submit(work)
    if done_callback is not None:

        def _on_done(done):
            try:
                result = done.result()
            except Exception:
                return
            try:
                done_callback(result)
            except Exception:
                logger.exception("run_in_worker done_callback failed")

        future.add_done_callback(_on_done)
    return await asyncio.wrap_future(future)


async def run_blocking_ghidra_call(
    func,
    /,
    *args,
    bind_connection: bool = True,
    connection: ConnectionSnapshot | None = None,
    **kwargs,
):
    """Run one blocking Ghidra call with cancellation-safe request binding."""
    snapshot = connection if bind_connection else None
    if bind_connection and snapshot is None:
        snapshot = _capture_request_connection_snapshot()
    cancel_handle = RequestCancelHandle()
    with _active_request_handles_lock:
        _active_request_handles.add(cancel_handle)
    token = _request_connection.set(snapshot) if bind_connection else None
    cancel_token = _request_cancel_handle.set(cancel_handle)
    context = contextvars.copy_context()
    work = partial(context.run, func, *args, **kwargs)
    future = _get_worker_pool().submit(work)
    wrapped = asyncio.wrap_future(future)
    try:
        return await asyncio.shield(wrapped)
    except asyncio.CancelledError:
        if future.cancel():
            raise
        cancel_handle.abort()
        try:
            await asyncio.wait_for(wrapped, timeout=1)
        except asyncio.TimeoutError:
            pass
        raise
    finally:
        with _active_request_handles_lock:
            _active_request_handles.discard(cancel_handle)
        _request_cancel_handle.reset(cancel_token)
        if token is not None:
            _request_connection.reset(token)


def shutdown_worker_pool(wait: bool = False) -> None:
    """Stop the shared executor used by bridge-side worker offload."""
    global _ghidra_executor
    with _active_request_handles_lock:
        active_handles = list(_active_request_handles)
    for handle in active_handles:
        handle.abort()
    with _executor_lock:
        executor = _ghidra_executor
        if executor is None:
            return
        _ghidra_executor = None
    executor.shutdown(wait=wait, cancel_futures=True)


atexit.register(shutdown_worker_pool, False)


# --------------------------------------------------------------------------
# Tool-registration state
# --------------------------------------------------------------------------

# NOTE: _dynamic_tool_names and _loaded_groups are only ever mutated in place
# (clear/append/add/discard) so external references stay valid. _full_schema,
# _lazy_mode, and _default_groups ARE reassigned — always read them through
# this module.
_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema
_loaded_groups: set[str] = set()

# CLI-configurable: --lazy keeps only default groups, --no-lazy loads all.
#
# DEFAULT IS LAZY (#440). Eager was the default until 2026-08-25 and made the
# bridge advertise all 253 endpoints in one tools/list. That is not merely
# expensive -- it is over a hard limit for at least one major provider. Gemini
# compiles function declarations into a constrained-decoding state machine and
# rejects the whole request before any tool is ever called:
#
#     400 INVALID_ARGUMENT
#     "The specified schema produces a constraint that has too many states
#      for serving"
#
# So the eager default did not degrade Gemini clients, it broke them outright,
# and no amount of client-side configuration could work around a server that
# only ever offered the full set. CORE_GROUPS (listing/function/program) is 57
# endpoints + 8 static tools, which fits.
#
# Eager only ever existed for clients that ignore tools/list_changed and would
# therefore never see a later load_tool_group() registration. That notification
# actually works as of a7f5936, and the always-present static tools
# (search_tools / check_tools) hand the model the exact load_tool_group(...)
# call it needs, so discovery no longer depends on advertising everything up
# front. Clients that still want the old behaviour pass --no-lazy, or set
# GHIDRA_MCP_LAZY=0 where the client's config gives no way to pass argv (a
# container ENTRYPOINT, an `uvx` invocation, a registry-installed server entry).
_lazy_mode = True  # default: lazy (CORE_GROUPS only; --no-lazy loads all)
_default_groups: set[str] = set(CORE_GROUPS)

_TRUTHY_LAZY = {"1", "true", "yes", "on"}
_FALSEY_LAZY = {"0", "false", "no", "off"}


def lazy_mode_from_env(default: bool = True) -> bool:
    """Resolve lazy mode from GHIDRA_MCP_LAZY, falling back to the default.

    The escape hatch for a client that ignores ``tools/list_changed`` is
    ``--no-lazy``, but a CLI flag is only reachable when the caller controls
    argv. Docker ENTRYPOINTs, ``uvx`` one-liners and some MCP client configs
    do not, and telling those users "pass a flag you cannot pass" is not an
    escape hatch. GHIDRA_MCP_LAZY=0 is the same switch by another route.

    An unrecognised value is ignored (and warned about) rather than guessed at,
    because guessing here silently picks one of the two client families this
    setting exists to keep working.
    """
    raw = (os.getenv("GHIDRA_MCP_LAZY") or "").strip().lower()
    if not raw:
        return default
    if raw in _FALSEY_LAZY:
        return False
    if raw in _TRUTHY_LAZY:
        return True
    logger.warning(
        "Ignoring GHIDRA_MCP_LAZY=%r: expected one of %s. Leaving lazy tool loading %s.",
        raw,
        ",".join(sorted(_TRUTHY_LAZY | _FALSEY_LAZY)),
        "on" if default else "off",
    )
    return default
