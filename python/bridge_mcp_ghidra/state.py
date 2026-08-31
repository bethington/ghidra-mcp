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
from dataclasses import dataclass
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
_tools_changed_session_lock = threading.Lock()
_tools_changed_targets: list[tuple[asyncio.AbstractEventLoop, object]] = []
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
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    with _tools_changed_session_lock:
        for existing_loop, existing_session in _tools_changed_targets:
            if existing_loop is loop and existing_session is session:
                return
        _tools_changed_targets.append((loop, session))


def remember_tools_changed_context(ctx) -> None:
    """Remember the MCP session behind a FastMCP Context, if it has one."""
    if ctx is None or getattr(ctx, "_request_context", None) is None:
        return
    remember_tools_changed_session(ctx.request_context.session)


def notify_tools_changed_from_worker() -> None:
    """Best-effort tools/list_changed notification from a worker thread."""
    with _tools_changed_session_lock:
        targets = list(_tools_changed_targets)
    stale: list[tuple[asyncio.AbstractEventLoop, object]] = []
    for loop, session in targets:
        if loop.is_closed():
            stale.append((loop, session))
            continue
        try:
            asyncio.run_coroutine_threadsafe(session.send_tool_list_changed(), loop)
        except Exception:
            stale.append((loop, session))
    if stale:
        with _tools_changed_session_lock:
            for target in stale:
                if target in _tools_changed_targets:
                    _tools_changed_targets.remove(target)


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

# CLI-configurable: --lazy keeps only default groups, otherwise load all
_lazy_mode = False  # default: eager (load all groups on connect)
_default_groups: set[str] = set(CORE_GROUPS)
