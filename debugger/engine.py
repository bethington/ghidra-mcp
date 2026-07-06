"""
dbgeng engine wrapper — thin layer over pybag with proper COM threading.

Replicates the Worker/Queue/eng_thread pattern from Ghidra's ghidradbg/util.py
without importing it, so we have no coupling to Ghidra's internal debugger agent.
"""

from __future__ import annotations

import concurrent.futures
import functools
import io
import logging
import os
import queue
import struct
import threading
import time
from collections import namedtuple
from contextlib import contextmanager, nullcontext
from concurrent.futures import Future
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, TypeVar, cast

from .windbg import ensure_windbg_dir

ensure_windbg_dir()

from pybag import pydbg, userdbg  # type: ignore
from pybag.dbgeng import core as DbgEng  # type: ignore
from pybag.dbgeng import exception  # type: ignore

from .protocol import BreakpointInfo, BreakpointType, DebuggerState, ModuleInfo

logger = logging.getLogger(__name__)

T = TypeVar("T")
C = TypeVar("C", bound=Callable[..., Any])
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664


def _normalize_pid_match(match: Any) -> int:
    if isinstance(match, tuple):
        if not match:
            raise RuntimeError("Process lookup returned an empty match tuple")
        match = match[0]
    return int(match)


def _module_info_from_pybag_entry(raw_module: Any) -> ModuleInfo:
    if isinstance(raw_module, ModuleInfo):
        return raw_module

    if isinstance(raw_module, tuple) and len(raw_module) == 2:
        name_info, params = raw_module
        if isinstance(name_info, tuple):
            image_path = str(name_info[0]) if len(name_info) > 0 and name_info[0] else ""
            short_name = str(name_info[1]) if len(name_info) > 1 and name_info[1] else ""
            loaded_name = str(name_info[2]) if len(name_info) > 2 and name_info[2] else ""
            name = short_name or os.path.basename(image_path) or os.path.basename(loaded_name) or image_path or str(name_info)
        else:
            name = str(name_info)

        runtime_base = getattr(params, "Base", getattr(params, "base", None))
        size = getattr(params, "Size", getattr(params, "size", None))
        if runtime_base is None or size is None:
            raise ValueError(f"Unsupported pybag module tuple: {raw_module!r}")
        return ModuleInfo(name=name, runtime_base=int(runtime_base), size=int(size))

    name = getattr(raw_module, "name", None)
    runtime_base = getattr(raw_module, "runtime_base", getattr(raw_module, "base", getattr(raw_module, "Base", None)))
    size = getattr(raw_module, "size", getattr(raw_module, "Size", None))
    if name is None or runtime_base is None or size is None:
        raise ValueError(f"Unsupported pybag module entry: {raw_module!r}")
    return ModuleInfo(name=str(name), runtime_base=int(runtime_base), size=int(size))


def _register_query_plan(bitness: str) -> List[Tuple[str, str]]:
    if bitness == "64":
        return [
            ("RAX", "rax"),
            ("RBX", "rbx"),
            ("RCX", "rcx"),
            ("RDX", "rdx"),
            ("RSI", "rsi"),
            ("RDI", "rdi"),
            ("RSP", "rsp"),
            ("RBP", "rbp"),
            ("RIP", "rip"),
            ("R8", "r8"),
            ("R9", "r9"),
            ("R10", "r10"),
            ("R11", "r11"),
            ("R12", "r12"),
            ("R13", "r13"),
            ("R14", "r14"),
            ("R15", "r15"),
            ("EFLAGS", "efl"),
        ]
    return [
        ("EAX", "eax"),
        ("EBX", "ebx"),
        ("ECX", "ecx"),
        ("EDX", "edx"),
        ("ESI", "esi"),
        ("EDI", "edi"),
        ("ESP", "esp"),
        ("EBP", "ebp"),
        ("EIP", "eip"),
        ("EFLAGS", "efl"),
    ]


def _is_wow64_module_name(name: str) -> bool:
    normalized = name.lower()
    return normalized.startswith("wow64")


# ---------------------------------------------------------------------------
# AllDbg — combined user/kernel debugger base (from ghidradbg/util.py)
# ---------------------------------------------------------------------------

class AllDbg(pydbg.DebuggerBase):
    """Composite debugger class that borrows user-mode methods."""
    proc_list = userdbg.UserDbg.proc_list
    ps = userdbg.UserDbg.ps
    pids_by_name = userdbg.UserDbg.pids_by_name
    create_proc = userdbg.UserDbg.create
    attach_proc = userdbg.UserDbg.attach
    detach_proc = userdbg.UserDbg.detach
    terminate_proc = userdbg.UserDbg.terminate


# ---------------------------------------------------------------------------
# Threading primitives (from ghidradbg/util.py:90-186)
# ---------------------------------------------------------------------------

class _WorkItem:
    __slots__ = ("future", "fn", "args", "kwargs")

    def __init__(self, future: Future, fn: Callable, args: tuple, kwargs: dict):
        self.future = future
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self) -> None:
        try:
            result = self.fn(*self.args, **self.kwargs)
        except BaseException as exc:
            self.future.set_exception(exc)
        else:
            self.future.set_result(result)


class _Worker(threading.Thread):
    """Daemon thread that owns the dbgeng COM apartment."""

    def __init__(self, init_fn: Callable, work_queue: queue.SimpleQueue,
                 dispatch_fn: Callable):
        super().__init__(name="DbgEngWorker", daemon=True)
        self.init_fn = init_fn
        self.work_queue = work_queue
        self.dispatch_fn = dispatch_fn

    def run(self) -> None:
        self.init_fn()
        while True:
            try:
                item = self.work_queue.get_nowait()
            except queue.Empty:
                item = None
            if item is None:
                try:
                    self.dispatch_fn(100)
                except exception.DbgEngTimeout:
                    pass
            else:
                item.run()


class DebuggeeRunningException(Exception):
    pass


class WrongThreadException(Exception):
    pass


# ---------------------------------------------------------------------------
# Event callbacks
# ---------------------------------------------------------------------------

class EngineEventHandler:
    """Receives dbgeng events and forwards to registered listeners."""

    def __init__(self):
        self.on_breakpoint_hit: Optional[Callable[[int], int]] = None
        self.on_state_changed: Optional[Callable[[int, int], None]] = None
        self.on_module_loaded: Optional[Callable[[], None]] = None

    def breakpoint_handler(self, bp_id: int) -> int:
        if self.on_breakpoint_hit:
            return self.on_breakpoint_hit(bp_id)
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    def state_change_handler(self, *args) -> int:
        if len(args) >= 2 and self.on_state_changed:
            self.on_state_changed(args[0], args[1])
        return DbgEng.DEBUG_STATUS_NO_CHANGE


# ---------------------------------------------------------------------------
# DebugEngine — main API
# ---------------------------------------------------------------------------

class DebugEngine:
    """
    Wraps pybag's dbgeng with proper COM threading.

    All dbgeng operations run on a dedicated worker thread. Public methods
    are decorated with @eng_thread so callers from any thread are safe.
    """

    def __init__(self):
        self._state = DebuggerState.DETACHED
        self._target_pid: Optional[int] = None
        self._target_name: Optional[str] = None
        self._executing = False  # True when target is running
        self._is_wow64 = False
        self._protected_base: Optional[AllDbg] = None
        self._events = EngineEventHandler()
        # Anti-anti-debug: when enabled, pass first-chance exceptions (notably
        # the INT3/STATUS_BREAKPOINT flood PD2 throws) to the TARGET's own SEH
        # instead of the debugger swallowing them, so the target's handler runs
        # and it doesn't conclude a debugger is present. Off by default so
        # attach/normal debugging behave as usual.
        self._pass_exceptions = False
        self._call_guard = False   # True during an in-process call (crash-guard)
        self._call_fault = None     # exception code caught during a guarded call
        self._call_ret_catch = None  # ret_catch address during an in-process call
        self._stepping = False       # True while a single-step is in flight
        # Addresses of breakpoints WE planted, so the exception filter can tell
        # our own int3s (which dbgeng must own) from the target's anti-debug int3
        # flood (which must pass through to its SEH). _bp_id_to_addr keeps the set
        # accurate as breakpoints are removed.
        self._our_bp_addrs: set = set()
        self._bp_id_to_addr: dict = {}

        # Work queue and worker thread
        self._work_queue: queue.SimpleQueue = queue.SimpleQueue()
        self._thread = _Worker(self._init_dbgeng, self._work_queue,
                               self._dispatch_events)
        self._thread.start()

        # Wait for worker to be ready
        self._submit(lambda: None).result(timeout=10)
        logger.info("DebugEngine initialized (worker thread ready)")

    # -- Threading infrastructure ------------------------------------------

    def _init_dbgeng(self) -> None:
        """Called on the worker thread to create the dbgeng base."""
        self._protected_base = AllDbg()
        logger.info("dbgeng COM initialized on worker thread")

    def _dispatch_events(self, timeout: int = 100) -> None:
        """Pump dbgeng event callbacks (called in worker idle loop)."""
        if self._protected_base is not None:
            self._protected_base._client.DispatchCallbacks(timeout)

    @property
    def _base(self) -> AllDbg:
        """Access the dbgeng base — only from the worker thread."""
        if threading.current_thread() is not self._thread:
            raise WrongThreadException(
                f"dbgeng access from {threading.current_thread().name}, "
                f"must be {self._thread.name}")
        if self._protected_base is None:
            raise RuntimeError("dbgeng not initialized")
        return self._protected_base

    def _submit(self, fn: Callable[..., T], *args, **kwargs) -> Future[T]:
        """Submit work to the engine thread."""
        f: Future[T] = Future()
        w = _WorkItem(f, fn, args, kwargs)
        self._work_queue.put(w)
        if self._protected_base is not None:
            try:
                self._protected_base._client.ExitDispatch()
            except Exception:
                pass
        return f

    def _run_on_engine(self, fn: Callable[..., T], *args, **kwargs) -> T:
        """Submit and block until complete."""
        if threading.current_thread() is self._thread:
            return fn(*args, **kwargs)
        future = self._submit(fn, *args, **kwargs)
        while True:
            try:
                return future.result(0.5)
            except concurrent.futures.TimeoutError:
                pass

    def eng_thread(self, func: C) -> C:
        """Decorator: ensures func runs on the engine thread."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            if threading.current_thread() is self._thread:
                return func(*args, **kwargs)
            return self._run_on_engine(func, *args, **kwargs)
        return cast(C, wrapper)

    # -- Process management ------------------------------------------------

    def attach(self, target: str) -> dict:
        """Attach to a process by name or PID.

        Args:
            target: Process name (e.g. "Game.exe") or PID as string.

        Returns:
            Status dict with pid, name, module_count.
        """
        return self._run_on_engine(self._attach_impl, target)

    def _attach_impl(self, target: str) -> dict:
        if self._state not in (DebuggerState.DETACHED, DebuggerState.EXITED):
            # Already attached — detach first so re-attach is robust/idempotent
            # (fixes "Cannot attach in state stopped" and clears stale
            # breakpoint objects that otherwise E_NOINTERFACE on removal).
            logger.info(f"Already {self._state.value}; detaching before re-attach")
            try:
                self._detach_impl()
            except Exception as e:
                logger.warning(f"pre-attach detach failed (continuing): {e}")

        base = self._base
        target_name = target

        # Resolve PID
        try:
            pid = int(target)
        except ValueError:
            matches = base.pids_by_name(target)
            if not matches:
                raise RuntimeError(f"No process found matching '{target}'")
            pid = _normalize_pid_match(matches[0])
            if isinstance(matches[0], tuple) and len(matches[0]) > 1:
                target_name = os.path.basename(str(matches[0][1])) or str(matches[0][1])

        logger.info(f"Attaching to PID {pid}...")
        try:
            base.attach_proc(pid)
            raw_modules = self._wait_for_target_access_impl()
            modules = [_module_info_from_pybag_entry(mod) for mod in raw_modules]
        except Exception as exc:
            try:
                base.detach_proc()
            except Exception as detach_exc:
                logger.warning(f"Detach after failed attach raised: {detach_exc}")
            self._target_pid = None
            self._target_name = None
            self._state = DebuggerState.DETACHED
            self._executing = False
            raise RuntimeError(
                f"Attached to PID {pid} but the target never became queryable: {exc}"
            ) from exc

        self._target_pid = pid
        self._is_wow64 = self._detect_wow64_target(modules)
        self._target_name = modules[0].name if modules else target_name
        self._state = DebuggerState.STOPPED
        self._executing = False

        logger.info(f"Attached to PID {pid}, {len(modules)} modules loaded")
        return {
            "pid": pid,
            "name": self._target_name,
            "module_count": len(modules),
            "state": self._state.value,
        }

    def _wait_for_target_access_impl(self, timeout_seconds: float = 5.0) -> List[Any]:
        deadline = time.monotonic() + timeout_seconds
        last_error: Optional[Exception] = None

        while time.monotonic() < deadline:
            try:
                self._base.reg.get_pc()
                return list(self._base.module_list())
            except Exception as exc:
                last_error = exc
                time.sleep(0.05)

        if last_error is not None:
            raise last_error
        return []

    def _detect_wow64_target(self, modules: List[ModuleInfo]) -> bool:
        try:
            actual_processor = self._base._control.GetActualProcessorType()
        except Exception:
            return False
        if actual_processor != _IMAGE_FILE_MACHINE_AMD64:
            return False
        return any(_is_wow64_module_name(module.name) for module in modules)

    @contextmanager
    def _effective_processor_context(self, processor_type: Optional[int]) -> Iterator[None]:
        if processor_type is None:
            yield
            return

        control = self._base._control
        previous_type: Optional[int] = None
        changed = False
        try:
            previous_type = control.GetEffectiveProcessorType()
            if previous_type != processor_type:
                control.SetEffectiveProcessorType(processor_type)
                changed = True
            yield
        finally:
            if changed and previous_type is not None:
                control.SetEffectiveProcessorType(previous_type)

    def _wow64_x86_context(self) -> Iterator[None]:
        if self._is_wow64:
            return self._effective_processor_context(_IMAGE_FILE_MACHINE_I386)
        return nullcontext()

    def detach(self) -> dict:
        """Detach from the target process."""
        return self._run_on_engine(self._detach_impl)

    def _detach_impl(self) -> dict:
        if self._state == DebuggerState.DETACHED:
            return {"state": "detached", "message": "Already detached"}
        try:
            self._base.detach_proc()
        except Exception as e:
            logger.warning(f"Detach error (non-fatal): {e}")
        pid = self._target_pid
        self._target_pid = None
        self._target_name = None
        self._is_wow64 = False
        self._state = DebuggerState.DETACHED
        self._executing = False
        # A detached process's breakpoint objects are gone; stale addresses
        # here would misclassify a future (re-attached) process's real
        # exceptions at a reused address as "ours" in _on_exception.
        self._our_bp_addrs.clear()
        self._bp_id_to_addr.clear()
        self._call_guard = False
        self._stepping = False
        logger.info(f"Detached from PID {pid}")
        return {"state": "detached", "pid": pid}

    # -- Execution control -------------------------------------------------

    def go(self) -> dict:
        """Resume execution."""
        return self._run_on_engine(self._go_impl)

    def _go_impl(self) -> dict:
        self._require_stopped()
        self._state = DebuggerState.RUNNING
        self._executing = True
        self._base.go()
        # go() returns when the debuggee breaks again
        self._state = DebuggerState.STOPPED
        self._executing = False
        return {"state": self._state.value}

    def go_nowait(self) -> dict:
        """Resume execution without waiting for break.

        Returns immediately. Use wait_for_break() or poll status().
        """
        def _impl():
            self._require_stopped()
            self._state = DebuggerState.RUNNING
            self._executing = True
            try:
                self._base._control.SetExecutionStatus(
                    DbgEng.DEBUG_STATUS_GO)
            except Exception as e:
                self._state = DebuggerState.STOPPED
                self._executing = False
                raise
        self._run_on_engine(_impl)
        return {"state": "running"}

    def go_wait(self, timeout_ms: int = 4000) -> dict:
        """Resume execution and BLOCK until a breakpoint/event or timeout.

        Unlike go_nowait (which only sets DEBUG_STATUS_GO and relies on the
        idle DispatchCallbacks pump — that does not actually advance the
        target), this pumps WaitForEvent on the engine thread, which is what
        makes dbgeng run the debuggee and deliver breakpoint events. On timeout
        it interrupts so control is regained. Returns {state, pc, timeout?}.
        """
        return self._run_on_engine(self._go_wait_impl, timeout_ms)

    def _go_wait_impl(self, timeout_ms: int) -> dict:
        self._require_stopped()
        self._state = DebuggerState.RUNNING
        self._executing = True
        # A FINITE WaitForEvent timeout faults (AV) in non-standalone mode, and
        # the engine's single worker can't be interrupted from within its own
        # blocked wait. So run the proven infinite wait and self-bound it with a
        # timer thread that issues SetInterrupt (thread-safe, unblocks
        # WaitForEvent) — go_wait always returns within ~timeout_ms.
        bomb_state = {"timed_out": False}

        def _bomb():
            bomb_state["timed_out"] = True
            try:
                if self._protected_base is not None:
                    self._protected_base._control.SetInterrupt(
                        DbgEng.DEBUG_INTERRUPT_ACTIVE)
            except Exception:
                pass

        timer = threading.Timer(max(0.05, timeout_ms / 1000.0), _bomb)
        timer.daemon = True
        timer.start()
        try:
            self._base.go()   # SetExecutionStatus(GO) + wait(WAIT_INFINITE)
        finally:
            timer.cancel()
            self._state = DebuggerState.STOPPED
            self._executing = False
        pc = 0
        try:
            pc = self._read_pc_impl()
        except Exception:
            pass
        return {"state": "stopped", "timeout": bomb_state["timed_out"],
                "pc": f"0x{pc:08X}"}

    def interrupt(self) -> dict:
        """Break into the debugger (interrupt execution)."""
        # interrupt() can be called from any thread
        if self._protected_base is not None:
            self._protected_base._control.SetInterrupt(
                DbgEng.DEBUG_INTERRUPT_ACTIVE)
        self._state = DebuggerState.STOPPED
        self._executing = False
        return {"state": "stopped"}

    # -- Anti-anti-debug: first-chance exception pass-through ----------------

    def set_pass_exceptions(self, enabled: bool) -> dict:
        """Enable/disable handing first-chance exceptions to the target's own
        SEH instead of the debugger swallowing them. Defeats INT3-based
        anti-debug (e.g. PD2's breakpoint-exception flood)."""
        return self._run_on_engine(self._set_pass_exceptions_impl, bool(enabled))

    def _set_pass_exceptions_impl(self, enabled: bool) -> dict:
        self._pass_exceptions = enabled
        try:
            if enabled:
                self._base.events.exception(self._on_exception)
            else:
                self._base.events.noexception()
        except Exception as e:
            logger.warning(f"exception pass-through toggle failed: {e}")
        logger.info(f"Exception pass-through {'ENABLED' if enabled else 'disabled'}")
        return {"pass_exceptions": self._pass_exceptions}

    def _on_exception(self, *args):
        """dbgeng EXCEPTION-event callback. args[0]=ExceptionRecord,
        args[1]=first-chance flag.

        With pass-through ON we hand the target's own first-chance exceptions
        (notably PD2's INT3/STATUS_BREAKPOINT anti-debug flood) to its SEH so it
        can't detect us. But during OUR OWN call/step we must not pass the
        debugger's own control exceptions (a single-step trap, or a fault we want
        to crash-guard) to the target.

        STABILITY: the anti-debug INT3 flood is a HIGH-RATE stream. Touching the
        COM exception record (_exc_code/_exc_address) on every one of them churns
        comtypes interface wrappers whose __del__ Release() can access-violate on
        the GC thread and corrupt the dbgeng client (observed: a _compointer_base
        __del__ AV, then SetExecutionStatus -> 0x80070005 and a wedged worker).
        So we take a FAST PATH that never inspects the record unless we are
        actually mid-call/mid-step. Breakpoints we plant via set_breakpoint()
        (used for passive capture) are recognized dbgeng breakpoint objects,
        so a hit calls the separate BREAKPOINT event/handler, not this one —
        this fast path never needs to protect them. That specifically matches
        prior empirical behavior (passive breakpoint capture already worked
        against this WOW64 target before this filter existed, when ALL
        first-chance exceptions were passed through unconditionally), which
        is only explainable if ordinary planted breakpoints don't route
        through here. The ONE breakpoint this filter must protect is
        call_function's ret_catch, planted via an artificial EIP-hijack
        rather than normal execution — and that is covered because
        _call_guard is True for the call's entire duration, so the mid-
        call/mid-step branch below (not this fast path) always runs for it.
        CONFIRMED (2026-07-05): live-verified end to end against a genuine
        WOW64 target — a synthetic disposable process (PE machine type
        0x14C, unrelated to any specific target application) built to loop
        on kernel32!SleepEx. (1) Passive path:
        attach + pass_exceptions + set_breakpoint + go_wait reported repeated
        real hits (timeout=False, pc at the breakpoint, real WX86 exception
        codes) even though this code never calls events.breakpoint() (so
        DEBUG_EVENT_BREAKPOINT is absent from GetInterestMask) — dbgeng's own
        execution-halt-at-breakpoint is independent of whether our callback
        is subscribed to be notified; the interest mask only gates the
        notification, not the underlying stop. (2) Guarded-call path: with
        the thread stopped at that same hit breakpoint, call_function (no
        explicit ret_catch, so it defaults to the current EIP — the proven
        manual flow) returned cleanly (returned_to == ret_catch, faulted =
        False) and passive go_wait capture continued to hit afterward with
        no run-control poisoning. Both halves of this filter are now
        live-confirmed on real WOW64 exception delivery, not just reasoned
        about or tested against a native target."""
        first_chance = (len(args) < 2) or bool(args[1])
        if not first_chance:
            return DbgEng.DEBUG_STATUS_NO_CHANGE
        # Fast path: not running our own call/step -> nothing of ours to protect
        # here; pass the flood without touching the COM record.
        if not (self._call_guard or self._stepping):
            return (DbgEng.DEBUG_STATUS_GO_NOT_HANDLED
                    if self._pass_exceptions else DbgEng.DEBUG_STATUS_NO_CHANGE)
        # Mid call/step only (a bounded window): inspect minimally.
        code = self._exc_code(args)
        # single-step trap (incl. WOW64 WX86 variant) -> ours.
        if code in (0x80000004, 0x4000001E):
            return DbgEng.DEBUG_STATUS_NO_CHANGE
        # int3 (incl. WX86): ours only if it's the active call's ret_catch or a
        # breakpoint we planted; otherwise it's the flood -> pass it through.
        if code in (0x80000003, 0x4000001F):
            addr = self._exc_address(args)
            if addr is None or addr == self._call_ret_catch \
                    or addr in self._live_bp_addrs():
                return DbgEng.DEBUG_STATUS_NO_CHANGE
        # A genuine FAULT (e.g. AV 0xC0000005) inside a guarded call must break
        # into the debugger so call_function can roll back, not reach the SEH.
        elif self._call_guard:
            self._call_fault = code
            return DbgEng.DEBUG_STATUS_NO_CHANGE
        if self._pass_exceptions:
            return DbgEng.DEBUG_STATUS_GO_NOT_HANDLED
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    @staticmethod
    def _exc_code(args):
        """Best-effort extract the exception code from an dbgeng exception event's
        args (structure varies by pybag version). 0 if unknown."""
        try:
            rec = args[0]
            for attr in ("ExceptionCode", "exception_code", "code"):
                if hasattr(rec, attr):
                    return int(getattr(rec, attr)) & 0xFFFFFFFF
            if hasattr(rec, "ExceptionRecord"):
                return int(rec.ExceptionRecord.ExceptionCode) & 0xFFFFFFFF
            if isinstance(rec, dict):
                return int(rec.get("ExceptionCode", rec.get("code", 0))) & 0xFFFFFFFF
        except Exception:
            pass
        return 0

    @staticmethod
    def _exc_address(args):
        """Best-effort extract the faulting address from a dbgeng exception
        event's args (structure varies by pybag version). For an int3 breakpoint
        this is the address of the int3 byte. None if unknown."""
        try:
            rec = args[0]
            for attr in ("ExceptionAddress", "exception_address", "address"):
                if hasattr(rec, attr):
                    return int(getattr(rec, attr)) & 0xFFFFFFFF
            if hasattr(rec, "ExceptionRecord"):
                return int(rec.ExceptionRecord.ExceptionAddress) & 0xFFFFFFFF
            if isinstance(rec, dict):
                v = rec.get("ExceptionAddress", rec.get("address"))
                return None if v is None else int(v) & 0xFFFFFFFF
        except Exception:
            pass
        return None

    def step_into(self, count: int = 1) -> dict:
        """Single-step into (trace)."""
        return self._run_on_engine(self._step_into_impl, count)

    def _step_into_impl(self, count: int) -> dict:
        self._require_stopped()
        self._stepping = True
        try:
            self._base.stepi(count)
        finally:
            self._stepping = False
        return {"state": "stopped", "pc": f"0x{self._read_pc_impl():08X}"}

    def step_over(self, count: int = 1) -> dict:
        """Step over (proceed)."""
        return self._run_on_engine(self._step_over_impl, count)

    def _step_over_impl(self, count: int) -> dict:
        self._require_stopped()
        self._stepping = True
        try:
            self._base.stepo(count)
        finally:
            self._stepping = False
        return {"state": "stopped", "pc": f"0x{self._read_pc_impl():08X}"}

    # -- State inspection --------------------------------------------------

    def get_state(self) -> DebuggerState:
        return self._state

    def get_target_pid(self) -> Optional[int]:
        return self._target_pid

    def get_target_name(self) -> Optional[str]:
        return self._target_name

    def get_modules(self) -> List[ModuleInfo]:
        """Get list of loaded modules."""
        return self._run_on_engine(self._get_modules_impl)

    def _get_modules_impl(self) -> List[ModuleInfo]:
        self._require_attached()
        modules = []
        try:
            for mod in self._base.module_list():
                modules.append(_module_info_from_pybag_entry(mod))
        except Exception as e:
            logger.error(f"Error enumerating modules: {e}")
        return modules

    def get_registers(self) -> Dict[str, int]:
        """Read all general-purpose registers."""
        return self._run_on_engine(self._get_registers_impl)

    def _get_registers_impl(self) -> Dict[str, int]:
        self._require_stopped()
        return self._collect_registers_impl()

    def _collect_registers_impl(self) -> Dict[str, int]:
        regs = {}
        reg_obj = self._base.reg
        bitness = self._get_effective_bitness_impl()
        with self._wow64_x86_context():
            for result_name, query_name in _register_query_plan(bitness):
                try:
                    regs[result_name] = reg_obj._get_register(query_name)
                except Exception:
                    pass
        return regs

    def _get_effective_bitness_impl(self) -> str:
        if self._is_wow64:
            return "32"
        try:
            return self._base.bitness()
        except Exception:
            return "32"

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the target."""
        return self._run_on_engine(self._read_memory_impl, address, size)

    def _read_memory_impl(self, address: int, size: int) -> bytes:
        self._require_stopped()
        return bytes(self._base.read(address, size))

    def write_memory(self, address: int, data: bytes) -> int:
        """Write bytes to target memory. Returns number of bytes written."""
        return self._run_on_engine(self._write_memory_impl, address, data)

    def _write_memory_impl(self, address: int, data: bytes) -> int:
        self._require_stopped()
        self._base.write(address, bytes(data))
        return len(data)

    def write_registers(self, values: Dict[str, int]) -> Dict[str, int]:
        """Set one or more CPU registers. Keys are names (eax, ebp, eip, ...);
        values are ints. Used to drive controlled execution of a code fragment
        (set EIP + inputs, then step). Returns the values applied."""
        return self._run_on_engine(self._write_registers_impl, values)

    def _write_registers_impl(self, values: Dict[str, int]) -> Dict[str, int]:
        self._require_stopped()
        applied = {}
        with self._wow64_x86_context():
            for name, value in values.items():
                self._base.reg._set_register(name.lower(), int(value))
                applied[name.upper()] = int(value)
        return applied

    def read_dword(self, address: int) -> int:
        """Read a 32-bit value from memory."""
        data = self.read_memory(address, 4)
        return struct.unpack("<I", data)[0]

    def read_pointer(self, address: int) -> int:
        """Read a pointer-sized value (32-bit for x86)."""
        return self.read_dword(address)

    def get_stack_trace(self, depth: int = 20) -> List[dict]:
        """Get stack backtrace."""
        return self._run_on_engine(self._get_stack_trace_impl, depth)

    def _get_stack_trace_impl(self, depth: int) -> List[dict]:
        self._require_stopped()
        frames = []
        try:
            with self._wow64_x86_context():
                for i, frame in enumerate(self._base.backtrace_list()):
                    if i >= depth:
                        break
                    entry: dict = {
                        "level": i,
                        "instruction_offset": f"0x{frame.InstructionOffset:08X}",
                        "return_offset": f"0x{frame.ReturnOffset:08X}",
                        "stack_offset": f"0x{frame.StackOffset:08X}",
                        "frame_offset": f"0x{frame.FrameOffset:08X}",
                    }
                    try:
                        name = self._base.get_name_by_offset(frame.InstructionOffset)
                        entry["symbol"] = name
                    except Exception:
                        pass
                    frames.append(entry)
        except Exception as e:
            logger.error(f"Error reading stack trace: {e}")
        return frames

    # -- Breakpoint management ---------------------------------------------

    def call_function(self, address: int, stack_args=None, registers=None,
                      ret_catch: Optional[int] = None,
                      timeout_ms: int = 8000) -> dict:
        """Call a function IN-PROCESS by hijacking the currently-stopped thread.

        Requires the target STOPPED at a breakpoint (valid thread context). Saves
        the full context, sets up the calling convention (`stack_args` pushed
        after a return address; `registers` written for register args like
        ecx/edx/eax), runs to a return-catch breakpoint, reads the result, then
        RESTORES the saved context (also the crash safety-net). Proven on WOW64:
        writing EIP + go_wait commits the context (only single-step is blocked).

        The caller sets up any pointer-arg scratch via write_memory first and
        passes the address in `registers`/`stack_args`. Returns
        {eax, edx, returned_to, timeout, ret_catch}. Verify returned_to==ret_catch.
        """
        return self._run_on_engine(self._call_function_impl, int(address),
                                   list(stack_args or []), dict(registers or {}),
                                   ret_catch, int(timeout_ms))

    def _call_function_impl(self, address, stack_args, registers, ret_catch,
                            timeout_ms):
        # Mirrors the proven manual sequence exactly (no extra breakpoints, no
        # eflags write, no in-handler exception juggling) -- those additions
        # corrupted state and crashed the target. Recovery is the context
        # restore below; crash *prevention* is the loaded-module EIP check plus
        # calling only with valid inputs. (Catching a fault in the called code
        # before it reaches the target's SEH needs the suspend-other-threads
        # design -- a follow-up; until then, do not pass deliberately-bad args.)
        self._require_stopped()
        saved = {k.lower(): v for k, v in self._collect_registers_impl().items()}
        if "eip" not in saved or "esp" not in saved or saved["esp"] == 0:
            raise RuntimeError("no valid thread context (esp/eip == 0) -- target "
                               "not stopped at a real debug event")
        # SAFETY: refuse to set EIP outside a loaded module (executing unmapped
        # memory = guaranteed access violation). Best-effort; app-agnostic.
        try:
            mods = self._get_modules_impl()
            if mods and not any(
                    m.runtime_base <= int(address) < m.runtime_base + m.size
                    for m in mods):
                raise RuntimeError(
                    f"target 0x{int(address):08X} is not in any loaded module -- "
                    f"refusing to call (would execute unmapped memory)")
        except RuntimeError:
            raise
        except Exception:
            pass
        # ret_catch is where the called function returns and where we stop. It
        # needs an int3, so we plant a breakpoint there for the duration of the
        # call unless one of ours is already present (a second int3 at the same
        # address risks restoring a stale 0xCC on removal). Default: the current
        # stopped EIP, which in the proven manual flow already carries our bp.
        # The exception filter (_on_exception) recognises this bp/ret_catch as
        # ours and lets dbgeng stop on it instead of passing it to the target's
        # SEH -- which is what makes the return actually catch on WOW64.
        if ret_catch is None:
            ret_catch = saved["eip"]
        ret_catch = int(ret_catch)
        # build the call stack: [new_esp]=ret_catch, [+4]=arg1, [+8]=arg2, ...
        new_esp = saved["esp"] - 4 * (len(stack_args) + 1)
        self._base.write(new_esp, ret_catch.to_bytes(4, "little"))
        for i, a in enumerate(stack_args):
            self._base.write(new_esp + 4 + 4 * i,
                             (int(a) & 0xFFFFFFFF).to_bytes(4, "little"))
        temp_bp_id = None
        self._call_ret_catch = ret_catch
        self._call_fault = None
        self._call_guard = True   # arm crash-guard + "our int3" recognition
        try:
            if ret_catch not in self._our_bp_addrs:
                temp_bp_id = self._set_breakpoint_impl(
                    ret_catch, BreakpointType.SOFTWARE, False, None)
            # set register args + esp + eip, then run to the return-catch
            with self._wow64_x86_context():
                for name, val in registers.items():
                    self._base.reg._set_register(name.lower(),
                                                 int(val) & 0xFFFFFFFF)
                self._base.reg._set_register("esp", new_esp)
                self._base.reg._set_register("eip", int(address))
            res = self._go_wait_impl(timeout_ms)
            out = {k.lower(): v
                   for k, v in self._collect_registers_impl().items()}
            returned_to = out.get("eip", 0)
            fault = self._call_fault
            faulted = (returned_to != ret_catch) or bool(res.get("timeout")) \
                or fault is not None
        finally:
            self._call_guard = False
            self._call_ret_catch = None
            if temp_bp_id is not None:
                try:
                    self._remove_breakpoint_impl(temp_bp_id)
                except Exception:
                    pass
            # restore the saved context (same register set as the proven spike --
            # NO eflags), which also rolls the thread back on fault/timeout.
            with self._wow64_x86_context():
                for name in ("eax", "ebx", "ecx", "edx", "esi", "edi",
                             "esp", "ebp", "eip"):
                    if name in saved:
                        self._base.reg._set_register(name, int(saved[name]))
        return {
            "eax": f"0x{out.get('eax', 0):08X}",
            "edx": f"0x{out.get('edx', 0):08X}",
            "returned_to": f"0x{returned_to:08X}",
            "ret_catch": f"0x{ret_catch:08X}",
            "timeout": bool(res.get("timeout")),
            "faulted": bool(faulted),
            "fault_code": (f"0x{fault:08X}" if fault is not None else None),
        }

    def set_breakpoint(self, address: int,
                       bp_type: BreakpointType = BreakpointType.SOFTWARE,
                       oneshot: bool = False,
                       handler: Optional[Callable] = None) -> int:
        """Set a breakpoint. Returns the breakpoint ID."""
        return self._run_on_engine(
            self._set_breakpoint_impl, address, bp_type, oneshot, handler)

    def _set_breakpoint_impl(self, address: int, bp_type: BreakpointType,
                              oneshot: bool,
                              handler: Optional[Callable]) -> int:
        self._require_attached()
        if bp_type == BreakpointType.HARDWARE:
            # Hardware *execute* breakpoint: a DATA breakpoint with
            # DEBUG_BREAK_EXECUTE access — this is what arms a debug
            # register (DR0-DR3) instead of patching an int3 into the
            # target. Previously this branch passed DEBUG_BREAKPOINT_CODE
            # (the *software* int3 type) and only re-enabled it, so
            # type="hardware" planted an int3 that anti-debug-aware
            # targets detect and that corrupts checksummed/self-modifying
            # code regions where a HW bp was specifically requested.
            bp_id = self._base.breakpoints.set(
                expr=address,
                type=DbgEng.DEBUG_BREAKPOINT_DATA,
                size=1,
                access=DbgEng.DEBUG_BREAK_EXECUTE,
                oneshot=oneshot,
                handler=handler,
            )
        else:
            bp_id = self._base.breakpoints.set(
                expr=address,
                handler=handler,
                oneshot=oneshot,
            )
        # Record the address so the exception filter can recognise our own int3
        # (vs the target's anti-debug flood) on a WOW64 target.
        self._bp_id_to_addr[bp_id] = int(address)
        self._our_bp_addrs.add(int(address))
        logger.info(f"Breakpoint #{bp_id} set at 0x{address:08X} "
                    f"(type={bp_type.value}, oneshot={oneshot})")
        return bp_id

    def _live_bp_addrs(self) -> set:
        """Addresses of breakpoints dbgeng still actually has planted.

        `_our_bp_addrs` is a shadow set updated on set/remove, but dbgeng
        auto-drops a oneshot breakpoint's object the moment it fires — with
        no corresponding remove_breakpoint() call, so the shadow set can go
        stale and keep an address "ours" long after dbgeng forgot it. Query
        dbgeng directly here instead of trusting the shadow set; this only
        runs inside the already-narrow call/step-guarded window in
        _on_exception, not the high-rate flood path, so the extra round trip
        is cheap and safe.
        """
        addrs = set()
        try:
            for bp_id in self._base.breakpoints:
                try:
                    bp_obj = self._base._control.GetBreakpointById(bp_id)
                    addrs.add(int(bp_obj.GetOffset()) & 0xFFFFFFFF)
                except Exception:
                    continue
        except Exception:
            pass
        return addrs

    def remove_breakpoint(self, bp_id: int) -> None:
        """Remove a breakpoint by ID."""
        self._run_on_engine(self._remove_breakpoint_impl, bp_id)

    def _remove_breakpoint_impl(self, bp_id: int) -> None:
        self._require_attached()
        # Drop it from our address tracking first (only if no other bp shares the
        # address), so the set stays accurate even if the engine remove throws.
        addr = self._bp_id_to_addr.pop(bp_id, None)
        if addr is not None and addr not in self._bp_id_to_addr.values():
            self._our_bp_addrs.discard(addr)
        try:
            self._base.breakpoints.remove(bp_id)
            logger.info(f"Breakpoint #{bp_id} removed")
        except Exception as e:
            logger.error(f"Error removing breakpoint #{bp_id}: {e}")
            raise

    def set_data_breakpoint(self, address: int, size: int,
                            access: int,
                            handler: Optional[Callable] = None) -> int:
        """Set a data (hardware) breakpoint for memory access watching.

        Args:
            address: Memory address to watch.
            size: Size in bytes (1, 2, or 4 for x86).
            access: DbgEng.DEBUG_BREAK_READ, DEBUG_BREAK_WRITE, or both OR'd.
            handler: Optional callback on hit.

        Returns:
            Breakpoint ID.
        """
        return self._run_on_engine(
            self._set_data_breakpoint_impl, address, size, access, handler)

    def _set_data_breakpoint_impl(self, address: int, size: int, access: int,
                                   handler: Optional[Callable]) -> int:
        self._require_attached()
        bp_id = self._base.breakpoints.set(
            expr=address,
            type=DbgEng.DEBUG_BREAKPOINT_DATA,
            size=size,
            access=access,
            handler=handler,
        )
        logger.info(f"Data breakpoint #{bp_id} at 0x{address:08X} "
                    f"(size={size}, access=0x{access:X})")
        return bp_id

    def list_breakpoints(self) -> List[dict]:
        """List all active breakpoints."""
        return self._run_on_engine(self._list_breakpoints_impl)

    def _list_breakpoints_impl(self) -> List[dict]:
        self._require_attached()
        result = []
        for bp_id in self._base.breakpoints:
            try:
                bp_obj = self._base._control.GetBreakpointById(bp_id)
                offset = bp_obj.GetOffset()
                flags = bp_obj.GetFlags()
                bp_type = bp_obj.GetType()
                result.append({
                    "id": bp_id,
                    "address": f"0x{offset:08X}",
                    "enabled": bool(flags & DbgEng.DEBUG_BREAKPOINT_ENABLED),
                    "oneshot": bool(flags & DbgEng.DEBUG_BREAKPOINT_ONE_SHOT),
                    "type": "data" if bp_type[0] == DbgEng.DEBUG_BREAKPOINT_DATA else "code",
                })
            except Exception as e:
                result.append({"id": bp_id, "error": str(e)})
        return result

    # -- Helpers -----------------------------------------------------------

    def _require_attached(self) -> None:
        if self._state == DebuggerState.DETACHED:
            raise RuntimeError("Not attached to any process")

    def _require_stopped(self) -> None:
        self._require_attached()
        if self._state == DebuggerState.RUNNING:
            raise RuntimeError("Target is running — interrupt first")

    def get_pc(self) -> int:
        """Get current program counter."""
        return self._run_on_engine(self._read_pc_impl)

    def get_sp(self) -> int:
        """Get current stack pointer."""
        return self._run_on_engine(self._read_sp_impl)

    def _read_pc_impl(self) -> int:
        with self._wow64_x86_context():
            return self._base.reg.get_pc()

    def _read_sp_impl(self) -> int:
        with self._wow64_x86_context():
            return self._base.reg.get_sp()

    def resolve_symbol(self, address: int) -> Optional[str]:
        """Try to resolve an address to a symbol name."""
        try:
            return self._run_on_engine(
                lambda: self._base.get_name_by_offset(address))
        except Exception:
            return None

    def find_pids_by_name(self, name: str) -> List[int]:
        """Find process IDs by executable name."""
        return self._run_on_engine(lambda: self._base.pids_by_name(name))
