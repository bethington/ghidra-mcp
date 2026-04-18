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
from concurrent.futures import Future
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, cast

from pybag import pydbg, userdbg  # type: ignore
from pybag.dbgeng import core as DbgEng  # type: ignore
from pybag.dbgeng import exception  # type: ignore

from .protocol import BreakpointInfo, BreakpointType, DebuggerState, ModuleInfo

logger = logging.getLogger(__name__)

T = TypeVar("T")
C = TypeVar("C", bound=Callable[..., Any])


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
        self._protected_base: Optional[AllDbg] = None
        self._events = EngineEventHandler()

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
            raise RuntimeError(f"Cannot attach in state {self._state.value}")

        base = self._base

        # Resolve PID
        try:
            pid = int(target)
        except ValueError:
            pids = base.pids_by_name(target)
            if not pids:
                raise RuntimeError(f"No process found matching '{target}'")
            pid = pids[0]

        logger.info(f"Attaching to PID {pid}...")
        base.attach_proc(pid)

        # Wait for initial break
        try:
            base.wait(timeout=10000)
        except exception.DbgEngTimeout:
            logger.warning("Timeout waiting for initial break, continuing anyway")

        self._target_pid = pid
        try:
            self._target_name = base.get_name_by_offset(base.reg.get_pc())
        except Exception:
            self._target_name = target
        self._state = DebuggerState.STOPPED

        modules = self._get_modules_impl()
        logger.info(f"Attached to PID {pid}, {len(modules)} modules loaded")
        return {
            "pid": pid,
            "name": self._target_name,
            "module_count": len(modules),
            "state": self._state.value,
        }

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
        self._state = DebuggerState.DETACHED
        self._executing = False
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

    def interrupt(self) -> dict:
        """Break into the debugger (interrupt execution)."""
        # interrupt() can be called from any thread
        if self._protected_base is not None:
            self._protected_base._control.SetInterrupt(
                DbgEng.DEBUG_INTERRUPT_ACTIVE)
        self._state = DebuggerState.STOPPED
        self._executing = False
        return {"state": "stopped"}

    def step_into(self, count: int = 1) -> dict:
        """Single-step into (trace)."""
        return self._run_on_engine(self._step_into_impl, count)

    def _step_into_impl(self, count: int) -> dict:
        self._require_stopped()
        self._base.stepi(count)
        return {"state": "stopped", "pc": f"0x{self._base.reg.get_pc():08X}"}

    def step_over(self, count: int = 1) -> dict:
        """Step over (proceed)."""
        return self._run_on_engine(self._step_over_impl, count)

    def _step_over_impl(self, count: int) -> dict:
        self._require_stopped()
        self._base.stepo(count)
        return {"state": "stopped", "pc": f"0x{self._base.reg.get_pc():08X}"}

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
                modules.append(ModuleInfo(
                    name=mod.name,
                    runtime_base=mod.base,
                    size=mod.size,
                ))
        except Exception as e:
            logger.error(f"Error enumerating modules: {e}")
        return modules

    def get_registers(self) -> Dict[str, int]:
        """Read all general-purpose registers."""
        return self._run_on_engine(self._get_registers_impl)

    def _get_registers_impl(self) -> Dict[str, int]:
        self._require_stopped()
        regs = {}
        reg_obj = self._base.reg
        # x86 general-purpose registers
        for name in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI",
                      "ESP", "EBP", "EIP"]:
            try:
                val = reg_obj._get_register(name)
                regs[name] = val
            except Exception:
                pass
        # Flags
        try:
            regs["EFLAGS"] = reg_obj._get_register("efl")
        except Exception:
            pass
        return regs

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the target."""
        return self._run_on_engine(self._read_memory_impl, address, size)

    def _read_memory_impl(self, address: int, size: int) -> bytes:
        self._require_stopped()
        return bytes(self._base.read(address, size))

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
            bp_id = self._base.breakpoints.set(
                expr=address,
                type=DbgEng.DEBUG_BREAKPOINT_CODE,
                oneshot=oneshot,
                handler=handler,
            )
            # For HW exec, convert to hardware after creation
            try:
                bp_obj = self._base._control.GetBreakpointById(bp_id)
                bp_obj.AddFlags(DbgEng.DEBUG_BREAKPOINT_ENABLED)
            except Exception:
                pass
        else:
            bp_id = self._base.breakpoints.set(
                expr=address,
                handler=handler,
                oneshot=oneshot,
            )
        logger.info(f"Breakpoint #{bp_id} set at 0x{address:08X} "
                    f"(type={bp_type.value}, oneshot={oneshot})")
        return bp_id

    def remove_breakpoint(self, bp_id: int) -> None:
        """Remove a breakpoint by ID."""
        self._run_on_engine(self._remove_breakpoint_impl, bp_id)

    def _remove_breakpoint_impl(self, bp_id: int) -> None:
        self._require_attached()
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
        return self._run_on_engine(lambda: self._base.reg.get_pc())

    def get_sp(self) -> int:
        """Get current stack pointer."""
        return self._run_on_engine(lambda: self._base.reg.get_sp())

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
