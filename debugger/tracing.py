"""
Non-breaking function tracing engine.

Sets breakpoints with Python handlers that log arguments and return
DEBUG_STATUS_GO_HANDLED to auto-resume execution without stopping the game.

This is critical for Diablo 2 RE — the game loop runs at 25fps (40ms ticks),
and stopping on every call to a hot function would freeze gameplay.
"""

from __future__ import annotations

import collections
import logging
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from pybag.dbgeng import core as DbgEng  # type: ignore

from .engine import DebugEngine
from .address_map import AddressMapper
from .d2.conventions import read_args, read_return_address
from .protocol import TraceEntry, TracePointInfo, WatchHit

logger = logging.getLogger(__name__)

# Maximum entries in the trace log ring buffer
MAX_LOG_SIZE = 10_000
MAX_WATCH_LOG_SIZE = 5_000


@dataclass
class _ActiveTrace:
    """Internal state for an active function trace."""
    trace_id: int
    ghidra_address: int
    runtime_address: int
    module: str
    convention: str
    arg_count: int
    arg_names: Optional[List[str]]
    capture_return: bool
    max_hits: int
    bp_id: int  # pybag breakpoint ID
    hit_count: int = 0
    active: bool = True


@dataclass
class _ActiveWatch:
    """Internal state for an active data watchpoint."""
    watch_id: int
    ghidra_address: int
    runtime_address: int
    module: str
    size: int
    access: str
    bp_id: int  # pybag breakpoint ID
    hit_count: int = 0
    active: bool = True


class TraceSession:
    """Manages non-breaking function traces and data watchpoints."""

    def __init__(self, engine: DebugEngine, mapper: AddressMapper):
        self._engine = engine
        self._mapper = mapper
        self._next_trace_id = 0
        self._next_watch_id = 0
        self._traces: Dict[int, _ActiveTrace] = {}
        self._watches: Dict[int, _ActiveWatch] = {}
        self._log: collections.deque[TraceEntry] = collections.deque(maxlen=MAX_LOG_SIZE)
        self._watch_log: collections.deque[WatchHit] = collections.deque(maxlen=MAX_WATCH_LOG_SIZE)
        self._lock = threading.Lock()

    # -- Function tracing --------------------------------------------------

    def add_function_trace(
        self,
        ghidra_address: int,
        module: str,
        convention: str = "__stdcall",
        arg_count: int = 4,
        arg_names: Optional[List[str]] = None,
        capture_return: bool = False,
        max_hits: int = 0,
    ) -> int:
        """Start a non-breaking trace on a function.

        On each call: logs timestamp, args, caller return address.
        The handler returns DEBUG_STATUS_GO_HANDLED to auto-resume.

        Args:
            ghidra_address: Function address in Ghidra.
            module: DLL name for address resolution.
            convention: __stdcall, __fastcall, __thiscall, __cdecl.
            arg_count: Number of arguments to capture.
            arg_names: Optional names for readability.
            capture_return: Also capture EAX at function return.
            max_hits: Stop after N hits (0 = unlimited).

        Returns:
            Trace ID.
        """
        runtime_addr = self._mapper.to_runtime(ghidra_address, module or None)

        trace_id = self._next_trace_id
        self._next_trace_id += 1

        trace = _ActiveTrace(
            trace_id=trace_id,
            ghidra_address=ghidra_address,
            runtime_address=runtime_addr,
            module=module,
            convention=convention,
            arg_count=arg_count,
            arg_names=arg_names,
            capture_return=capture_return,
            max_hits=max_hits,
            bp_id=-1,
        )

        # Build the breakpoint handler — runs on the dbgeng engine thread
        def _on_entry(bp) -> int:
            if not trace.active:
                return DbgEng.DEBUG_STATUS_GO_HANDLED

            try:
                base = self._engine._protected_base
                if base is None:
                    return DbgEng.DEBUG_STATUS_GO_HANDLED

                regs = self._engine._collect_registers_impl()

                args = read_args(regs, lambda a: struct.unpack("<I", base.read(a, 4))[0],
                                 convention, arg_count)
                caller = struct.unpack("<I", base.read(regs["ESP"], 4))[0]

                # Map caller to Ghidra address
                caller_ghidra = None
                caller_symbol = None
                mapped = self._mapper.try_to_ghidra(caller)
                if mapped:
                    caller_ghidra = mapped[1]
                try:
                    caller_symbol = base.get_name_by_offset(caller)
                except Exception:
                    pass

                entry = TraceEntry(
                    timestamp=time.monotonic(),
                    trace_id=trace_id,
                    ghidra_address=ghidra_address,
                    module=module,
                    args=args,
                    arg_names=arg_names,
                    caller=caller,
                    caller_ghidra=caller_ghidra,
                    caller_symbol=caller_symbol,
                )

                self._log.append(entry)
                trace.hit_count += 1

                # Check max hits
                if trace.max_hits > 0 and trace.hit_count >= trace.max_hits:
                    trace.active = False
                    logger.info(f"Trace #{trace_id} reached max_hits={trace.max_hits}")

            except Exception as e:
                logger.error(f"Trace #{trace_id} handler error: {e}")

            return DbgEng.DEBUG_STATUS_GO_HANDLED

        # Set the breakpoint via the engine
        bp_id = self._engine.set_breakpoint(
            runtime_addr,
            handler=_on_entry,
        )
        trace.bp_id = bp_id

        with self._lock:
            self._traces[trace_id] = trace

        logger.info(
            f"Trace #{trace_id} started: 0x{ghidra_address:08X} ({module}) "
            f"[{convention}, {arg_count} args, "
            f"capture_return={capture_return}, max_hits={max_hits}]")
        return trace_id

    def stop_trace(self, trace_id: int) -> None:
        """Stop a specific trace."""
        with self._lock:
            trace = self._traces.get(trace_id)
            if trace is None:
                return
            trace.active = False

        try:
            self._engine.remove_breakpoint(trace.bp_id)
        except Exception as e:
            logger.warning(f"Error removing trace BP: {e}")

        logger.info(f"Trace #{trace_id} stopped ({trace.hit_count} hits)")

    def stop_all(self) -> int:
        """Stop all traces and watches. Returns count stopped."""
        count = 0
        with self._lock:
            trace_ids = list(self._traces.keys())
            watch_ids = list(self._watches.keys())

        for tid in trace_ids:
            self.stop_trace(tid)
            count += 1
        for wid in watch_ids:
            self.stop_watch(wid)
            count += 1
        return count

    def get_log(self, trace_id: int = -1, last_n: int = 50) -> List[TraceEntry]:
        """Get trace log entries.

        Args:
            trace_id: Filter by trace ID, or -1 for all.
            last_n: Number of most recent entries.
        """
        entries = list(self._log)
        if trace_id >= 0:
            entries = [e for e in entries if e.trace_id == trace_id]
        return entries[-last_n:]

    def list_traces(self) -> List[TracePointInfo]:
        """List all trace points with status."""
        result = []
        with self._lock:
            for trace in self._traces.values():
                result.append(TracePointInfo(
                    trace_id=trace.trace_id,
                    ghidra_address=trace.ghidra_address,
                    module=trace.module,
                    convention=trace.convention,
                    arg_count=trace.arg_count,
                    arg_names=trace.arg_names,
                    capture_return=trace.capture_return,
                    max_hits=trace.max_hits,
                    hit_count=trace.hit_count,
                    active=trace.active,
                ))
        return result

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._traces.values() if t.active)

    # -- Data watchpoints --------------------------------------------------

    def add_data_watch(
        self,
        ghidra_address: int,
        module: str,
        size: int = 4,
        access: str = "write",
    ) -> int:
        """Set a hardware watchpoint on a memory range.

        Limited to 4 simultaneous watchpoints (x86 DR0-DR3).

        Args:
            ghidra_address: Start address in Ghidra.
            module: DLL name for resolution.
            size: Bytes to watch (1, 2, or 4).
            access: "read", "write", or "readwrite".

        Returns:
            Watch ID.
        """
        # Check limit
        active_watches = sum(1 for w in self._watches.values() if w.active)
        if active_watches >= 4:
            raise RuntimeError(
                "x86 hardware breakpoint limit reached (4 max). "
                "Stop an existing watchpoint first.")

        runtime_addr = self._mapper.to_runtime(ghidra_address, module or None)

        watch_id = self._next_watch_id
        self._next_watch_id += 1

        watch = _ActiveWatch(
            watch_id=watch_id,
            ghidra_address=ghidra_address,
            runtime_address=runtime_addr,
            module=module,
            size=size,
            access=access,
            bp_id=-1,
        )

        # Map access string to dbgeng flags
        access_flags = DbgEng.DEBUG_BREAK_WRITE
        if access == "read":
            access_flags = DbgEng.DEBUG_BREAK_READ
        elif access == "readwrite":
            access_flags = DbgEng.DEBUG_BREAK_READ | DbgEng.DEBUG_BREAK_WRITE

        def _on_watch_hit(bp) -> int:
            if not watch.active:
                return DbgEng.DEBUG_STATUS_GO_HANDLED

            try:
                base = self._engine._protected_base
                if base is None:
                    return DbgEng.DEBUG_STATUS_GO_HANDLED

                pc = self._engine._read_pc_impl()

                # Read the watched value
                value = None
                try:
                    data = base.read(runtime_addr, size)
                    if size == 1:
                        value = data[0]
                    elif size == 2:
                        value = struct.unpack("<H", data)[0]
                    elif size == 4:
                        value = struct.unpack("<I", data)[0]
                except Exception:
                    pass

                # Map accessor to Ghidra
                accessor_ghidra = None
                accessor_symbol = None
                mapped = self._mapper.try_to_ghidra(pc)
                if mapped:
                    accessor_ghidra = mapped[1]
                try:
                    accessor_symbol = base.get_name_by_offset(pc)
                except Exception:
                    pass

                hit = WatchHit(
                    timestamp=time.monotonic(),
                    watch_id=watch_id,
                    address=runtime_addr,
                    ghidra_address=ghidra_address,
                    size=size,
                    access=access,
                    value=value,
                    accessor_address=pc,
                    accessor_ghidra=accessor_ghidra,
                    accessor_symbol=accessor_symbol,
                )
                self._watch_log.append(hit)
                watch.hit_count += 1

            except Exception as e:
                logger.error(f"Watch #{watch_id} handler error: {e}")

            return DbgEng.DEBUG_STATUS_GO_HANDLED

        bp_id = self._engine.set_data_breakpoint(
            runtime_addr, size, access_flags, handler=_on_watch_hit)
        watch.bp_id = bp_id

        with self._lock:
            self._watches[watch_id] = watch

        logger.info(
            f"Watch #{watch_id} set at 0x{ghidra_address:08X} ({module}) "
            f"[size={size}, access={access}]")
        return watch_id

    def stop_watch(self, watch_id: int) -> None:
        """Stop a specific watchpoint."""
        with self._lock:
            watch = self._watches.get(watch_id)
            if watch is None:
                return
            watch.active = False

        try:
            self._engine.remove_breakpoint(watch.bp_id)
        except Exception as e:
            logger.warning(f"Error removing watch BP: {e}")

        logger.info(f"Watch #{watch_id} stopped ({watch.hit_count} hits)")

    def stop_all_watches(self) -> int:
        """Stop all watchpoints. Returns count stopped."""
        count = 0
        with self._lock:
            watch_ids = list(self._watches.keys())
        for wid in watch_ids:
            self.stop_watch(wid)
            count += 1
        return count

    def get_watch_log(self, watch_id: int = -1, last_n: int = 50) -> List[WatchHit]:
        """Get watchpoint hit log."""
        entries = list(self._watch_log)
        if watch_id >= 0:
            entries = [e for e in entries if e.watch_id == watch_id]
        return entries[-last_n:]

    def watch_count(self) -> int:
        with self._lock:
            return sum(1 for w in self._watches.values() if w.active)
