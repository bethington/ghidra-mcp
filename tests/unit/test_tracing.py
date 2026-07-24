"""
Unit tests for debugger/tracing.py -- the non-breaking trace/watch engine.

tracing.py had NO dedicated test file and sat at 26% coverage, despite being
the piece of the debugger with the tightest correctness requirement in the
whole subsystem: its breakpoint handlers run ON the dbgeng engine thread while
Diablo 2's 25fps game loop is live. Two invariants matter more than anything
the handler actually logs:

  1. Every handler path -- including the error paths -- must return
     DEBUG_STATUS_GO_HANDLED so the target auto-resumes. A handler that fell
     through to "stopped" (or let an exception escape) freezes the game.
  2. A handler must never raise into dbgeng.

Both are asserted directly below, alongside the argument/caller decoding, the
max_hits cutoff, the x86 4-watchpoint hardware limit, and the stop/cleanup
paths.

Everything runs offline with a fake engine + fake address mapper. pybag is not
installed on CI (or on the dev box), so the module's `from pybag.dbgeng import
core as DbgEng` is satisfied by the same stub pattern used in
test_debugger_engine.py / test_debugger_server.py.
"""

from __future__ import annotations

import struct
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# pybag stub -- must be installed before ANY debugger.* import.
# Mirrors test_debugger_server.py::_install_pybag_stubs, plus the three
# constants only tracing.py reads (DEBUG_STATUS_GO_HANDLED, DEBUG_BREAK_WRITE,
# DEBUG_BREAK_READ). Distinct bit values so the read/write/readwrite mapping
# test can tell an OR from a copy.
# ---------------------------------------------------------------------------


def _install_pybag_stubs():
    for name in list(sys.modules):
        if name.startswith("pybag") or name.startswith("debugger"):
            del sys.modules[name]

    fake_pybag = types.ModuleType("pybag")
    fake_pydbg = types.ModuleType("pybag.pydbg")

    class FakeDebuggerBase:
        pass

    fake_pydbg.DebuggerBase = FakeDebuggerBase

    fake_userdbg = types.ModuleType("pybag.userdbg")

    class FakeUserDbg:
        def proc_list(self):
            return []

        def ps(self):
            return []

        def pids_by_name(self, _name):
            return []

        def create(self, *args, **kwargs):
            return None

        def attach(self, *args, **kwargs):
            return None

        def detach(self, *args, **kwargs):
            return None

        def terminate(self, *args, **kwargs):
            return None

    fake_userdbg.UserDbg = FakeUserDbg

    fake_dbgeng = types.ModuleType("pybag.dbgeng")
    fake_core = types.ModuleType("pybag.dbgeng.core")
    fake_core.DEBUG_INTERRUPT_ACTIVE = 1
    fake_core.DEBUG_STATUS_GO = 2
    fake_core.DEBUG_BREAKPOINT_CODE = 3
    fake_core.DEBUG_BREAKPOINT_ENABLED = 4
    fake_core.DEBUG_BREAKPOINT_ONE_SHOT = 8
    fake_core.DEBUG_BREAKPOINT_DATA = 16
    fake_core.DEBUG_STATUS_NO_CHANGE = 0
    fake_core.DEBUG_STATUS_GO_NOT_HANDLED = 2
    fake_core.DEBUG_STATUS_GO_HANDLED = 5
    fake_core.DEBUG_BREAK_EXECUTE = 0x04
    fake_core.DEBUG_BREAK_READ = 0x08
    fake_core.DEBUG_BREAK_WRITE = 0x10

    fake_exception = types.ModuleType("pybag.dbgeng.exception")

    class FakeDbgEngTimeout(Exception):
        pass

    fake_exception.DbgEngTimeout = FakeDbgEngTimeout

    fake_pybag.pydbg = fake_pydbg
    fake_pybag.userdbg = fake_userdbg
    fake_pybag.dbgeng = fake_dbgeng
    fake_dbgeng.core = fake_core
    fake_dbgeng.exception = fake_exception

    sys.modules["pybag"] = fake_pybag
    sys.modules["pybag.pydbg"] = fake_pydbg
    sys.modules["pybag.userdbg"] = fake_userdbg
    sys.modules["pybag.dbgeng"] = fake_dbgeng
    sys.modules["pybag.dbgeng.core"] = fake_core
    sys.modules["pybag.dbgeng.exception"] = fake_exception

    return fake_core


DbgEng = _install_pybag_stubs()

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from debugger import tracing  # noqa: E402
from debugger.tracing import TraceSession  # noqa: E402

GO_HANDLED = DbgEng.DEBUG_STATUS_GO_HANDLED


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------

# Arbitrary but fixed: runtime = ghidra + SLIDE, as if the DLL relocated.
SLIDE = 0x01000000


class FakeMapper:
    """Stand-in for AddressMapper.

    `unmappable` lets a test exercise the "caller/accessor address is outside
    every known module" branch (try_to_ghidra -> None), which is the normal
    case for a caller inside an un-imported system DLL.
    """

    def __init__(self, known_modules=("D2Game.dll",), unmappable=()):
        self.known_modules = set(known_modules)
        self.unmappable = set(unmappable)
        self.to_runtime_calls = []

    def to_runtime(self, ghidra_addr: int, module=None) -> int:
        self.to_runtime_calls.append((ghidra_addr, module))
        if module is not None and module not in self.known_modules:
            raise ValueError(f"Module '{module}' not in address map")
        return ghidra_addr + SLIDE

    def try_to_ghidra(self, runtime_addr: int):
        if runtime_addr in self.unmappable:
            return None
        return ("D2Game.dll", runtime_addr - SLIDE)


class FakeBase:
    """Stand-in for the pybag debugger base object.

    Memory is a {address: dword} map; reads of unknown addresses return zero
    so tests only have to declare the words they care about.
    """

    def __init__(self, memory=None, symbols=None, read_fails_at=()):
        self.memory = dict(memory or {})
        self.symbols = dict(symbols or {})
        self.read_fails_at = set(read_fails_at)

    def read(self, addr: int, size: int) -> bytes:
        if addr in self.read_fails_at:
            raise OSError(f"unreadable memory at 0x{addr:08X}")
        return struct.pack("<I", self.memory.get(addr, 0))[:size]

    def get_name_by_offset(self, addr: int) -> str:
        if addr not in self.symbols:
            raise ValueError("no symbol")
        return self.symbols[addr]


class FakeEngine:
    """Stand-in for DebugEngine.

    Captures the handlers TraceSession installs so tests can invoke them
    directly -- that is the only way to exercise the on-hit code without a live
    dbgeng event loop.
    """

    def __init__(self, base=None, registers=None, pc=0, remove_error=None):
        self._protected_base = base
        # An Exception instance may be passed instead of a value to make the
        # corresponding read fail, exercising the handler's error arm.
        self.registers = registers if isinstance(registers, Exception) else dict(registers or {})
        self.pc = pc
        self.remove_error = remove_error
        self.code_breakpoints = {}  # bp_id -> (address, handler)
        self.data_breakpoints = {}  # bp_id -> (address, size, access, handler)
        self.removed = []
        self._next_bp_id = 100

    def _collect_registers_impl(self):
        if isinstance(self.registers, Exception):
            raise self.registers
        return dict(self.registers)

    def _read_pc_impl(self):
        if isinstance(self.pc, Exception):
            raise self.pc
        return self.pc

    def set_breakpoint(self, address, handler=None):
        bp_id = self._next_bp_id
        self._next_bp_id += 1
        self.code_breakpoints[bp_id] = (address, handler)
        return bp_id

    def set_data_breakpoint(self, address, size, access, handler=None):
        bp_id = self._next_bp_id
        self._next_bp_id += 1
        self.data_breakpoints[bp_id] = (address, size, access, handler)
        return bp_id

    def remove_breakpoint(self, bp_id):
        if self.remove_error is not None:
            raise self.remove_error
        self.removed.append(bp_id)

    # -- test helpers ----------------------------------------------------

    def fire(self, bp_id, times=1):
        """Invoke an installed handler as dbgeng would. Returns the last status."""
        handler = (self.code_breakpoints.get(bp_id) or self.data_breakpoints.get(bp_id))[-1]
        status = None
        for _ in range(times):
            status = handler(object())
        return status


def make_session(engine=None, mapper=None):
    engine = engine or FakeEngine(base=FakeBase(), registers={"ESP": 0x200000})
    mapper = mapper or FakeMapper()
    return TraceSession(engine, mapper), engine, mapper


# ---------------------------------------------------------------------------
# add_function_trace
# ---------------------------------------------------------------------------


class TestAddFunctionTrace:
    def test_breakpoint_is_set_at_the_mapped_runtime_address(self):
        """Ghidra addresses are static; the live process is relocated. A trace
        set at the un-slid address would break on whatever code happens to sit
        there, so the mapper translation is the load-bearing step."""
        session, engine, mapper = make_session()

        trace_id = session.add_function_trace(0x6FAA1000, "D2Game.dll")

        assert trace_id == 0
        assert mapper.to_runtime_calls == [(0x6FAA1000, "D2Game.dll")]
        (address, handler), = engine.code_breakpoints.values()
        assert address == 0x6FAA1000 + SLIDE
        assert callable(handler)

    def test_empty_module_is_passed_as_none_for_auto_detection(self):
        """AddressMapper.to_runtime(module=None) auto-detects the owning module;
        an empty string would be looked up as a literal module name and raise."""
        session, _engine, mapper = make_session()

        session.add_function_trace(0x6FAA1000, "")

        assert mapper.to_runtime_calls == [(0x6FAA1000, None)]

    def test_trace_ids_are_unique_and_monotonic(self):
        session, _engine, _mapper = make_session()

        ids = [session.add_function_trace(0x6FAA1000 + i, "D2Game.dll") for i in range(3)]

        assert ids == [0, 1, 2]

    def test_unknown_module_propagates_the_mapper_error(self):
        """Failing loudly beats silently tracing address 0 -- the caller (the
        HTTP layer) turns this into a 400 telling the user to attach first."""
        session, engine, _mapper = make_session(mapper=FakeMapper(known_modules=()))

        with pytest.raises(ValueError, match="not in address map"):
            session.add_function_trace(0x6FAA1000, "Nope.dll")

        assert engine.code_breakpoints == {}, "breakpoint set despite mapping failure"

    def test_list_traces_reports_configuration_and_hit_count(self):
        session, engine, _mapper = make_session(
            engine=FakeEngine(base=FakeBase(), registers={"ESP": 0x200000, "ECX": 7})
        )
        trace_id = session.add_function_trace(
            0x6FAA1000,
            "D2Game.dll",
            convention="__thiscall",
            arg_count=1,
            arg_names=["pUnit"],
            capture_return=True,
            max_hits=5,
        )
        bp_id = next(iter(engine.code_breakpoints))
        engine.fire(bp_id, times=2)

        info, = session.list_traces()

        assert info.trace_id == trace_id
        assert info.ghidra_address == 0x6FAA1000
        assert info.module == "D2Game.dll"
        assert info.convention == "__thiscall"
        assert info.arg_count == 1
        assert info.arg_names == ["pUnit"]
        assert info.capture_return is True
        assert info.max_hits == 5
        assert info.hit_count == 2
        assert info.active is True

    def test_active_count_tracks_stopped_traces(self):
        session, _engine, _mapper = make_session()
        first = session.add_function_trace(0x6FAA1000, "D2Game.dll")
        session.add_function_trace(0x6FAA2000, "D2Game.dll")

        assert session.active_count() == 2
        session.stop_trace(first)
        assert session.active_count() == 1


# ---------------------------------------------------------------------------
# The on-entry handler -- the code that runs inside the live game loop.
# ---------------------------------------------------------------------------


class TestTraceHandler:
    def _session_with_stack(self, convention="__stdcall", arg_count=2, **kwargs):
        base = FakeBase(
            memory={
                0x200000: 0x6FC01234,  # [ESP] = caller return address
                0x200004: 0x00000011,  # arg 1
                0x200008: 0x00000022,  # arg 2
            },
            symbols={0x6FC01234: "D2Client!Foo+0x10"},
        )
        engine = FakeEngine(
            base=base, registers={"ESP": 0x200000, "ECX": 0xC1, "EDX": 0xD2}
        )
        session, engine, mapper = make_session(engine=engine)
        session.add_function_trace(
            0x6FAA1000,
            "D2Game.dll",
            convention=convention,
            arg_count=arg_count,
            **kwargs,
        )
        return session, engine, next(iter(engine.code_breakpoints))

    def test_hit_logs_args_caller_and_auto_resumes(self):
        session, engine, bp_id = self._session_with_stack(arg_names=["a", "b"])

        status = engine.fire(bp_id)

        assert status == GO_HANDLED, "handler did not auto-resume -- game would freeze"
        entry, = session.get_log()
        assert entry.trace_id == 0
        assert entry.ghidra_address == 0x6FAA1000
        assert entry.module == "D2Game.dll"
        assert entry.args == [0x11, 0x22]
        assert entry.arg_names == ["a", "b"]
        assert entry.caller == 0x6FC01234
        assert entry.caller_ghidra == 0x6FC01234 - SLIDE
        assert entry.caller_symbol == "D2Client!Foo+0x10"
        assert entry.timestamp > 0

    def test_fastcall_reads_args_from_ecx_edx(self):
        """Convention routing is what makes a trace's args meaningful; a
        __fastcall traced as __stdcall silently logs stack garbage."""
        session, engine, bp_id = self._session_with_stack(convention="__fastcall")

        engine.fire(bp_id)

        entry, = session.get_log()
        assert entry.args == [0xC1, 0xD2]

    def test_unresolvable_caller_symbol_leaves_the_field_none(self):
        base = FakeBase(memory={0x200000: 0x6FC01234}, symbols={})
        engine = FakeEngine(base=base, registers={"ESP": 0x200000})
        session, engine, _mapper = make_session(engine=engine)
        session.add_function_trace(0x6FAA1000, "D2Game.dll", arg_count=0)
        bp_id = next(iter(engine.code_breakpoints))

        status = engine.fire(bp_id)

        entry, = session.get_log()
        assert status == GO_HANDLED
        assert entry.caller_symbol is None
        assert entry.caller == 0x6FC01234

    def test_caller_outside_known_modules_leaves_ghidra_address_none(self):
        base = FakeBase(memory={0x200000: 0x77001234})
        engine = FakeEngine(base=base, registers={"ESP": 0x200000})
        mapper = FakeMapper(unmappable={0x77001234})
        session, engine, _mapper = make_session(engine=engine, mapper=mapper)
        session.add_function_trace(0x6FAA1000, "D2Game.dll", arg_count=0)

        engine.fire(next(iter(engine.code_breakpoints)))

        entry, = session.get_log()
        assert entry.caller == 0x77001234
        assert entry.caller_ghidra is None

    def test_detached_engine_resumes_without_logging(self):
        """_protected_base goes None when the target exits. Touching it would
        raise inside the engine thread; the handler must bail out cleanly."""
        engine = FakeEngine(base=None, registers={"ESP": 0x200000})
        session, engine, _mapper = make_session(engine=engine)
        session.add_function_trace(0x6FAA1000, "D2Game.dll")

        status = engine.fire(next(iter(engine.code_breakpoints)))

        assert status == GO_HANDLED
        assert session.get_log() == []

    def test_handler_swallows_errors_and_still_resumes(self):
        """An exception escaping into dbgeng leaves the target suspended. Any
        failure while decoding must degrade to "no log entry", never a raise."""
        engine = FakeEngine(base=FakeBase(), registers=RuntimeError("register read failed"))
        session, engine, _mapper = make_session(engine=engine)
        session.add_function_trace(0x6FAA1000, "D2Game.dll")

        status = engine.fire(next(iter(engine.code_breakpoints)))

        assert status == GO_HANDLED
        assert session.get_log() == []
        info, = session.list_traces()
        assert info.hit_count == 0

    def test_max_hits_stops_logging_after_the_budget(self):
        session, engine, bp_id = self._session_with_stack(max_hits=2)

        for _ in range(5):
            assert engine.fire(bp_id) == GO_HANDLED

        assert len(session.get_log()) == 2
        info, = session.list_traces()
        assert info.hit_count == 2
        assert info.active is False

    def test_max_hits_zero_means_unlimited(self):
        session, engine, bp_id = self._session_with_stack(max_hits=0)

        engine.fire(bp_id, times=6)

        assert len(session.get_log()) == 6
        assert session.list_traces()[0].active is True

    def test_stopped_trace_stops_logging_even_if_the_bp_still_fires(self):
        """remove_breakpoint is best-effort; a hit already queued on the engine
        thread can still arrive. The active flag is the real gate."""
        session, engine, bp_id = self._session_with_stack()
        engine.fire(bp_id)
        session.stop_trace(0)

        status = engine.fire(bp_id)

        assert status == GO_HANDLED
        assert len(session.get_log()) == 1


# ---------------------------------------------------------------------------
# get_log
# ---------------------------------------------------------------------------


class TestGetLog:
    def _two_traces(self):
        base = FakeBase(memory={0x200000: 0x6FC01234})
        engine = FakeEngine(base=base, registers={"ESP": 0x200000})
        session, engine, _mapper = make_session(engine=engine)
        session.add_function_trace(0x6FAA1000, "D2Game.dll", arg_count=0)
        session.add_function_trace(0x6FAA2000, "D2Game.dll", arg_count=0)
        bp_ids = list(engine.code_breakpoints)
        return session, engine, bp_ids

    def test_default_returns_every_trace_interleaved(self):
        session, engine, (bp0, bp1) = self._two_traces()
        engine.fire(bp0)
        engine.fire(bp1)
        engine.fire(bp0)

        assert [e.trace_id for e in session.get_log()] == [0, 1, 0]

    def test_filters_by_trace_id(self):
        session, engine, (bp0, bp1) = self._two_traces()
        engine.fire(bp0, times=2)
        engine.fire(bp1)

        assert [e.trace_id for e in session.get_log(trace_id=1)] == [1]

    def test_last_n_returns_the_most_recent_entries(self):
        session, engine, (bp0, _bp1) = self._two_traces()
        engine.fire(bp0, times=5)

        assert len(session.get_log(last_n=2)) == 2

    def test_log_is_a_bounded_ring_buffer(self):
        """A hot D2 function is hit ~25x/second; an unbounded log would eat the
        debugger process alive during a long trace."""
        session, _engine, _mapper = make_session()

        assert session._log.maxlen == tracing.MAX_LOG_SIZE
        assert session._watch_log.maxlen == tracing.MAX_WATCH_LOG_SIZE


# ---------------------------------------------------------------------------
# stop_trace / stop_all
# ---------------------------------------------------------------------------


class TestStopTrace:
    def test_stop_removes_the_breakpoint(self):
        session, engine, _mapper = make_session()
        trace_id = session.add_function_trace(0x6FAA1000, "D2Game.dll")
        bp_id = next(iter(engine.code_breakpoints))

        session.stop_trace(trace_id)

        assert engine.removed == [bp_id]
        assert session.list_traces()[0].active is False

    def test_stopping_an_unknown_trace_is_a_no_op(self):
        session, engine, _mapper = make_session()

        session.stop_trace(999)

        assert engine.removed == []

    def test_engine_removal_failure_does_not_propagate(self):
        """Removing a breakpoint from a target that already exited throws.
        stop_trace is called from shutdown paths, so it must not raise."""
        engine = FakeEngine(base=FakeBase(), remove_error=RuntimeError("target gone"))
        session, engine, _mapper = make_session(engine=engine)
        trace_id = session.add_function_trace(0x6FAA1000, "D2Game.dll")

        session.stop_trace(trace_id)  # must not raise

        assert session.list_traces()[0].active is False

    def test_stop_all_covers_traces_and_watches(self):
        session, engine, _mapper = make_session()
        session.add_function_trace(0x6FAA1000, "D2Game.dll")
        session.add_function_trace(0x6FAA2000, "D2Game.dll")
        session.add_data_watch(0x6FBB0000, "D2Game.dll")

        assert session.stop_all() == 3
        assert session.active_count() == 0
        assert session.watch_count() == 0
        assert len(engine.removed) == 3


# ---------------------------------------------------------------------------
# add_data_watch
# ---------------------------------------------------------------------------


class TestAddDataWatch:
    def test_watch_is_set_at_the_mapped_runtime_address(self):
        session, engine, mapper = make_session()

        watch_id = session.add_data_watch(0x6FBB0000, "D2Game.dll", size=2)

        assert watch_id == 0
        assert mapper.to_runtime_calls == [(0x6FBB0000, "D2Game.dll")]
        (address, size, _access, handler), = engine.data_breakpoints.values()
        assert address == 0x6FBB0000 + SLIDE
        assert size == 2
        assert callable(handler)

    @pytest.mark.parametrize(
        "access, expected",
        [
            ("write", DbgEng.DEBUG_BREAK_WRITE),
            ("read", DbgEng.DEBUG_BREAK_READ),
            ("readwrite", DbgEng.DEBUG_BREAK_READ | DbgEng.DEBUG_BREAK_WRITE),
            ("bogus", DbgEng.DEBUG_BREAK_WRITE),  # unknown -> safe default
        ],
    )
    def test_access_string_maps_to_dbgeng_flags(self, access, expected):
        session, engine, _mapper = make_session()

        session.add_data_watch(0x6FBB0000, "D2Game.dll", access=access)

        (_addr, _size, flags, _handler), = engine.data_breakpoints.values()
        assert flags == expected

    def test_fifth_watch_is_refused(self):
        """x86 has exactly four debug registers (DR0-DR3). Silently dropping
        the fifth would leave a watch that never fires."""
        session, _engine, _mapper = make_session()
        for i in range(4):
            session.add_data_watch(0x6FBB0000 + i * 4, "D2Game.dll")

        with pytest.raises(RuntimeError, match="hardware breakpoint limit"):
            session.add_data_watch(0x6FBB1000, "D2Game.dll")

    def test_stopping_a_watch_frees_a_hardware_slot(self):
        session, _engine, _mapper = make_session()
        ids = [session.add_data_watch(0x6FBB0000 + i * 4, "D2Game.dll") for i in range(4)]

        session.stop_watch(ids[0])

        assert session.add_data_watch(0x6FBB1000, "D2Game.dll") == 4
        assert session.watch_count() == 4


# ---------------------------------------------------------------------------
# The watch-hit handler
# ---------------------------------------------------------------------------


class TestWatchHandler:
    def _session_with_watch(self, size=4, value=0xCAFEBABE, **kwargs):
        target_runtime = 0x6FBB0000 + SLIDE
        base = FakeBase(
            memory={target_runtime: value},
            symbols={0x6FC05000: "D2Game!SetHp+0x8"},
        )
        engine = FakeEngine(base=base, pc=0x6FC05000)
        session, engine, _mapper = make_session(engine=engine)
        session.add_data_watch(0x6FBB0000, "D2Game.dll", size=size, **kwargs)
        return session, engine, next(iter(engine.data_breakpoints))

    def test_hit_records_value_accessor_and_auto_resumes(self):
        session, engine, bp_id = self._session_with_watch()

        status = engine.fire(bp_id)

        assert status == GO_HANDLED
        hit, = session.get_watch_log()
        assert hit.watch_id == 0
        assert hit.address == 0x6FBB0000 + SLIDE
        assert hit.ghidra_address == 0x6FBB0000
        assert hit.size == 4
        assert hit.access == "write"
        assert hit.value == 0xCAFEBABE
        assert hit.accessor_address == 0x6FC05000
        assert hit.accessor_ghidra == 0x6FC05000 - SLIDE
        assert hit.accessor_symbol == "D2Game!SetHp+0x8"

    @pytest.mark.parametrize("size, expected", [(1, 0xBE), (2, 0xBABE), (4, 0xCAFEBABE)])
    def test_value_is_decoded_at_the_watch_width(self, size, expected):
        """A 1- or 2-byte watch must report the byte/word actually watched, not
        the enclosing dword -- that is the difference between reading a stat
        index and reading three unrelated fields."""
        session, engine, bp_id = self._session_with_watch(size=size)

        engine.fire(bp_id)

        assert session.get_watch_log()[0].value == expected

    def test_unreadable_memory_leaves_value_none_but_keeps_the_hit(self):
        """Losing the value is fine; losing the *accessor* would waste the hit,
        and the accessor is the reason to set a watchpoint at all."""
        target_runtime = 0x6FBB0000 + SLIDE
        base = FakeBase(read_fails_at={target_runtime})
        engine = FakeEngine(base=base, pc=0x6FC05000)
        session, engine, _mapper = make_session(engine=engine)
        session.add_data_watch(0x6FBB0000, "D2Game.dll")

        status = engine.fire(next(iter(engine.data_breakpoints)))

        hit, = session.get_watch_log()
        assert status == GO_HANDLED
        assert hit.value is None
        assert hit.accessor_address == 0x6FC05000

    def test_detached_engine_resumes_without_logging(self):
        engine = FakeEngine(base=None)
        session, engine, _mapper = make_session(engine=engine)
        session.add_data_watch(0x6FBB0000, "D2Game.dll")

        status = engine.fire(next(iter(engine.data_breakpoints)))

        assert status == GO_HANDLED
        assert session.get_watch_log() == []

    def test_handler_swallows_errors_and_still_resumes(self):
        engine = FakeEngine(base=FakeBase(), pc=RuntimeError("pc read failed"))
        session, engine, _mapper = make_session(engine=engine)
        session.add_data_watch(0x6FBB0000, "D2Game.dll")

        status = engine.fire(next(iter(engine.data_breakpoints)))

        assert status == GO_HANDLED
        assert session.get_watch_log() == []

    def test_stopped_watch_stops_logging(self):
        session, engine, bp_id = self._session_with_watch()
        engine.fire(bp_id)
        session.stop_watch(0)

        status = engine.fire(bp_id)

        assert status == GO_HANDLED
        assert len(session.get_watch_log()) == 1


# ---------------------------------------------------------------------------
# watch log / stop_watch / stop_all_watches
# ---------------------------------------------------------------------------


class TestWatchLogAndStop:
    def _two_watches(self):
        base = FakeBase(memory={})
        engine = FakeEngine(base=base, pc=0x6FC05000)
        session, engine, _mapper = make_session(engine=engine)
        session.add_data_watch(0x6FBB0000, "D2Game.dll")
        session.add_data_watch(0x6FBB0010, "D2Game.dll")
        return session, engine, list(engine.data_breakpoints)

    def test_watch_log_filters_by_watch_id(self):
        session, engine, (bp0, bp1) = self._two_watches()
        engine.fire(bp0, times=2)
        engine.fire(bp1)

        assert [h.watch_id for h in session.get_watch_log(watch_id=1)] == [1]
        assert len(session.get_watch_log()) == 3

    def test_watch_log_last_n(self):
        session, engine, (bp0, _bp1) = self._two_watches()
        engine.fire(bp0, times=4)

        assert len(session.get_watch_log(last_n=3)) == 3

    def test_stopping_an_unknown_watch_is_a_no_op(self):
        session, engine, _bps = self._two_watches()

        session.stop_watch(999)

        assert engine.removed == []

    def test_engine_removal_failure_does_not_propagate(self):
        engine = FakeEngine(base=FakeBase(), remove_error=RuntimeError("target gone"))
        session, engine, _mapper = make_session(engine=engine)
        watch_id = session.add_data_watch(0x6FBB0000, "D2Game.dll")

        session.stop_watch(watch_id)  # must not raise

        assert session.watch_count() == 0

    def test_stop_all_watches_leaves_function_traces_running(self):
        """The HTTP layer exposes watch teardown separately from trace
        teardown; bleeding across would silently kill an in-flight trace."""
        session, engine, _bps = self._two_watches()
        session.add_function_trace(0x6FAA1000, "D2Game.dll")

        assert session.stop_all_watches() == 2
        assert session.watch_count() == 0
        assert session.active_count() == 1
