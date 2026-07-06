"""Unit tests for debugger/engine.py helpers and attach flow."""

from __future__ import annotations

import importlib
import sys
import threading
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def import_engine_with_stubs():
    for name in [
        "debugger.engine",
        "pybag",
        "pybag.pydbg",
        "pybag.userdbg",
        "pybag.dbgeng",
        "pybag.dbgeng.core",
        "pybag.dbgeng.exception",
    ]:
        sys.modules.pop(name, None)

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

        def create(self, *_args, **_kwargs):
            return None

        def attach(self, *_args, **_kwargs):
            return None

        def detach(self, *_args, **_kwargs):
            return None

        def terminate(self, *_args, **_kwargs):
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

    return importlib.import_module("debugger.engine")


def make_engine(engine_module, base, state):
    engine = engine_module.DebugEngine.__new__(engine_module.DebugEngine)
    engine._state = state
    engine._target_pid = None
    engine._target_name = None
    engine._executing = False
    engine._is_wow64 = False
    engine._protected_base = base
    engine._thread = threading.current_thread()
    engine._pass_exceptions = False
    engine._call_guard = False
    engine._stepping = False
    engine._call_ret_catch = None
    engine._call_fault = None
    engine._our_bp_addrs = set()
    engine._bp_id_to_addr = {}
    return engine


class TestEngineHelpers:
    def test_attach_uses_pid_from_pybag_match_and_skips_extra_wait(self):
        engine_module = import_engine_with_stubs()

        class FakeReg:
            def get_pc(self):
                return 0x140001000

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()
                self.attached = []
                self.wait_calls = 0

            def pids_by_name(self, _target):
                return [(4321, r"C:\Windows\System32\ping.exe", "ping")]

            def attach_proc(self, pid):
                self.attached.append(pid)

            def wait(self, _timeout=0):
                self.wait_calls += 1

            def module_list(self):
                return [
                    (
                        (r"C:\Windows\System32\ping.exe", "ping", ""),
                        types.SimpleNamespace(Base=0x140000000, Size=0x1000),
                    )
                ]

        base = FakeBase()
        engine = make_engine(engine_module, base, engine_module.DebuggerState.DETACHED)

        result = engine._attach_impl("ping.exe")

        assert base.attached == [4321]
        assert base.wait_calls == 0
        assert result["module_count"] == 1
        assert result["name"] == "ping"
        assert engine._state == engine_module.DebuggerState.STOPPED

    def test_module_tuple_is_translated_to_module_info(self):
        engine_module = import_engine_with_stubs()

        module = engine_module._module_info_from_pybag_entry(
            (
                (r"C:\Windows\System32\ping.exe", "ping", ""),
                types.SimpleNamespace(Base=0x140000000, Size=0x2000),
            )
        )

        assert module.name == "ping"
        assert module.runtime_base == 0x140000000
        assert module.size == 0x2000

    def test_registers_use_64bit_names_when_target_is_64bit(self):
        engine_module = import_engine_with_stubs()

        class FakeReg:
            def __init__(self):
                self.values = {
                    "rax": 1,
                    "rbx": 2,
                    "rcx": 3,
                    "rdx": 4,
                    "rsi": 5,
                    "rdi": 6,
                    "rsp": 7,
                    "rbp": 8,
                    "rip": 9,
                    "r8": 10,
                    "r9": 11,
                    "r10": 12,
                    "r11": 13,
                    "r12": 14,
                    "r13": 15,
                    "r14": 16,
                    "r15": 17,
                    "efl": 0x246,
                }

            def _get_register(self, name):
                return self.values[name]

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()

            def bitness(self):
                return "64"

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        regs = engine._get_registers_impl()

        assert regs["RAX"] == 1
        assert regs["R15"] == 17
        assert regs["RIP"] == 9
        assert regs["EFLAGS"] == 0x246
        assert "EAX" not in regs

    def test_registers_use_32bit_names_when_target_is_wow64(self):
        engine_module = import_engine_with_stubs()

        class FakeControl:
            def __init__(self):
                self.effective = 0x8664
                self.set_calls = []

            def GetEffectiveProcessorType(self):
                return self.effective

            def SetEffectiveProcessorType(self, processor_type):
                self.set_calls.append(processor_type)
                self.effective = processor_type

        class FakeReg:
            def __init__(self):
                self.values = {
                    "eax": 1,
                    "ebx": 2,
                    "ecx": 3,
                    "edx": 4,
                    "esi": 5,
                    "edi": 6,
                    "esp": 7,
                    "ebp": 8,
                    "eip": 9,
                    "efl": 0x202,
                }

            def _get_register(self, name):
                return self.values[name]

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()
                self._control = FakeControl()

            def bitness(self):
                return "64"

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        engine._is_wow64 = True
        regs = engine._get_registers_impl()

        assert regs["EAX"] == 1
        assert regs["EIP"] == 9
        assert regs["EFLAGS"] == 0x202
        assert "RAX" not in regs
        assert engine._protected_base._control.set_calls == [0x14C, 0x8664]

    def test_get_pc_uses_32bit_effective_processor_on_wow64(self):
        engine_module = import_engine_with_stubs()

        class FakeControl:
            def __init__(self):
                self.effective = 0x8664
                self.set_calls = []

            def GetEffectiveProcessorType(self):
                return self.effective

            def SetEffectiveProcessorType(self, processor_type):
                self.set_calls.append(processor_type)
                self.effective = processor_type

        class FakeReg:
            def get_pc(self):
                return 0x12345678

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()
                self._control = FakeControl()

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        engine._is_wow64 = True

        assert engine._read_pc_impl() == 0x12345678
        assert engine._protected_base._control.set_calls == [0x14C, 0x8664]

    def test_attach_failure_detaches_and_resets_state(self):
        engine_module = import_engine_with_stubs()

        class FakeReg:
            def get_pc(self):
                return 0x140001000

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()
                self.detached = False

            def attach_proc(self, _pid):
                return None

            def detach_proc(self):
                self.detached = True

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.DETACHED)
        engine._wait_for_target_access_impl = lambda: (_ for _ in ()).throw(RuntimeError("not ready"))

        with pytest.raises(RuntimeError, match="never became queryable"):
            engine._attach_impl("1234")

        assert engine._protected_base.detached is True
        assert engine._state == engine_module.DebuggerState.DETACHED


class TestMemoryAndRegisterWrites:
    def test_write_memory_calls_base_write_and_returns_length(self):
        engine_module = import_engine_with_stubs()

        class FakeBase:
            def __init__(self):
                self.writes = []

            def write(self, address, data):
                self.writes.append((address, bytes(data)))

        base = FakeBase()
        engine = make_engine(engine_module, base, engine_module.DebuggerState.STOPPED)

        n = engine._write_memory_impl(0x401000, b"\x90\x90\xC3")

        assert n == 3
        assert base.writes == [(0x401000, b"\x90\x90\xC3")]

    def test_write_memory_requires_stopped_state(self):
        engine_module = import_engine_with_stubs()

        class FakeBase:
            def write(self, address, data):
                raise AssertionError("write() should not be called while detached")

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.DETACHED)

        with pytest.raises(RuntimeError, match="Not attached"):
            engine._write_memory_impl(0x401000, b"\x90")

    def test_write_memory_rejects_write_while_running(self):
        engine_module = import_engine_with_stubs()

        class FakeBase:
            def write(self, address, data):
                raise AssertionError("write() should not be called while running")

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.RUNNING)

        with pytest.raises(RuntimeError, match="running"):
            engine._write_memory_impl(0x401000, b"\x90")

    def test_write_registers_calls_set_register_and_returns_applied_uppercase(self):
        engine_module = import_engine_with_stubs()

        class FakeReg:
            def __init__(self):
                self.set_calls = []

            def _set_register(self, name, value):
                self.set_calls.append((name, value))

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()

        base = FakeBase()
        engine = make_engine(engine_module, base, engine_module.DebuggerState.STOPPED)

        applied = engine._write_registers_impl({"eip": 0x401000, "EAX": "5"})

        assert base.reg.set_calls == [("eip", 0x401000), ("eax", 5)]
        assert applied == {"EIP": 0x401000, "EAX": 5}

    def test_write_registers_requires_stopped_state(self):
        engine_module = import_engine_with_stubs()

        class FakeReg:
            def _set_register(self, name, value):
                raise AssertionError("_set_register() should not be called while detached")

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.DETACHED)

        with pytest.raises(RuntimeError, match="Not attached"):
            engine._write_registers_impl({"eip": 0x401000})

    def test_write_registers_uses_wow64_effective_processor_context(self):
        engine_module = import_engine_with_stubs()

        class FakeControl:
            def __init__(self):
                self.effective = 0x8664
                self.set_calls = []

            def GetEffectiveProcessorType(self):
                return self.effective

            def SetEffectiveProcessorType(self, processor_type):
                self.set_calls.append(processor_type)
                self.effective = processor_type

        class FakeReg:
            def _set_register(self, name, value):
                pass

        class FakeBase:
            def __init__(self):
                self.reg = FakeReg()
                self._control = FakeControl()

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        engine._is_wow64 = True

        engine._write_registers_impl({"eip": 0x401000})

        assert engine._protected_base._control.set_calls == [0x14C, 0x8664]


class TestOnExceptionFilter:
    """Regression tests for the WOW64 exception-filter contradiction found in
    review: PR #366's design assumed our own breakpoints could arrive as
    first-chance EXCEPTION events (needing _our_bp_addrs matching here), while
    PR #367's fast path assumes they never reach here (breakpoints surface via
    the separate BREAKPOINT event) and skips inspection entirely outside a
    call/step window. These tests pin down the currently-intended behavior of
    _on_exception so a future change can't silently reintroduce either the
    COM-record-touching-on-every-flood-event bug (#367's fix) or a swallowed
    ret_catch/guarded-fault (#366's fix) without a test failing.
    """

    CODE_INT3 = 0x80000003
    CODE_WX86_INT3 = 0x4000001F
    CODE_STEP = 0x80000004
    CODE_WX86_STEP = 0x4000001E
    CODE_AV = 0xC0000005

    @staticmethod
    def exc(code, address=0x401000):
        return {"ExceptionCode": code, "ExceptionAddress": address}

    def test_fast_path_never_touches_record_when_not_guarding(self):
        engine_module = import_engine_with_stubs()
        engine = make_engine(engine_module, object(), engine_module.DebuggerState.STOPPED)
        engine._pass_exceptions = True

        # If the fast path regresses into inspecting the record on the flood
        # path, this raises instead of silently passing. Plain functions
        # assigned on the instance (not via the class) shadow the
        # @staticmethod without descriptor binding, so no self is passed.
        def _boom(args):
            raise AssertionError("must not inspect record outside call/step")

        engine._exc_code = _boom
        engine._exc_address = _boom

        result = engine._on_exception(self.exc(self.CODE_WX86_INT3), True)

        assert result == engine_module.DbgEng.DEBUG_STATUS_GO_NOT_HANDLED

    def test_fast_path_passes_through_when_pass_exceptions_disabled(self):
        engine_module = import_engine_with_stubs()
        engine = make_engine(engine_module, object(), engine_module.DebuggerState.STOPPED)
        engine._pass_exceptions = False

        result = engine._on_exception(self.exc(self.CODE_INT3), True)

        assert result == engine_module.DbgEng.DEBUG_STATUS_NO_CHANGE

    def test_guarded_call_recognizes_ret_catch_breakpoint(self):
        engine_module = import_engine_with_stubs()
        engine = make_engine(engine_module, object(), engine_module.DebuggerState.STOPPED)
        engine._call_guard = True
        engine._call_ret_catch = 0x501000
        engine._pass_exceptions = True

        result = engine._on_exception(self.exc(self.CODE_WX86_INT3, 0x501000), True)

        assert result == engine_module.DbgEng.DEBUG_STATUS_NO_CHANGE

    def test_guarded_call_still_passes_through_unrelated_flood_int3(self):
        engine_module = import_engine_with_stubs()

        class FakeBase:
            breakpoints = []  # no live breakpoints -> not "ours"

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        engine._call_guard = True
        engine._call_ret_catch = 0x501000
        engine._pass_exceptions = True

        # An anti-debug INT3 at an unrelated address during the call window
        # must still reach the target's SEH, not be swallowed as "ours".
        result = engine._on_exception(self.exc(self.CODE_INT3, 0x999999), True)

        assert result == engine_module.DbgEng.DEBUG_STATUS_GO_NOT_HANDLED

    def test_guarded_call_catches_genuine_fault(self):
        engine_module = import_engine_with_stubs()
        engine = make_engine(engine_module, object(), engine_module.DebuggerState.STOPPED)
        engine._call_guard = True
        engine._call_ret_catch = 0x501000
        engine._pass_exceptions = True

        result = engine._on_exception(self.exc(self.CODE_AV, 0x401000), True)

        assert result == engine_module.DbgEng.DEBUG_STATUS_NO_CHANGE
        assert engine._call_fault == self.CODE_AV

    def test_stale_shadow_set_no_longer_misclassifies_removed_oneshot_bp(self):
        """Regression: dbgeng auto-drops a fired oneshot breakpoint's object
        with no remove_breakpoint() call, so _our_bp_addrs alone can go stale.
        _on_exception must reconcile against dbgeng's live breakpoint list
        (_live_bp_addrs) rather than trust the shadow set, so a later real
        exception at the reused address isn't wrongly swallowed as ours."""
        engine_module = import_engine_with_stubs()

        class FakeBase:
            breakpoints = []  # dbgeng no longer has anything planted

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        engine._call_guard = True
        engine._call_ret_catch = 0x501000
        engine._pass_exceptions = True
        # Stale bookkeeping: our oneshot bp fired and dbgeng dropped it, but
        # nothing called remove_breakpoint() to clear this shadow entry.
        engine._our_bp_addrs = {0x401000}

        result = engine._on_exception(self.exc(self.CODE_INT3, 0x401000), True)

        # Must be treated as a genuine target exception (passed through),
        # not silently absorbed because of the stale shadow-set entry.
        assert result == engine_module.DbgEng.DEBUG_STATUS_GO_NOT_HANDLED

    def test_live_bp_addrs_reconciles_against_dbgeng_not_shadow_set(self):
        engine_module = import_engine_with_stubs()

        class FakeBpObj:
            def GetOffset(self):
                return 0x601000

        class FakeControl:
            def GetBreakpointById(self, bp_id):
                return FakeBpObj()

        class FakeBase:
            breakpoints = [7]
            _control = FakeControl()

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)

        assert engine._live_bp_addrs() == {0x601000}

    def test_second_chance_exception_lets_dbgeng_handle_it(self):
        engine_module = import_engine_with_stubs()
        engine = make_engine(engine_module, object(), engine_module.DebuggerState.STOPPED)
        engine._pass_exceptions = True

        result = engine._on_exception(self.exc(self.CODE_INT3), False)

        assert result == engine_module.DbgEng.DEBUG_STATUS_NO_CHANGE


class TestDetachClearsBreakpointBookkeeping:
    def test_detach_clears_shadow_bp_state_and_call_flags(self):
        engine_module = import_engine_with_stubs()

        class FakeBase:
            def detach_proc(self):
                pass

        engine = make_engine(engine_module, FakeBase(), engine_module.DebuggerState.STOPPED)
        engine._target_pid = 4321
        engine._our_bp_addrs = {0x401000, 0x402000}
        engine._bp_id_to_addr = {1: 0x401000, 2: 0x402000}
        engine._call_guard = True
        engine._stepping = True

        engine._detach_impl()

        assert engine._our_bp_addrs == set()
        assert engine._bp_id_to_addr == {}
        assert engine._call_guard is False
        assert engine._stepping is False
