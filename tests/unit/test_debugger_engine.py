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
