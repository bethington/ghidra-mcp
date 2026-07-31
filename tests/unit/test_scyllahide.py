"""Regression tests for debugger/scyllahide.py -- ensure-injection on attach.

WHY
---
PD2's Game.exe strips or detects software breakpoints unless ScyllaHide is
injected, so without it the debugger fails QUIETLY: breakpoints appear to be set
and simply never hit, and call_function's return-catch never fires. Until
2026-07-30 only `start-oracle.ps1` injected it -- not the launcher the
conformance work uses, and not oracle_health's unattended recovery path -- and it
was measurably absent from the live process.

The two properties that matter here:
  1. ensure() NEVER raises and never fails an attach (hardening must not be able
     to refuse a debug session), and
  2. it is never OPTIMISTIC -- an injection the module list can't confirm reports
     as not-hardened, because a false "hardened" restores exactly the silent
     failure this exists to remove.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from debugger import scyllahide  # noqa: E402


class TestIsInjected:
    def test_detects_bare_name(self):
        assert scyllahide.is_injected(["ntdll.dll", "HookLibraryx86.dll"])

    def test_detects_full_path_and_case_insensitively(self):
        assert scyllahide.is_injected([r"C:\tools\sh\hooklibraryx86.DLL"])

    def test_detects_name_without_extension(self):
        """dbgeng reports module names in several spellings depending on how the
        module was loaded; missing one spelling would read as 'not hardened' and
        trigger a redundant injection on every attach."""
        assert scyllahide.is_injected(["HookLibraryx86"])

    def test_x64_variant_is_distinct(self):
        assert scyllahide.is_injected(["HookLibraryx64.dll"], arch="x64")
        assert not scyllahide.is_injected(["HookLibraryx64.dll"], arch="x86")

    def test_absent_and_empty(self):
        assert not scyllahide.is_injected(["ntdll.dll", "Game.exe"])
        assert not scyllahide.is_injected([])
        assert not scyllahide.is_injected(None)


class TestEnsure:
    def test_already_present_does_not_inject(self, monkeypatch):
        called = []
        monkeypatch.setattr(scyllahide, "inject", lambda *a, **k: called.append(1))
        st = scyllahide.ensure(1234, ["HookLibraryx86.dll"])
        assert st["status"] == "present"
        assert not called, "must not re-inject an already-hooked target"

    def test_injects_and_verifies_via_module_list(self, monkeypatch, tmp_path):
        (tmp_path / "InjectorCLIx86.exe").write_text("")
        (tmp_path / "HookLibraryx86.dll").write_text("")
        monkeypatch.setattr(scyllahide, "inject",
                            lambda *a, **k: {"ok": True, "detail": "injected"})
        st = scyllahide.ensure(1234, ["ntdll.dll"], directory=tmp_path,
                               refresh_modules=lambda: ["ntdll.dll", "HookLibraryx86.dll"])
        assert st["status"] == "injected"

    def test_injector_success_without_the_module_is_UNVERIFIED(self, monkeypatch, tmp_path):
        """The injector's exit code is not proof. If the hook is not in the module
        list afterwards, the target is NOT hardened and must not be reported as
        such -- breakpoints would fail silently again."""
        (tmp_path / "InjectorCLIx86.exe").write_text("")
        (tmp_path / "HookLibraryx86.dll").write_text("")
        monkeypatch.setattr(scyllahide, "inject",
                            lambda *a, **k: {"ok": True, "detail": "done"})
        st = scyllahide.ensure(1234, ["ntdll.dll"], directory=tmp_path,
                               refresh_modules=lambda: ["ntdll.dll"])
        assert st["status"] == "unverified"
        assert st["status"] not in scyllahide.OK_STATUSES
        assert scyllahide.warning_for(st) is not None

    def test_missing_binaries_report_unavailable(self, tmp_path):
        st = scyllahide.ensure(1234, ["ntdll.dll"], directory=tmp_path)
        assert st["status"] == "unavailable"
        assert str(tmp_path) in st["detail"]

    def test_auto_inject_disabled(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SCYLLAHIDE_AUTO_INJECT", "0")
        called = []
        monkeypatch.setattr(scyllahide, "inject", lambda *a, **k: called.append(1))
        st = scyllahide.ensure(1234, ["ntdll.dll"], directory=tmp_path)
        assert st["status"] == "disabled"
        assert not called

    def test_disabled_still_reports_present_when_already_hooked(self, monkeypatch):
        monkeypatch.setenv("SCYLLAHIDE_AUTO_INJECT", "0")
        assert scyllahide.ensure(1, ["HookLibraryx86.dll"])["status"] == "present"

    def test_no_pid_is_skipped_not_an_error(self):
        assert scyllahide.ensure(None, ["ntdll.dll"])["status"] == "skipped"

    def test_injector_failure_is_reported_not_raised(self, monkeypatch, tmp_path):
        (tmp_path / "InjectorCLIx86.exe").write_text("")
        (tmp_path / "HookLibraryx86.dll").write_text("")
        monkeypatch.setattr(scyllahide, "inject",
                            lambda *a, **k: {"ok": False, "detail": "access denied"})
        st = scyllahide.ensure(1234, ["ntdll.dll"], directory=tmp_path)
        assert st["status"] == "failed"
        assert "access denied" in st["detail"]

    def test_refresh_callback_raising_does_not_propagate(self, monkeypatch, tmp_path):
        (tmp_path / "InjectorCLIx86.exe").write_text("")
        (tmp_path / "HookLibraryx86.dll").write_text("")
        monkeypatch.setattr(scyllahide, "inject",
                            lambda *a, **k: {"ok": True, "detail": "ok"})

        def boom():
            raise RuntimeError("dbgeng busy")

        st = scyllahide.ensure(1234, ["ntdll.dll"], directory=tmp_path,
                               refresh_modules=boom)
        assert st["status"] in ("injected", "unverified")


class TestWarningFor:
    @pytest.mark.parametrize("status", ["unavailable", "failed", "disabled",
                                        "skipped", "unverified", "error"])
    def test_non_ok_statuses_warn(self, status):
        w = scyllahide.warning_for({"status": status, "detail": "x"})
        assert w and "breakpoints" in w.lower()

    @pytest.mark.parametrize("status", ["present", "injected"])
    def test_ok_statuses_do_not_warn(self, status):
        assert scyllahide.warning_for({"status": status, "detail": "x"}) is None

    def test_warning_names_the_consequence_and_the_fix(self):
        w = scyllahide.warning_for({"status": "unavailable", "detail": "not found"})
        assert "silently fail" in w
        assert "start-oracle.ps1" in w

    def test_missing_status_object_does_not_crash(self):
        assert scyllahide.warning_for(None) is None


class TestInjectIsHermetic:
    def test_missing_tools_returns_error_without_running_anything(self, tmp_path):
        res = scyllahide.inject(1234, "x86", directory=tmp_path)
        assert res["ok"] is False
        assert "not found" in res["detail"]

    def test_os_error_is_caught(self, monkeypatch, tmp_path):
        (tmp_path / "InjectorCLIx86.exe").write_text("")
        (tmp_path / "HookLibraryx86.dll").write_text("")

        def boom(*a, **k):
            raise OSError("not executable")

        monkeypatch.setattr(scyllahide.subprocess, "run", boom)
        res = scyllahide.inject(1234, "x86", directory=tmp_path)
        assert res["ok"] is False and "not executable" in res["detail"]
