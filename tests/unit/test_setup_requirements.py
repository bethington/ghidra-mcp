"""
Unit tests for tools.setup.requirements — uv-driven dependency install.

The project's Python dependencies are managed through uv + the root
``pyproject.toml`` / ``uv.lock`` (PEP 735 dependency groups). Setup commands
sync them with ``uv sync`` rather than ``pip install -r requirements*.txt``.
All tests stub subprocess and shutil so no real uv invocation happens.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.setup import requirements as req


def _completed(returncode: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")


def test_uv_executable_prefers_path(monkeypatch):
    monkeypatch.setattr(req.shutil, "which", lambda name: "/opt/bin/uv" if name == "uv" else None)
    assert req.uv_executable() == "/opt/bin/uv"


def test_uv_executable_falls_back_to_bare_name(monkeypatch):
    monkeypatch.setattr(req.shutil, "which", lambda _: None)
    assert req.uv_executable() == "uv"


def test_ensure_uv_available_returns_executable(monkeypatch):
    monkeypatch.setattr(req.shutil, "which", lambda _: "/opt/bin/uv")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0))
    assert req.ensure_uv_available() == "/opt/bin/uv"


def test_ensure_uv_available_raises_when_missing(monkeypatch):
    monkeypatch.setattr(req.shutil, "which", lambda _: None)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1))
    with pytest.raises(FileNotFoundError) as exc:
        req.ensure_uv_available()
    assert "uv is not available" in str(exc.value)


def test_make_install_plan_dev_group_by_default():
    plan = req.make_install_plan(Path("/repo"), install_debugger=False)
    assert plan.groups == ("dev",)
    assert plan.install_debugger is False


def test_make_install_plan_adds_debugger_group():
    plan = req.make_install_plan(Path("/repo"), install_debugger=True)
    assert "debugger" in plan.groups
    assert plan.install_debugger is True


def test_uv_sync_command_includes_each_group(monkeypatch):
    monkeypatch.setattr(req, "uv_executable", lambda: "uv")
    plan = req.make_install_plan(Path("/repo"), install_debugger=True)
    cmd = req.uv_sync_command(plan)
    assert cmd[:2] == ["uv", "sync"]
    assert "--group" in cmd
    assert "dev" in cmd
    assert "debugger" in cmd


def test_execute_install_plan_runs_uv_sync(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return _completed(0)

    monkeypatch.setattr(req, "uv_executable", lambda: "uv")
    monkeypatch.setattr(subprocess, "run", fake_run)

    plan = req.make_install_plan(tmp_path, install_debugger=False)
    req.execute_install_plan(plan)

    assert captured["cmd"][:2] == ["uv", "sync"]
    assert "dev" in captured["cmd"]
    assert captured["cwd"] == str(tmp_path)
