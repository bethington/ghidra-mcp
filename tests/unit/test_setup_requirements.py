"""
Unit tests for tools.setup.requirements — pip command resolution.

Covers the nix / Linux case where ``python -m pip`` fails but a bare
``pip`` exists on PATH (#190). All tests stub subprocess and shutil so no
real pip invocation happens.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.setup import requirements as req


@pytest.fixture(autouse=True)
def _clear_pip_cache():
    """Reset the resolved-pip cache between tests so each scenario gets a
    fresh probe."""
    req._PIP_COMMAND_CACHE.clear()
    yield
    req._PIP_COMMAND_CACHE.clear()


def _completed(returncode: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")


def test_pip_command_prefers_python_dash_m_pip(monkeypatch):
    """The happy path on Windows / Mac / most Linux: ``python -m pip`` works."""

    def fake_run(cmd, **kwargs):
        assert "-m" in cmd and "pip" in cmd, cmd
        return _completed(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(req.shutil, "which", lambda _: None)  # don't fall through

    py = Path("/usr/bin/python3")
    assert req.pip_command(py) == [str(py), "-m", "pip"]


def test_pip_command_falls_back_to_bare_pip_on_nix(monkeypatch):
    """The nix case: ``python -m pip`` fails but bare ``pip`` works.

    This is the #190 regression — without the fallback, setup commands
    failed on nix-managed Python environments where pip is exposed as a
    binary but not importable from the active interpreter.
    """
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "-m" in cmd and "pip" in cmd:
            return _completed(1)  # python -m pip fails
        if cmd[0] == "/usr/bin/pip":
            return _completed(0)  # bare pip works
        raise AssertionError(f"unexpected probe: {cmd}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(req.shutil, "which", lambda name: "/usr/bin/pip" if name == "pip" else None)

    py = Path("/nix/store/abc/bin/python3")
    result = req.pip_command(py)
    assert result == ["/usr/bin/pip"]
    # Probed both forms before settling on the fallback.
    assert any("-m" in c and "pip" in c for c in calls)
    assert ["/usr/bin/pip", "--version"] in calls


def test_pip_command_raises_when_neither_form_works(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1))
    monkeypatch.setattr(req.shutil, "which", lambda _: None)

    py = Path("/usr/bin/python3")
    with pytest.raises(FileNotFoundError) as exc:
        req.pip_command(py)
    msg = str(exc.value)
    # Path renders with native separators (/ on POSIX, \ on Windows); check
    # the str(py) form to stay portable.
    assert str(py) in msg
    assert "pip is not available" in msg


def test_pip_command_cached_per_python_executable(monkeypatch):
    """Resolving twice for the same interpreter must not re-probe subprocess."""
    probe_count = 0

    def fake_run(cmd, **kwargs):
        nonlocal probe_count
        probe_count += 1
        return _completed(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(req.shutil, "which", lambda _: None)

    py = Path("/usr/bin/python3")
    first = req.pip_command(py)
    second = req.pip_command(py)
    assert first == second
    assert probe_count == 1, "second call should hit the cache, not re-probe"
    # Caller mutating the returned list must not poison the cache.
    first.append("--mutated")
    third = req.pip_command(py)
    assert "--mutated" not in third


def test_pip_command_per_interpreter_isolation(monkeypatch):
    """Different python executables get independent cache entries."""

    def fake_run(cmd, **kwargs):
        # Both interpreters succeed at python -m pip
        return _completed(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(req.shutil, "which", lambda _: None)

    py_a = Path("/usr/bin/python3.11")
    py_b = Path("/usr/bin/python3.12")
    assert req.pip_command(py_a)[0] == str(py_a)
    assert req.pip_command(py_b)[0] == str(py_b)
    assert req.pip_command(py_a)[0] == str(py_a)  # cache wasn't overwritten by py_b


def test_install_requirements_file_uses_resolved_pip_command(monkeypatch, tmp_path):
    """install_requirements_file must go through pip_command, not the old
    hardcoded ``python -m pip`` invocation."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _completed(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(req.shutil, "which", lambda _: None)
    # Force the bare-pip fallback so we can assert the command prefix matches.
    req._PIP_COMMAND_CACHE[str(Path("/nix/python"))] = ["/usr/bin/pip"]

    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests\n")
    req.install_requirements_file(Path("/nix/python"), reqs)

    assert captured["cmd"][:3] == ["/usr/bin/pip", "install", "-r"]
