"""Regression test for the dashboard single-instance port check.

Motivation: every `python fun_doc.py ...` invocation used to call
`create_app()` and build its own in-process WorkerManager. When two
processes ran at the same time, the second one silently failed to
bind the dashboard port but still owned a live WorkerManager that
nothing could reach from the browser — events emitted there flowed
to a detached bus. The fix probes the dashboard port BEFORE
create_app(); if another fun_doc is already listening, the extra
process must skip dashboard + WorkerManager entirely and behave as a
pure CLI.

This test launches a minimal TCP listener on the dashboard port, then
spawns `fun_doc.py` as a subprocess and asserts it prints the
skip-dashboard line instead of building a WorkerManager.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
FUN_DOC_PY = FUN_DOC_DIR / "fun_doc.py"


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _hold_port(port: int) -> tuple[socket.socket, threading.Event]:
    """Listen on `port` so a subsequent fun_doc launch sees it taken."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    stop = threading.Event()

    def _accept_loop():
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return

    threading.Thread(target=_accept_loop, daemon=True).start()
    return srv, stop


def test_skip_dashboard_when_port_already_owned():
    """Spawning fun_doc.py with --help on a taken port should still work,
    but a real status run must print the skip-dashboard line.
    """
    port = _pick_free_port()
    srv, stop = _hold_port(port)
    try:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        # Use --status (dry lookup) so the subprocess hits the dashboard
        # auto-start block then exits quickly. --web-port points it at
        # our occupied port.
        proc = subprocess.Popen(
            [
                sys.executable,
                str(FUN_DOC_PY),
                "--status",
                "--web-port",
                str(port),
            ],
            cwd=str(FUN_DOC_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        try:
            out, _ = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            pytest.fail(f"fun_doc.py did not exit within 60s. Output so far:\n{out}")

        assert proc.returncode == 0, f"Expected clean exit, got {proc.returncode}\n{out}"
        assert "Dashboard already running" in out, (
            "Expected port-owned skip message. Output was:\n" + out
        )
    finally:
        stop.set()
        try:
            srv.close()
        except OSError:
            pass


def test_starts_dashboard_when_port_free():
    """With the port free, the skip message must NOT print — fun_doc
    must still run the dashboard thread as it always has.
    """
    port = _pick_free_port()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [
            sys.executable,
            str(FUN_DOC_PY),
            "--status",
            "--web-port",
            str(port),
        ],
        cwd=str(FUN_DOC_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    try:
        out, _ = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        pytest.fail(f"fun_doc.py did not exit within 60s. Output so far:\n{out}")

    # --status exits after printing; dashboard gets to create_app but
    # will stop when main returns. We just want to prove the skip path
    # did NOT fire when port was free.
    assert "Dashboard already running" not in out, (
        "Unexpected skip message when port was free. Output:\n" + out
    )
