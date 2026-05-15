"""Regression tests for fun-doc/log_rotation.py.

The three append-only logs (ghidra_http.jsonl, runs.jsonl, events.jsonl)
were unbounded prior to this module — ghidra_http alone hit 1.03 GB over
three weeks on the user's main workspace. write_jsonl_rotating bounds
each log to ``max_bytes * (backups + 1)`` and is the single helper all
three writers route through.

These tests use tiny max_bytes (256 B) so rotation triggers after a
handful of writes, and run in tmp_path so they never touch the real
fun-doc/logs/ directory.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest


@pytest.fixture
def log_rotation_module():
    """Import the helper from fun-doc/."""
    funcdoc_dir = Path(__file__).resolve().parent.parent.parent / "fun-doc"
    if str(funcdoc_dir) not in sys.path:
        sys.path.insert(0, str(funcdoc_dir))
    import log_rotation

    return log_rotation


def _read_lines(p: Path) -> list[str]:
    return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


# ---------------------------------------------------------------------------
# Single-writer behavior
# ---------------------------------------------------------------------------

def test_append_writes_one_jsonl_line(log_rotation_module, tmp_path):
    """Single append must produce exactly one line ending with newline."""
    path = tmp_path / "test.jsonl"
    entry = json.dumps({"event": "hello", "n": 1})
    assert log_rotation_module.write_jsonl_rotating(path, entry, max_bytes=1024, backups=3) is True

    raw = path.read_text(encoding="utf-8")
    assert raw == entry + "\n"


def test_append_adds_newline_when_missing(log_rotation_module, tmp_path):
    """Caller passes bare JSON; helper guarantees trailing newline."""
    path = tmp_path / "test.jsonl"
    log_rotation_module.write_jsonl_rotating(path, '{"a":1}', max_bytes=1024, backups=3)
    log_rotation_module.write_jsonl_rotating(path, '{"a":2}', max_bytes=1024, backups=3)
    lines = _read_lines(path)
    assert lines == ['{"a":1}', '{"a":2}']


def test_append_creates_parent_dir(log_rotation_module, tmp_path):
    """Missing parent directories must be created automatically."""
    nested = tmp_path / "a" / "b" / "c" / "test.jsonl"
    assert log_rotation_module.write_jsonl_rotating(nested, '{"x":1}') is True
    assert nested.exists()


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

def test_rotation_kicks_in_at_threshold(log_rotation_module, tmp_path):
    """Once max_bytes is exceeded, next write triggers a rotation to .1."""
    path = tmp_path / "test.jsonl"

    # Each line is ~30 bytes. With max_bytes=80 we get 2-3 entries per file.
    for i in range(6):
        log_rotation_module.write_jsonl_rotating(
            path,
            json.dumps({"i": i, "pad": "x" * 20}),
            max_bytes=80,
            backups=3,
        )

    # .1 must exist (rotated at least once)
    rotated_1 = path.with_suffix(path.suffix + ".1")
    assert rotated_1.exists(), "Expected .1 backup after multiple appends > max_bytes"
    # Live file should be smaller than threshold + one record's worth.
    assert path.stat().st_size <= 80 + 60


def test_rotation_caps_at_backups_count(log_rotation_module, tmp_path):
    """Oldest backup must be dropped; total file count never exceeds backups + 1."""
    path = tmp_path / "test.jsonl"

    # Hammer with enough writes to force many rotations.
    for i in range(40):
        log_rotation_module.write_jsonl_rotating(
            path,
            json.dumps({"i": i, "pad": "x" * 30}),
            max_bytes=64,
            backups=2,
        )

    # Files that should exist: test.jsonl, test.jsonl.1, test.jsonl.2.
    # Files that must NOT exist: test.jsonl.3 (oldest got dropped).
    assert path.exists()
    assert path.with_suffix(path.suffix + ".1").exists()
    assert path.with_suffix(path.suffix + ".2").exists()
    assert not path.with_suffix(path.suffix + ".3").exists()
    assert not path.with_suffix(path.suffix + ".4").exists()


def test_rotation_preserves_recent_data(log_rotation_module, tmp_path):
    """After rotation, the .1 backup contains the writes that triggered it."""
    path = tmp_path / "test.jsonl"

    log_rotation_module.write_jsonl_rotating(
        path, json.dumps({"i": 0, "pad": "x" * 60}), max_bytes=80, backups=3
    )
    log_rotation_module.write_jsonl_rotating(
        path, json.dumps({"i": 1, "pad": "x" * 60}), max_bytes=80, backups=3
    )

    rotated_1 = path.with_suffix(path.suffix + ".1")
    # The first write should have rotated into .1, and the second should
    # be in the live file.
    assert rotated_1.exists()
    backup_contents = rotated_1.read_text(encoding="utf-8")
    live_contents = path.read_text(encoding="utf-8")
    assert '"i": 0' in backup_contents
    assert '"i": 1' in live_contents


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

def test_concurrent_writes_are_serialized(log_rotation_module, tmp_path):
    """Threads writing the same file must produce a valid JSONL stream
    (no torn lines)."""
    path = tmp_path / "concurrent.jsonl"
    n_threads = 8
    n_per_thread = 50

    def worker(tid):
        for j in range(n_per_thread):
            log_rotation_module.write_jsonl_rotating(
                path,
                json.dumps({"tid": tid, "j": j}),
                max_bytes=10 * 1024 * 1024,  # big enough to avoid rotation
                backups=2,
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = _read_lines(path)
    assert len(lines) == n_threads * n_per_thread
    # Every line is valid JSON (no torn writes).
    for line in lines:
        rec = json.loads(line)
        assert "tid" in rec and "j" in rec


def test_concurrent_writes_to_different_files_dont_block(log_rotation_module, tmp_path):
    """Per-path locking — writers to different files don't contend."""
    path_a = tmp_path / "a.jsonl"
    path_b = tmp_path / "b.jsonl"

    def write_to(p):
        for i in range(20):
            log_rotation_module.write_jsonl_rotating(p, json.dumps({"i": i}))

    ta = threading.Thread(target=write_to, args=(path_a,))
    tb = threading.Thread(target=write_to, args=(path_b,))
    ta.start()
    tb.start()
    ta.join(timeout=5)
    tb.join(timeout=5)

    assert not ta.is_alive()
    assert not tb.is_alive()
    assert len(_read_lines(path_a)) == 20
    assert len(_read_lines(path_b)) == 20


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_write_returns_false_on_error_does_not_raise(log_rotation_module, tmp_path, monkeypatch, capsys):
    """Write failures must surface as a False return + stderr warning,
    never as an unhandled exception (workers must not die on log writes)."""
    path = tmp_path / "test.jsonl"

    def _boom(*args, **kwargs):
        raise OSError("simulated disk full")

    # Patch open to raise inside the helper's write path.
    import builtins
    original_open = builtins.open

    def patched_open(p, *args, **kwargs):
        if str(p) == str(path):
            raise OSError("simulated disk full")
        return original_open(p, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", patched_open)

    result = log_rotation_module.write_jsonl_rotating(path, '{"x":1}')
    assert result is False

    captured = capsys.readouterr()
    assert "simulated disk full" in captured.err


# ---------------------------------------------------------------------------
# Config from env
# ---------------------------------------------------------------------------

def test_max_bytes_overridable_via_env(log_rotation_module, tmp_path, monkeypatch):
    monkeypatch.setenv("FUN_DOC_LOG_MAX_BYTES", "1024")
    assert log_rotation_module._default_max_bytes() == 1024


def test_backups_overridable_via_env(log_rotation_module, tmp_path, monkeypatch):
    monkeypatch.setenv("FUN_DOC_LOG_BACKUPS", "10")
    assert log_rotation_module._default_backups() == 10


def test_default_max_bytes_when_no_env(log_rotation_module, monkeypatch):
    monkeypatch.delenv("FUN_DOC_LOG_MAX_BYTES", raising=False)
    assert log_rotation_module._default_max_bytes() == 200 * 1024 * 1024


def test_default_backups_when_no_env(log_rotation_module, monkeypatch):
    monkeypatch.delenv("FUN_DOC_LOG_BACKUPS", raising=False)
    assert log_rotation_module._default_backups() == 5


def test_garbage_env_falls_back_to_defaults(log_rotation_module, monkeypatch):
    monkeypatch.setenv("FUN_DOC_LOG_MAX_BYTES", "not-a-number")
    monkeypatch.setenv("FUN_DOC_LOG_BACKUPS", "-1")
    assert log_rotation_module._default_max_bytes() == 200 * 1024 * 1024
    # backups=0 is allowed; -1 is not.
    assert log_rotation_module._default_backups() == 5
