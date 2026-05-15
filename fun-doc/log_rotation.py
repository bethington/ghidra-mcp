"""Size-rotating JSONL append writer for fun-doc operational logs.

Three append-only log files in ``fun-doc/logs/`` had no rotation:

  * ``ghidra_http.jsonl`` — every Ghidra HTTP call (~50 MB/day under
    active worker load; hit 1.03 GB after three weeks)
  * ``runs.jsonl``        — every worker run record
  * ``events.jsonl``      — structured event-bus mirror

At current growth rates the disk usage was unbounded; on long-running
deployments this would eventually fill the working tree. This module
provides a single ``write_jsonl_rotating`` helper that all three log
writers route through.

Design notes
------------

* **Per-path RLock**, not a global lock. ``events.jsonl`` and
  ``runs.jsonl`` are written by different code paths (event bus vs
  ``_append_run_log``) and the original ``_event_lock`` only protected
  one of them. Per-path locking keeps both paths thread-safe without
  serializing across log files.
* **Rotation on write, not on schedule.** When the next append would
  exceed ``max_bytes`` we rotate first: ``file.N`` → drop, ``file.N-1``
  → ``file.N``, …, ``file`` → ``file.1``. This bounds disk to roughly
  ``max_bytes * (backups + 1)``.
* **Failures are non-fatal.** A failed rotate/write prints a one-line
  warning to stderr and continues. Production logging must never take
  down workers — that was the v5.9.0 release-day failure mode in a
  different guise.
* **JSONL contract preserved.** Callers serialize entries themselves
  (existing code uses ``json.dumps(entry, default=str)``), the helper
  just owns the open/append/rotate dance. The trailing newline is
  added here so callers can't forget it.

Configuration
-------------

Defaults: 200 MB per file, 5 backups → ~1.2 GB per log series cap.
Tunable per-file via the ``max_bytes`` / ``backups`` kwargs, and the
defaults can be overridden globally via the
``FUN_DOC_LOG_MAX_BYTES`` and ``FUN_DOC_LOG_BACKUPS`` env vars.
"""

from __future__ import annotations

import os
import sys
import threading
from collections import defaultdict
from pathlib import Path


# Per-path RLock so writers to different files don't contend.
_path_locks: dict[Path, threading.RLock] = defaultdict(threading.RLock)
_locks_lock = threading.Lock()


def _get_lock(path: Path) -> threading.RLock:
    """Return the lock for `path`, creating it on first use."""
    # Use the same Path instance every time we look up; resolve first.
    key = Path(path).resolve() if Path(path).is_absolute() else Path(path).absolute()
    with _locks_lock:
        return _path_locks[key]


def _default_max_bytes() -> int:
    """Default rotation threshold, configurable via env."""
    raw = os.environ.get("FUN_DOC_LOG_MAX_BYTES")
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return 200 * 1024 * 1024  # 200 MB


def _default_backups() -> int:
    """Default backup-count, configurable via env."""
    raw = os.environ.get("FUN_DOC_LOG_BACKUPS")
    if raw:
        try:
            v = int(raw)
            if v >= 0:
                return v
        except ValueError:
            pass
    return 5


def _rotate(path: Path, backups: int) -> None:
    """Rotate ``path`` to ``path.1``, shifting older backups up by one.

    ``path.{backups}`` is dropped (gone forever — the cap is hard).
    Idempotent on missing backup files. Caller holds the lock.
    """
    # Drop the oldest backup if present (path.backups → discard).
    oldest = path.with_suffix(path.suffix + f".{backups}")
    try:
        if oldest.exists():
            oldest.unlink()
    except OSError as e:
        sys.stderr.write(
            f"  WARNING: log rotation could not drop oldest backup {oldest}: "
            f"{type(e).__name__}: {e}\n"
        )

    # Shift remaining backups up by one: path.N-1 → path.N for N in [backups..2].
    for n in range(backups - 1, 0, -1):
        src = path.with_suffix(path.suffix + f".{n}")
        dst = path.with_suffix(path.suffix + f".{n + 1}")
        if src.exists():
            try:
                src.replace(dst)
            except OSError as e:
                sys.stderr.write(
                    f"  WARNING: log rotation could not rename {src} -> {dst}: "
                    f"{type(e).__name__}: {e}\n"
                )

    # path → path.1 (only if path exists; first call on a fresh log skips).
    if path.exists():
        try:
            path.replace(path.with_suffix(path.suffix + ".1"))
        except OSError as e:
            sys.stderr.write(
                f"  WARNING: log rotation could not rename {path} -> {path}.1: "
                f"{type(e).__name__}: {e}\n"
            )


def write_jsonl_rotating(
    path: Path,
    line: str,
    *,
    max_bytes: int | None = None,
    backups: int | None = None,
) -> bool:
    """Append ``line`` to ``path`` as a JSONL record, rotating if needed.

    Args:
        path: Target log file.
        line: One JSON-serialized record, **without** trailing newline.
            (The newline is appended here so callers can't forget it.)
        max_bytes: Rotation threshold for ``path`` (defaults to the env
            value or 200 MB).
        backups: Number of rotated copies to retain (defaults to the env
            value or 5).

    Returns:
        ``True`` on successful write, ``False`` on any error. Errors are
        printed to stderr; the caller should not raise on them.
    """
    path = Path(path)
    if max_bytes is None:
        max_bytes = _default_max_bytes()
    if backups is None:
        backups = _default_backups()

    payload = line if line.endswith("\n") else line + "\n"
    payload_bytes = payload.encode("utf-8")

    lock = _get_lock(path)
    try:
        with lock:
            path.parent.mkdir(parents=True, exist_ok=True)

            # Check size before write. If appending this record would push
            # us over the threshold, rotate first.
            try:
                current_size = path.stat().st_size if path.exists() else 0
            except OSError:
                current_size = 0

            if current_size + len(payload_bytes) > max_bytes:
                _rotate(path, backups)

            with open(path, "ab") as f:
                f.write(payload_bytes)
        return True
    except Exception as e:
        sys.stderr.write(
            f"  WARNING: log write to {path} failed: {type(e).__name__}: {e}\n"
        )
        return False
