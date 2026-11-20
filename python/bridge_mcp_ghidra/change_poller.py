"""Adaptive poller for program change tokens and tree status revisions.

Catches GUI edits, undo/redo and ``run_ghidra_script`` — everything the
write-hook invalidation path is blind to — at program coarseness, plus the
tree lane that watches ``status_revision`` while a sweep runs. Runs only
while at least one resource URI is known to some session; backs off when quiet
and **exits** when the known set empties (``kick()`` restarts it on the next
read/subscribe).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import unquote

from . import dispatch
from . import state
from . import subscriptions
from .config import logger

_ACTIVE_INTERVAL = 1.5
_QUIET_INTERVAL = 10.0
_QUIET_AFTER_CYCLES = 4  # ~6s of no change before backing off

_poll_task: asyncio.Task | None = None
_last_tokens: dict[str, str] = {}
_last_tree_revisions: dict[str, int] = {}
_quiet_cycles = 0


def kick() -> None:
    """Ensure the poller is running on the current event loop."""
    global _poll_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _poll_task is not None and not _poll_task.done():
        return

    async def _runner() -> None:
        try:
            await _poll_loop()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Change-token poller crashed")

    _poll_task = loop.create_task(_runner(), name="ghidra-change-token-poller")


def stop() -> None:
    """Cancel a running poller (used by tests)."""
    global _poll_task
    if _poll_task is not None and not _poll_task.done():
        _poll_task.cancel()
    _poll_task = None
    _last_tokens.clear()
    _last_tree_revisions.clear()


async def _poll_loop() -> None:
    global _quiet_cycles
    while True:
        known = state.known_resource_uris()
        if not known:
            _last_tokens.clear()
            _last_tree_revisions.clear()
            _quiet_cycles = 0
            # Exit rather than sleep forever: asyncio.run() in tests (and a
            # quiet process with no sessions) must not keep a zombie task.
            return

        snapshot = state.get_connection_snapshot()
        if snapshot.mode == "none":
            # No Ghidra yet — wait briefly; kick() will have us running once a
            # session exists, and we must not block the loop on connection retries.
            await asyncio.sleep(_ACTIVE_INTERVAL)
            continue

        any_change = False

        programs = _programs_from_uris(known)
        for program in programs:
            token = await _fetch_token(program)
            if token is None:
                continue
            previous = _last_tokens.get(program)
            _last_tokens[program] = token
            if previous is None or previous == token:
                continue
            any_change = True
            logger.debug(
                "Change token for %s moved %s → %s; invalidating known URIs",
                program, previous, token,
            )
            await _invalidate_program(program)

        # Second lane: a running sweep moves status_revision without touching
        # the program modification number, so the token lane alone is blind.
        for uri in _tree_uris(known):
            revision = await _fetch_tree_revision(uri)
            if revision is None:
                continue
            previous = _last_tree_revisions.get(uri)
            _last_tree_revisions[uri] = revision
            if previous is None or previous == revision:
                continue
            any_change = True
            logger.debug(
                "Checkout status_revision for %s moved %s → %s",
                uri, previous, revision,
            )
            await subscriptions.emit_resource_updated(uri)

        if any_change:
            _quiet_cycles = 0
            interval = _ACTIVE_INTERVAL
        else:
            _quiet_cycles += 1
            interval = (
                _ACTIVE_INTERVAL
                if _quiet_cycles < _QUIET_AFTER_CYCLES
                else _QUIET_INTERVAL
            )
        await asyncio.sleep(interval)


async def _fetch_token(program: str) -> str | None:
    """The program's change token: saved time, open epoch and modification number.

    Compared whole. The modification number alone starts over each time the program is
    opened, so after a server restart it could equal the last value seen and a stale cache
    would survive; the epoch makes every reopen a change."""
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/get_change_token", params={"program": program})
            )
        )
        payload = json.loads(raw)
        if isinstance(payload, dict) and payload.get("token"):
            return str(payload["token"])
    except Exception as e:
        logger.debug("get_change_token(%s) failed: %s", program, e)
    return None


async def _fetch_tree_revision(uri: str) -> int | None:
    tree_id = uri[len("ghidra://decompile-tree/") :]
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get(
                    "/decompile_tree_status", params={"tree": tree_id}
                )
            )
        )
        payload = json.loads(raw)
        if isinstance(payload, dict) and "status_revision" in payload:
            return int(payload["status_revision"])
    except Exception as e:
        logger.debug("decompile_tree_status(%s) failed: %s", tree_id, e)
    return None


async def _invalidate_program(program: str) -> None:
    from .invalidation import _known_uris_for_program  # local import: avoid cycle at load

    uris = _known_uris_for_program(program)
    # Cap: a coarse program-wide bump should not storm thousands of URIs.
    if len(uris) > 64:
        await subscriptions.emit_resource_list_changed()
        if "ghidra://programs" in uris:
            await subscriptions.emit_resource_updated("ghidra://programs")
        return
    for uri in sorted(uris):
        await subscriptions.emit_resource_updated(uri)
    await subscriptions.emit_resource_list_changed()


def _programs_from_uris(uris: set[str]) -> set[str]:
    """Extract program names from ``ghidra://function|program|search/{program}/...``."""
    programs: set[str] = set()
    for uri in uris:
        if not uri.startswith("ghidra://"):
            continue
        rest = uri[len("ghidra://") :]
        parts = rest.split("/")
        if len(parts) < 2:
            continue
        # Segment 2 of ghidra://decompile-tree/<id> is the id, not a program —
        # treating it as one would burn /get_change_token every cycle.
        if parts[0] == "tree":
            continue
        if parts[0] in ("function", "program", "search"):
            programs.add(unquote(parts[1]))
    return programs


def _tree_uris(uris: set[str]) -> set[str]:
    """Known ``ghidra://decompile-tree/{id}`` URIs (no deeper path)."""
    out: set[str] = set()
    prefix = "ghidra://decompile-tree/"
    for uri in uris:
        if not uri.startswith(prefix):
            continue
        rest = uri[len(prefix) :]
        if rest and "/" not in rest:
            out.add(uri)
    return out
