"""Tree lane of the change-token poller.

A running sweep moves ``status_revision`` without touching the program
modification number, so the token lane alone is blind to it.
"""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "python"))

from bridge_mcp_ghidra import change_poller  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


class TestProgramsFromUrisDecompTree(unittest.TestCase):
    def test_tree_id_is_not_treated_as_a_program(self):
        uris = {
            "ghidra://decompile-tree/tree_7de33ad7",
            "ghidra://function/ls/001f4000",
            "ghidra://program/driver.dll/changes",
        }
        programs = change_poller._programs_from_uris(uris)
        self.assertEqual(programs, {"ls", "driver.dll"})
        self.assertNotIn("tree_7de33ad7", programs)

    def test_tree_uris_extracts_only_tree_resources(self):
        uris = {
            "ghidra://decompile-tree/tree_aaa",
            "ghidra://decompile-tree/tree_bbb/extra",  # not a template instance
            "ghidra://function/ls/001f4000",
        }
        self.assertEqual(
            change_poller._tree_uris(uris),
            {"ghidra://decompile-tree/tree_aaa"},
        )


class TestTreeRevisionPolling(unittest.TestCase):
    def setUp(self):
        change_poller.stop()
        change_poller._last_tree_revisions.clear()
        change_poller._last_tokens.clear()
        change_poller._quiet_cycles = 0

    def tearDown(self):
        change_poller.stop()

    def test_status_revision_move_emits_exactly_once(self):
        uri = "ghidra://decompile-tree/tree_7de33ad7"
        emitted: list[str] = []
        revisions = iter([10, 11, 11])

        async def fake_fetch(u):
            self.assertEqual(u, uri)
            return next(revisions)

        async def fake_emit(u, **kw):
            emitted.append(u)
            return 1

        class _Snap:
            mode = "tcp"

        async def body():
            # Seed so the first observed revision is a baseline, not an emit.
            change_poller._last_tree_revisions[uri] = 10
            with mock.patch.object(
                change_poller.state, "known_resource_uris", return_value={uri}
            ), mock.patch.object(
                change_poller.state, "get_connection_snapshot", return_value=_Snap()
            ), mock.patch.object(
                change_poller, "_fetch_tree_revision", side_effect=fake_fetch
            ), mock.patch.object(
                change_poller.subscriptions, "emit_resource_updated", side_effect=fake_emit
            ), mock.patch.object(
                change_poller, "_programs_from_uris", return_value=set()
            ), mock.patch.object(
                change_poller.asyncio, "sleep", side_effect=[None, None, asyncio.CancelledError()]
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await change_poller._poll_loop()

        _run(body())
        self.assertEqual(emitted, [uri])

    def test_unchanged_revision_emits_nothing(self):
        uri = "ghidra://decompile-tree/tree_7de33ad7"
        emitted: list[str] = []

        async def fake_fetch(u):
            return 42

        async def fake_emit(u, **kw):
            emitted.append(u)
            return 1

        class _Snap:
            mode = "tcp"

        async def body():
            change_poller._last_tree_revisions[uri] = 42
            with mock.patch.object(
                change_poller.state, "known_resource_uris", return_value={uri}
            ), mock.patch.object(
                change_poller.state, "get_connection_snapshot", return_value=_Snap()
            ), mock.patch.object(
                change_poller, "_fetch_tree_revision", side_effect=fake_fetch
            ), mock.patch.object(
                change_poller.subscriptions, "emit_resource_updated", side_effect=fake_emit
            ), mock.patch.object(
                change_poller, "_programs_from_uris", return_value=set()
            ), mock.patch.object(
                change_poller.asyncio, "sleep", side_effect=[None, asyncio.CancelledError()]
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await change_poller._poll_loop()

        _run(body())
        self.assertEqual(emitted, [])

    def test_fetch_tree_revision_reads_status_revision(self):
        captured = {}

        def fake_dispatch(endpoint, params=None):
            captured["endpoint"] = endpoint
            captured["params"] = params
            return json.dumps({"tree_id": "tree_x", "status_revision": 7})

        async def body():
            with mock.patch.object(
                change_poller.dispatch, "dispatch_get", side_effect=fake_dispatch
            ), mock.patch.object(
                change_poller.dispatch, "raise_on_failure", side_effect=lambda t: t
            ), mock.patch.object(
                change_poller.state, "run_blocking_ghidra_call",
                side_effect=lambda func, *a, **kw: func(),
            ):
                rev = await change_poller._fetch_tree_revision(
                    "ghidra://decompile-tree/tree_x"
                )
            self.assertEqual(rev, 7)
            self.assertEqual(captured["endpoint"], "/decompile_tree_status")
            self.assertEqual(captured["params"], {"tree": "tree_x"})

        _run(body())


if __name__ == "__main__":
    unittest.main()


class TestChangeTokenSurvivesReopen(unittest.TestCase):
    """The modification number starts over each time a program opens. After a server
    restart it can land on the value the poller last saw; the token's epoch part makes
    that a change, so cached function resources are invalidated."""

    def test_the_token_is_compared_whole(self):
        payloads = iter([
            {"token": "1790000000000:aaaa:7", "modification_number": 7},
            {"token": "1790000000000:bbbb:7", "modification_number": 7},
        ])

        async def fake_blocking(fn):
            return json.dumps(next(payloads))

        async def body():
            with mock.patch.object(change_poller.state, "run_blocking_ghidra_call", side_effect=fake_blocking):
                first = await change_poller._fetch_token("fw")
                second = await change_poller._fetch_token("fw")
            return first, second

        first, second = _run(body())
        self.assertEqual(first, "1790000000000:aaaa:7")
        self.assertNotEqual(first, second, "same counter in a new open must still differ")
