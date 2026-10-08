"""Unit tests for resource subscription bookkeeping and capability flags."""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "python"))

from mcp import types  # noqa: E402
from mcp.shared.exceptions import McpError  # noqa: E402
from pydantic import AnyUrl  # noqa: E402

from bridge_mcp_ghidra import state  # noqa: E402
from bridge_mcp_ghidra.server import mcp, _patched_init_options  # noqa: E402
import bridge_mcp_ghidra.resources  # noqa: F401,E402
import bridge_mcp_ghidra.subscriptions as subscriptions  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


class _Session:
    """Plain instance that supports weakrefs (unlike ``object()``)."""

    pass


class TestResourceInterestBookkeeping(unittest.TestCase):
    def setUp(self):
        with state._resource_interest_lock:
            state._resource_interest.clear()

    def tearDown(self):
        with state._resource_interest_lock:
            state._resource_interest.clear()

    def test_remember_read_and_subscribe_are_tracked_separately(self):
        session = _Session()

        async def body():
            state.remember_resource_interest(
                session, uri="ghidra://function/ls/001f4000", read=True
            )
            state.remember_resource_interest(
                session, uri="ghidra://programs", subscribed=True
            )
            known = state.known_resource_uris(session)
            self.assertEqual(
                known,
                {"ghidra://function/ls/001f4000", "ghidra://programs"},
            )
            entry = state._resource_interest[id(session)]
            self.assertIn("ghidra://programs", entry.subscribed_uris)
            self.assertNotIn("ghidra://programs", entry.read_uris)
            state.forget_resource_subscription(session, "ghidra://programs")
            self.assertNotIn("ghidra://programs", entry.subscribed_uris)
            # Read interest survives unsubscribe.
            self.assertIn("ghidra://function/ls/001f4000", entry.read_uris)

        _run(body())

    def test_iter_filters_to_known_uri(self):
        session_a = _Session()
        session_b = _Session()

        async def body():
            state.remember_resource_interest(
                session_a, uri="ghidra://function/ls/aa", read=True
            )
            state.remember_resource_interest(
                session_b, uri="ghidra://function/ls/bb", read=True
            )
            hits = state.iter_resource_interest(uri="ghidra://function/ls/aa")
            self.assertEqual(len(hits), 1)
            self.assertIs(hits[0][1], session_a)

        _run(body())

    def test_weakref_drops_dead_session(self):
        async def body():
            session = _Session()
            state.remember_resource_interest(
                session, uri="ghidra://programs", read=True
            )
            self.assertEqual(len(state._resource_interest), 1)
            del session
            import gc

            gc.collect()
            self.assertEqual(len(state._resource_interest), 0)

        _run(body())


class TestCapabilityPatch(unittest.TestCase):
    def test_resources_advertise_subscribe_and_list_changed(self):
        mcp.settings.stateless_http = False
        opts = _patched_init_options()
        caps = opts.capabilities
        self.assertIsNotNone(caps.resources)
        self.assertTrue(caps.resources.subscribe)
        self.assertTrue(caps.resources.listChanged)
        self.assertIn(types.SubscribeRequest, mcp._mcp_server.request_handlers)
        self.assertIn(types.UnsubscribeRequest, mcp._mcp_server.request_handlers)

    def test_stateless_disables_subscribe_flag(self):
        mcp.settings.stateless_http = True
        try:
            opts = _patched_init_options()
            self.assertFalse(opts.capabilities.resources.subscribe)
            self.assertTrue(opts.capabilities.resources.listChanged)
        finally:
            mcp.settings.stateless_http = False


class TestSubscribeHandlers(unittest.TestCase):
    def setUp(self):
        with state._resource_interest_lock:
            state._resource_interest.clear()
        mcp.settings.stateless_http = False

    def tearDown(self):
        with state._resource_interest_lock:
            state._resource_interest.clear()
        mcp.settings.stateless_http = False
        from bridge_mcp_ghidra import change_poller

        change_poller.stop()

    def test_subscribe_records_interest(self):
        session = _Session()

        async def body():
            with patch.object(
                subscriptions, "_current_session", return_value=session
            ), patch("bridge_mcp_ghidra.change_poller.kick"):
                await subscriptions._on_subscribe(AnyUrl("ghidra://function/ls/001f4000"))
            entry = state._resource_interest[id(session)]
            self.assertIn("ghidra://function/ls/001f4000", entry.subscribed_uris)

        _run(body())

    def test_subscribe_refused_when_stateless(self):
        mcp.settings.stateless_http = True

        async def body():
            with self.assertRaises(McpError):
                await subscriptions._on_subscribe(AnyUrl("ghidra://programs"))

        _run(body())


class TestEmitUpdated(unittest.TestCase):
    def setUp(self):
        with state._resource_interest_lock:
            state._resource_interest.clear()

    def tearDown(self):
        with state._resource_interest_lock:
            state._resource_interest.clear()

    def test_emit_uses_related_request_id_and_skips_unknown_uris(self):
        session = MagicMock()
        session.send_notification = AsyncMock()

        async def body():
            state.remember_resource_interest(
                session, uri="ghidra://function/ls/known", read=True
            )
            n = await subscriptions.emit_resource_updated(
                "ghidra://function/ls/known",
                related_request_id="req-1",
            )
            self.assertEqual(n, 1)
            session.send_notification.assert_awaited()
            kwargs = session.send_notification.await_args.kwargs
            self.assertEqual(kwargs.get("related_request_id"), "req-1")

            session.send_notification.reset_mock()
            n2 = await subscriptions.emit_resource_updated(
                "ghidra://function/ls/unknown",
                related_request_id="req-2",
            )
            self.assertEqual(n2, 0)
            session.send_notification.assert_not_awaited()

        _run(body())

    def test_emit_sends_zero_for_unread_uri_when_only_known(self):
        """Unread URIs get zero notifications under only_known=True.

        This is deliberate, not a gap: resources/updated exists to invalidate
        a cached resources/read. A URI no session has read has nothing to
        invalidate, so fan-out is wasted work and trains clients to treat
        push as discovery. only_known=True is the default; flipping it to
        notify every connected session about unread checkout/function URIs
        would look like a "fix" and silently reintroduce notification
        storms. Reading a URI registers interest and kicks the poller —
        that is the discovery path.
        """
        session = MagicMock()
        session.send_notification = AsyncMock()

        async def body():
            # Interest in an unrelated URI must not leak notifications to
            # an unread checkout URI.
            state.remember_resource_interest(
                session, uri="ghidra://programs", read=True
            )
            n = await subscriptions.emit_resource_updated(
                "ghidra://decompile-tree/tree_unread",
                only_known=True,
            )
            self.assertEqual(n, 0)
            session.send_notification.assert_not_awaited()

        _run(body())


if __name__ == "__main__":
    unittest.main()
