"""MCP resource subscriptions and invalidation emit helpers.

Commit 5 wires subscribe/unsubscribe and the capability flags. Commit 6 hooks
writes to call :func:`emit_resource_updated` / :func:`emit_resource_list_changed`.
Nothing here talks to Ghidra — it only tracks which sessions already know a URI
and how to reach them over the active transport.
"""

from __future__ import annotations

from mcp import types
from mcp.shared.exceptions import McpError
from pydantic import AnyUrl

from . import state
from .config import logger
from .server import mcp


def _current_session():
    """Session for the in-flight MCP request, or None outside a request."""
    try:
        return mcp._mcp_server.request_context.session
    except LookupError:
        return None


def _current_request_id():
    try:
        return mcp._mcp_server.request_context.request_id
    except LookupError:
        return None


def note_resource_read(uri: str) -> None:
    """Record that the current session has read ``uri`` (cache interest)."""
    session = _current_session()
    if session is None:
        return
    state.remember_resource_interest(session, uri=str(uri), read=True)
    from . import change_poller

    change_poller.kick()


def _subscriptions_supported() -> bool:
    """False under ``--stateless-http``: there is no session to hang a sub on."""
    return not bool(getattr(mcp.settings, "stateless_http", False))


@mcp._mcp_server.subscribe_resource()
async def _on_subscribe(uri: AnyUrl) -> None:
    if not _subscriptions_supported():
        raise McpError(
            types.ErrorData(
                code=types.INVALID_REQUEST,
                message="resources/subscribe is unavailable under --stateless-http "
                        "(no durable session to deliver resources/updated on)",
            )
        )
    session = _current_session()
    if session is None:
        raise McpError(
            types.ErrorData(
                code=types.INVALID_REQUEST,
                message="resources/subscribe requires an active MCP session",
            )
        )
    state.remember_resource_interest(session, uri=str(uri), subscribed=True)
    logger.debug("Resource subscribed: %s", uri)
    from . import change_poller

    change_poller.kick()


@mcp._mcp_server.unsubscribe_resource()
async def _on_unsubscribe(uri: AnyUrl) -> None:
    session = _current_session()
    if session is None:
        return
    state.forget_resource_subscription(session, str(uri))
    logger.debug("Resource unsubscribed: %s", uri)


async def _send_updated(session, uri: str, related_request_id) -> None:
    notification = types.ServerNotification(
        types.ResourceUpdatedNotification(
            params=types.ResourceUpdatedNotificationParams(uri=AnyUrl(uri)),
        )
    )
    # Prefer send_notification with related_request_id: send_resource_updated()
    # omits it, and streamable-HTTP then routes the notice to the standalone GET
    # stream where a POST-only client never sees it (same trap as progress).
    await session.send_notification(notification, related_request_id=related_request_id)


async def _send_list_changed(session, related_request_id) -> None:
    notification = types.ServerNotification(types.ResourceListChangedNotification())
    await session.send_notification(notification, related_request_id=related_request_id)


async def emit_resource_updated(
    uri: str,
    *,
    related_request_id=None,
    only_known: bool = True,
) -> int:
    """Notify interested sessions that ``uri``'s body changed.

    Returns the number of sessions successfully notified. When called inside a
    tool handler on streamable-HTTP, pass ``related_request_id`` (usually the
    tool request's id) so the notification rides that POST's SSE stream.
    """
    uri_s = str(uri)
    rid = related_request_id if related_request_id is not None else _current_request_id()
    targets = state.iter_resource_interest(uri=uri_s if only_known else None)
    sent = 0
    for _loop, session, _entry in targets:
        try:
            await _send_updated(session, uri_s, rid)
            sent += 1
        except Exception as e:
            logger.debug("resources/updated to session failed: %s", e)
            state.drop_resource_interest(session)
    return sent


async def emit_resource_list_changed(*, related_request_id=None) -> int:
    """Tell interested sessions to re-fetch ``resources/list`` / templates."""
    rid = related_request_id if related_request_id is not None else _current_request_id()
    # Any session that has touched a resource cares about listing churn (rename
    # of an index row, new program, etc.).
    targets = state.iter_resource_interest()
    sent = 0
    for _loop, session, _entry in targets:
        try:
            await _send_list_changed(session, rid)
            sent += 1
        except Exception as e:
            logger.debug("resources/list_changed to session failed: %s", e)
            state.drop_resource_interest(session)
    return sent


def notify_resource_updated_from_worker(uri: str) -> int:
    """Worker-thread variant for the change-token poller (no request to hitch to)."""
    uri_s = str(uri)
    sent = 0
    for loop, session, _entry in state.iter_resource_interest(uri=uri_s):
        ok = state.schedule_on_session_loop(loop, _send_updated(session, uri_s, None))
        if ok:
            sent += 1
        else:
            state.drop_resource_interest(session)
    return sent


def notify_resource_list_changed_from_worker() -> int:
    sent = 0
    for loop, session, _entry in state.iter_resource_interest():
        ok = state.schedule_on_session_loop(loop, _send_list_changed(session, None))
        if ok:
            sent += 1
        else:
            state.drop_resource_interest(session)
    return sent
