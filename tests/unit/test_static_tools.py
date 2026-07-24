"""
Unit tests for the always-on static MCP tools (``bridge_mcp_ghidra/static_tools.py``).

These are the management tools every MCP client sees *before* it has connected
to anything -- list_instances, connect_instance, list_tool_groups,
load_tool_group, unload_tool_group, check_tools, search_tools, import_file --
so they are the highest-traffic Python in the repo. A coverage audit put
static_tools.py at 42%: registration was tested (test_mcp_tools.py asserts the
tools exist on the FastMCP server) but almost every tool *body* was not. The
uncovered ranges were the whole of load_tool_group / unload_tool_group /
check_tools / search_tools / import_file plus connect_instance's failure arms.
This file closes that gap.

Everything here runs offline: discovery, transport and dispatch are mocked.

Mock-patch targets follow the project convention (CLAUDE.md): cross-module
calls are module-qualified, so the ONE canonical target is the callee's own
module -- e.g. ``bridge.dispatch.dispatch_post``, ``bridge.registry._load_group``.
Patching the flat ``bridge_mcp_ghidra.*`` re-exports would not intercept the
call sites static_tools actually uses and the tests would pass vacuously.
"""

import asyncio
import contextlib
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_ctx():
    """A minimal FastMCP Context double.

    ``registry._notify_tools_changed`` only fires when ``ctx._request_context``
    is not None, so the double must set it; the AsyncMock lets tests assert the
    tools/list_changed notification was actually sent (clients that cache
    tools/list depend on it after load/unload).
    """
    session = SimpleNamespace(
        send_tool_list_changed=AsyncMock(),
        send_log_message=AsyncMock(),
    )
    return SimpleNamespace(
        _request_context=object(),
        request_context=SimpleNamespace(session=session),
    )


@contextlib.contextmanager
def isolated_bridge():
    """Snapshot and restore every mutable bridge global the static tools touch.

    load_tool_group/unload_tool_group register and unregister *real* tools on
    the module-level FastMCP singleton, and connect_instance rewrites the
    connection state. Without a full save/restore these tests would leak into
    the rest of the unit suite (which asserts things like "lazy mode is off"
    and "the static tools are registered").
    """
    import bridge_mcp_ghidra as bridge

    saved_tools = dict(bridge.mcp._tool_manager._tools)
    saved_dynamic = list(bridge.state._dynamic_tool_names)
    saved_schema = list(bridge.state._full_schema)
    saved_loaded = set(bridge.state._loaded_groups)
    saved_defaults = set(bridge.state._default_groups)
    saved_conn = (
        bridge.state._active_socket,
        bridge.state._active_tcp,
        bridge.state._transport_mode,
        bridge.state._connected_project,
        bridge.state._lazy_mode,
    )
    try:
        yield bridge
    finally:
        bridge.mcp._tool_manager._tools.clear()
        bridge.mcp._tool_manager._tools.update(saved_tools)
        bridge.state._dynamic_tool_names[:] = saved_dynamic
        # _full_schema and _default_groups are *rebound* by the production
        # code, so they must be restored by assignment, not in-place edit.
        bridge.state._full_schema = saved_schema
        bridge.state._default_groups = saved_defaults
        bridge.state._loaded_groups.clear()
        bridge.state._loaded_groups.update(saved_loaded)
        (
            bridge.state._active_socket,
            bridge.state._active_tcp,
            bridge.state._transport_mode,
            bridge.state._connected_project,
            bridge.state._lazy_mode,
        ) = saved_conn


def tool_def(name, category, description="", endpoint=None):
    return {
        "name": name,
        "description": description,
        "endpoint": endpoint or f"/{name}",
        "http_method": "GET",
        "category": category,
        "input_schema": {"type": "object", "properties": {}},
    }


def seed_schema(bridge, defs, loaded_groups=frozenset()):
    """Install `defs` as the cached /mcp/schema and register `loaded_groups`."""
    bridge.registry.register_tools_from_schema(list(defs), groups=set(loaded_groups))


# ---------------------------------------------------------------------------
# list_instances
# ---------------------------------------------------------------------------


class TestListInstances(unittest.TestCase):
    """list_instances is the first call every client makes; its job is to
    annotate each discovered instance with a correct `connected` flag."""

    def test_no_instances_returns_note(self):
        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[]
        ), patch.object(
            bridge.discovery, "discover_active_tcp_instance", return_value=None
        ):
            data = json.loads(bridge.list_instances())

        self.assertEqual(data["instances"], [])
        self.assertIn("No running Ghidra instances", data["note"])

    def test_marks_only_the_active_tcp_instance_connected(self):
        """The TCP fallback entry is `connected` only when it is the URL the
        bridge is actually dialing -- a stale/other-port instance must read as
        disconnected."""
        active = {"transport": "tcp", "url": "http://127.0.0.1:8089", "project": "A"}
        other = {"transport": "tcp", "url": "http://127.0.0.1:8090", "project": "B"}

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[dict(other)]
        ), patch.object(
            bridge.discovery, "discover_active_tcp_instance", return_value=dict(active)
        ):
            bridge.state._transport_mode = "tcp"
            bridge.state._active_tcp = "http://127.0.0.1:8089"
            bridge.state._active_socket = None
            data = json.loads(bridge.list_instances())

        by_url = {i["url"]: i["connected"] for i in data["instances"]}
        self.assertTrue(by_url["http://127.0.0.1:8089"])
        self.assertFalse(by_url["http://127.0.0.1:8090"])

    def test_uds_instance_connected_by_socket_path(self):
        uds = {"socket": "/tmp/ghidra-1.sock", "pid": 1, "project": "A"}
        uds2 = {"socket": "/tmp/ghidra-2.sock", "pid": 2, "project": "B"}

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[dict(uds), dict(uds2)]
        ), patch.object(
            bridge.discovery, "discover_active_tcp_instance", return_value=None
        ):
            bridge.state._transport_mode = "uds"
            bridge.state._active_socket = "/tmp/ghidra-1.sock"
            bridge.state._active_tcp = None
            data = json.loads(bridge.list_instances())

        by_socket = {i["socket"]: i["connected"] for i in data["instances"]}
        self.assertTrue(by_socket["/tmp/ghidra-1.sock"])
        self.assertFalse(by_socket["/tmp/ghidra-2.sock"])

    def test_uds_instance_connected_via_enriched_tcp_url(self):
        """On Windows the bridge dials a UDS-discovered instance over the TCP
        url discovery enriched it with. Its socket path will never match
        _active_socket, so the url must count as connected too -- otherwise
        list_instances reports 'nothing connected' on a healthy Windows bridge."""
        uds = {
            "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
            "pid": 9020,
            "project": "diablo2",
            "url": "http://127.0.0.1:8089",
        }

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[dict(uds)]
        ), patch.object(
            bridge.discovery, "discover_active_tcp_instance", return_value=None
        ):
            bridge.state._transport_mode = "tcp"
            bridge.state._active_tcp = "http://127.0.0.1:8089"
            bridge.state._active_socket = None
            data = json.loads(bridge.list_instances())

        self.assertTrue(data["instances"][0]["connected"])


# ---------------------------------------------------------------------------
# connect_instance -- failure arms
# ---------------------------------------------------------------------------


class TestConnectInstanceFailures(unittest.TestCase):
    """connect_instance's happy paths are covered in test_mcp_tools.py /
    test_bridge_utils.py. These are the error arms, which were entirely
    untested despite being what a user hits when Ghidra is down or
    misconfigured."""

    def test_uds_schema_fetch_failure_reports_socket(self):
        one = [{"project": "diablo2", "socket": "/tmp/d2.sock", "pid": 42}]

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=one
        ), patch.object(
            bridge.transport, "uds_supported", return_value=True
        ), patch.object(
            bridge.registry,
            "_fetch_and_register_schema",
            side_effect=RuntimeError("HTTP 503"),
        ):
            data = json.loads(asyncio.run(bridge.connect_instance("diablo2")))

        self.assertIn("Schema fetch failed", data["error"])
        self.assertIn("HTTP 503", data["error"])
        self.assertEqual(data["socket"], "/tmp/d2.sock")

    def test_substring_project_match_is_accepted_after_exact_match_fails(self):
        """connect_instance("diablo") should find the "diablo2" project --
        agents routinely pass a prefix. The substring pass runs only after the
        exact pass misses, so it needs its own case."""
        one = [{"project": "diablo2", "socket": "/tmp/d2.sock", "pid": 42}]

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=one
        ), patch.object(
            bridge.transport, "uds_supported", return_value=True
        ), patch.object(
            bridge.registry, "_fetch_and_register_schema", return_value=3
        ):
            bridge.state._full_schema = []
            data = json.loads(asyncio.run(bridge.connect_instance("diablo")))

        self.assertTrue(data["connected"])
        self.assertEqual(data["transport"], "uds")
        self.assertEqual(data["project"], "diablo2")
        self.assertEqual(data["socket"], "/tmp/d2.sock")

    def test_uds_match_without_af_unix_routes_to_the_enriched_tcp_url(self):
        """Windows CPython has no socket.AF_UNIX, so a matched UDS instance
        cannot be dialed over its socket. connect_instance must use the TCP url
        discovery recorded for THAT instance rather than failing the handshake
        (or, worse, defaulting to whatever is on port 8089)."""
        one = [
            {
                "project": "diablo2",
                "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
                "pid": 9020,
                "url": "http://127.0.0.1:8091",
            }
        ]
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_URL"}

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=one
        ), patch.object(
            bridge.transport, "uds_supported", return_value=False
        ), patch.object(
            bridge.discovery, "_scan_tcp_for_project"
        ) as scan, patch.object(
            bridge.registry, "_fetch_and_register_schema", return_value=5
        ), patch.dict(
            os.environ, env, clear=True
        ):
            bridge.state._full_schema = []
            data = json.loads(asyncio.run(bridge.connect_instance("diablo2")))
            mode = bridge.state._transport_mode
            socket_path = bridge.state._active_socket

        self.assertTrue(data["connected"])
        self.assertEqual(data["transport"], "tcp")
        self.assertEqual(data["url"], "http://127.0.0.1:8091")
        self.assertEqual(mode, "tcp")
        self.assertIsNone(socket_path)
        scan.assert_not_called()

    def test_refuses_non_local_url_from_env(self):
        """GHIDRA_MCP_URL wins over discovery, so it is also the one place a
        remote/hostile URL can enter. validate_server_url must refuse it before
        any schema fetch happens."""
        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[]
        ), patch.object(
            bridge.registry, "_fetch_and_register_schema"
        ) as fetch, patch.dict(
            os.environ, {"GHIDRA_MCP_URL": "http://evil.example.com:8089"}
        ):
            data = json.loads(asyncio.run(bridge.connect_instance("anything")))

        self.assertIn("Refusing to connect to invalid TCP URL", data["error"])
        self.assertIn("evil.example.com", data["error"])
        fetch.assert_not_called()

    def test_tcp_failure_resets_transport_state(self):
        """A failed TCP connect must leave the bridge cleanly disconnected --
        if _transport_mode stayed "tcp" every later dispatch would try to talk
        to a dead endpoint instead of reconnecting."""
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_URL"}

        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[]
        ), patch.object(
            bridge.discovery, "_scan_tcp_for_project", return_value=None
        ), patch.object(
            bridge.registry,
            "_fetch_and_register_schema",
            side_effect=ConnectionRefusedError("connection refused"),
        ), patch.dict(
            os.environ, env, clear=True
        ):
            bridge.state._transport_mode = "none"
            data = json.loads(asyncio.run(bridge.connect_instance("diablo2")))

            self.assertEqual(bridge.state._transport_mode, "none")
            self.assertIsNone(bridge.state._active_tcp)

        self.assertIn("No instance matching 'diablo2'", data["error"])
        self.assertEqual(data["available"], [])


# ---------------------------------------------------------------------------
# list_tool_groups
# ---------------------------------------------------------------------------


class TestListToolGroups(unittest.TestCase):
    def test_errors_without_a_connection(self):
        with isolated_bridge() as bridge:
            bridge.state._full_schema = []
            data = json.loads(bridge.list_tool_groups())

        self.assertIn("connect_instance", data["error"])

    def test_reports_counts_loaded_and_default_flags(self):
        defs = [
            tool_def("stg_alpha_one", "stg_alpha"),
            tool_def("stg_alpha_two", "stg_alpha"),
            tool_def("stg_beta_one", "stg_beta"),
        ]
        with isolated_bridge() as bridge:
            bridge.state._default_groups = {"stg_alpha"}
            seed_schema(bridge, defs, loaded_groups={"stg_alpha"})
            data = json.loads(bridge.list_tool_groups())

        self.assertEqual(data["total_tools"], 3)
        groups = {g["group"]: g for g in data["groups"]}
        self.assertEqual(groups["stg_alpha"]["tool_count"], 2)
        self.assertTrue(groups["stg_alpha"]["loaded"])
        self.assertTrue(groups["stg_alpha"]["default"])
        self.assertFalse(groups["stg_beta"]["loaded"])
        self.assertEqual(groups["stg_beta"]["tools"], ["stg_beta_one"])


# ---------------------------------------------------------------------------
# load_tool_group
# ---------------------------------------------------------------------------


class TestLoadToolGroup(unittest.TestCase):
    """load_tool_group is how a --lazy client makes a category callable. Its
    whole body (lines 233-278 at the time of the audit) was uncovered."""

    def test_errors_without_a_connection(self):
        with isolated_bridge() as bridge:
            bridge.state._full_schema = []
            data = json.loads(asyncio.run(bridge.load_tool_group("function")))

        self.assertIn("connect_instance", data["error"])

    def test_loads_group_registers_tools_and_notifies(self):
        defs = [
            tool_def("stg_load_a", "stg_alpha"),
            tool_def("stg_load_b", "stg_beta"),
        ]
        ctx = make_ctx()
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups=set())
            data = json.loads(
                asyncio.run(bridge.load_tool_group("stg_beta", ctx=ctx))
            )
            # The tool must be genuinely callable now, not merely reported.
            registered = "stg_load_b" in bridge.mcp._tool_manager._tools
            unrelated = "stg_load_a" in bridge.mcp._tool_manager._tools

        self.assertEqual(data["loaded"], "stg_beta")
        self.assertEqual(data["new_tools"], 1)
        self.assertEqual(data["tools"], ["stg_load_b"])
        self.assertEqual(data["total_loaded"], 1)
        self.assertEqual(data["loaded_groups"], ["stg_beta"])
        self.assertTrue(registered)
        self.assertFalse(unrelated, "loading stg_beta must not pull in stg_alpha")
        ctx.request_context.session.send_tool_list_changed.assert_awaited_once()

    def test_all_loads_every_group_once(self):
        defs = [
            tool_def("stg_all_a", "stg_alpha"),
            tool_def("stg_all_b", "stg_beta"),
            tool_def("stg_all_c", "stg_beta"),
        ]
        ctx = make_ctx()
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups={"stg_alpha"})
            data = json.loads(asyncio.run(bridge.load_tool_group("all", ctx=ctx)))

        self.assertEqual(data["loaded"], "all")
        # stg_all_a was already loaded, so only the two beta tools are new.
        self.assertEqual(data["new_tools"], 2)
        self.assertEqual(data["new_tool_names"], ["stg_all_b", "stg_all_c"])
        self.assertEqual(data["total_loaded"], 3)
        ctx.request_context.session.send_tool_list_changed.assert_awaited_once()

    def test_all_with_nothing_new_does_not_notify(self):
        """A no-op load must not emit tools/list_changed -- spurious
        notifications make conforming clients re-fetch the whole tool list."""
        defs = [tool_def("stg_noop_a", "stg_alpha")]
        ctx = make_ctx()
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups={"stg_alpha"})
            data = json.loads(asyncio.run(bridge.load_tool_group("all", ctx=ctx)))

        self.assertEqual(data["new_tools"], 0)
        ctx.request_context.session.send_tool_list_changed.assert_not_awaited()

    def test_already_loaded_group_returns_its_tool_names(self):
        """Re-loading must tell the agent what is already callable rather than
        reporting an error -- otherwise a retry looks like a failure."""
        defs = [
            tool_def("stg_dup_b", "stg_beta"),
            tool_def("stg_dup_a", "stg_beta"),
        ]
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups={"stg_beta"})
            data = json.loads(asyncio.run(bridge.load_tool_group("stg_beta")))

        self.assertIn("already loaded", data["message"])
        self.assertEqual(data["tools"], ["stg_dup_a", "stg_dup_b"])
        self.assertNotIn("error", data)

    def test_unknown_group_lists_available_groups(self):
        defs = [
            tool_def("stg_avail_a", "stg_alpha"),
            tool_def("stg_avail_b", "stg_beta"),
        ]
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups=set())
            data = json.loads(asyncio.run(bridge.load_tool_group("nope")))

        self.assertIn("No tools found for group 'nope'", data["error"])
        self.assertEqual(data["available_groups"], ["stg_alpha", "stg_beta"])


# ---------------------------------------------------------------------------
# unload_tool_group
# ---------------------------------------------------------------------------


class TestUnloadToolGroup(unittest.TestCase):
    def test_default_group_is_protected(self):
        with isolated_bridge() as bridge:
            bridge.state._default_groups = {"stg_alpha"}
            data = json.loads(asyncio.run(bridge.unload_tool_group("stg_alpha")))

        self.assertIn("Cannot unload default group", data["error"])
        self.assertEqual(data["default_groups"], ["stg_alpha"])

    def test_unloading_removes_tools_and_notifies(self):
        defs = [
            tool_def("stg_unload_a", "stg_alpha"),
            tool_def("stg_unload_b", "stg_beta"),
        ]
        ctx = make_ctx()
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups={"stg_alpha", "stg_beta"})
            data = json.loads(
                asyncio.run(bridge.unload_tool_group("stg_beta", ctx=ctx))
            )
            still_registered = "stg_unload_b" in bridge.mcp._tool_manager._tools
            sibling_kept = "stg_unload_a" in bridge.mcp._tool_manager._tools

        self.assertEqual(data["unloaded"], "stg_beta")
        self.assertEqual(data["removed_tools"], 1)
        self.assertEqual(data["total_loaded"], 1)
        self.assertEqual(data["loaded_groups"], ["stg_alpha"])
        self.assertFalse(still_registered, "unloaded tool is still callable")
        self.assertTrue(sibling_kept, "unload leaked into another group")
        ctx.request_context.session.send_tool_list_changed.assert_awaited_once()

    def test_unloading_an_unloaded_group_is_a_message_not_an_error(self):
        ctx = make_ctx()
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, [tool_def("stg_idle_a", "stg_alpha")], loaded_groups=set())
            data = json.loads(
                asyncio.run(bridge.unload_tool_group("stg_alpha", ctx=ctx))
            )

        self.assertIn("not loaded", data["message"])
        self.assertNotIn("error", data)
        ctx.request_context.session.send_tool_list_changed.assert_not_awaited()


# ---------------------------------------------------------------------------
# check_tools
# ---------------------------------------------------------------------------


class TestCheckTools(unittest.TestCase):
    """check_tools is the agent's "can I call this right now?" probe. Its
    three-way classification (callable / not_loaded / not_found) and the
    remediation hint it returns were completely untested."""

    def test_blank_input_is_rejected(self):
        with isolated_bridge() as bridge:
            data = json.loads(asyncio.run(bridge.check_tools("  , ,, ")))

        self.assertIn("comma-separated", data["error"])

    def test_classifies_static_loaded_unloaded_and_unknown(self):
        defs = [
            tool_def("stg_check_loaded", "stg_alpha"),
            tool_def("stg_check_unloaded", "stg_beta"),
        ]
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, defs, loaded_groups={"stg_alpha"})
            data = json.loads(
                asyncio.run(
                    bridge.check_tools(
                        " list_instances , stg_check_loaded ,"
                        "stg_check_unloaded,stg_check_missing"
                    )
                )
            )

        results = data["results"]
        # Static tools are callable without any connection at all.
        self.assertEqual(results["list_instances"]["status"], "callable")
        self.assertEqual(results["list_instances"]["type"], "static")
        # A dynamic tool from a loaded group is callable and reports its group.
        self.assertEqual(results["stg_check_loaded"]["status"], "callable")
        self.assertEqual(results["stg_check_loaded"]["group"], "stg_alpha")
        # A known tool whose group is not loaded gets the exact fix-up call.
        self.assertEqual(results["stg_check_unloaded"]["status"], "not_loaded")
        self.assertEqual(
            results["stg_check_unloaded"]["fix"], 'load_tool_group("stg_beta")'
        )
        # An unknown name is not_found -- no group, no fix.
        self.assertEqual(results["stg_check_missing"], {"status": "not_found"})
        self.assertEqual(data["summary"], "2/4 callable")


# ---------------------------------------------------------------------------
# search_tools
# ---------------------------------------------------------------------------


class TestSearchTools(unittest.TestCase):
    """search_tools lets a --lazy client find a tool without loading every
    group. Ranking (name hits beat description hits) is the whole point, so it
    is asserted directly rather than just checking the call returns JSON."""

    # Deliberate ordering: the description-only match is listed FIRST, so a
    # ranking bug that scored name and description hits equally would leave it
    # first (the sort is stable) and the ordering assertions below would fail.
    # Listing the name match first would make those assertions vacuous.
    _DEFS = [
        tool_def("stg_list_globals", "stg_globals", "List globals; rename is elsewhere"),
        tool_def("stg_rename_function", "stg_function", "Rename a function by address"),
        tool_def("stg_unrelated", "stg_misc", "Nothing to see here"),
    ]

    def test_blank_query_is_rejected(self):
        with isolated_bridge() as bridge:
            data = json.loads(asyncio.run(bridge.search_tools("   ")))

        self.assertIn("search keywords", data["error"])

    def test_name_hits_outrank_description_hits(self):
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, self._DEFS, loaded_groups=set())
            data = json.loads(asyncio.run(bridge.search_tools("rename")))

        names = [m["name"] for m in data["matches"]]
        self.assertEqual(names, ["stg_rename_function", "stg_list_globals"])
        self.assertEqual(data["match_count"], 2)
        self.assertEqual(data["returned"], 2)
        self.assertEqual(data["query"], "rename")

    def test_unloaded_match_carries_the_load_fix(self):
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, self._DEFS, loaded_groups={"stg_function"})
            data = json.loads(asyncio.run(bridge.search_tools("rename")))

        by_name = {m["name"]: m for m in data["matches"]}
        self.assertEqual(by_name["stg_rename_function"]["status"], "callable")
        self.assertNotIn("fix", by_name["stg_rename_function"])
        self.assertEqual(by_name["stg_list_globals"]["status"], "not_loaded")
        self.assertEqual(
            by_name["stg_list_globals"]["fix"], 'load_tool_group("stg_globals")'
        )

    def test_limit_caps_results_but_match_count_stays_honest(self):
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, self._DEFS, loaded_groups=set())
            data = json.loads(asyncio.run(bridge.search_tools("rename", limit=1)))

        self.assertEqual(data["returned"], 1)
        self.assertEqual(data["match_count"], 2)
        self.assertEqual(data["matches"][0]["name"], "stg_rename_function")

    def test_non_positive_limit_still_returns_the_best_match(self):
        """max(1, limit) guards against a client sending limit=0 and getting an
        empty, misleading "no tools found" result."""
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, self._DEFS, loaded_groups=set())
            data = json.loads(asyncio.run(bridge.search_tools("rename", limit=0)))

        self.assertEqual(data["returned"], 1)

    def test_descriptions_are_truncated(self):
        """Descriptions are clipped to 160 chars so a wide search can't blow up
        the client's context."""
        long_desc = "rename " + ("x" * 400)
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(
                bridge, [tool_def("stg_long", "stg_misc", long_desc)], loaded_groups=set()
            )
            data = json.loads(asyncio.run(bridge.search_tools("rename")))

        self.assertEqual(len(data["matches"][0]["description"]), 160)

    def test_category_is_searchable(self):
        with isolated_bridge() as bridge:
            bridge.state._default_groups = set()
            seed_schema(bridge, self._DEFS, loaded_groups=set())
            data = json.loads(asyncio.run(bridge.search_tools("stg_globals")))

        self.assertEqual([m["name"] for m in data["matches"]], ["stg_list_globals"])


# ---------------------------------------------------------------------------
# import_file
# ---------------------------------------------------------------------------


class FakeAsyncio:
    """Stand-in for the ``asyncio`` module inside static_tools.

    import_file fires a 30-minute background poll loop via asyncio.create_task
    with 5-second sleeps. Swapping the module reference lets the test capture
    the coroutine and drive it to completion synchronously, with no real
    waiting and no stray task outliving the test.
    """

    def __init__(self):
        self.tasks = []
        self.sleeps = []

    async def sleep(self, delay):
        self.sleeps.append(delay)

    def create_task(self, coro):
        self.tasks.append(coro)
        return coro


class TestImportFile(unittest.TestCase):
    def test_payload_omits_unset_language_and_compiler_spec(self):
        """Ghidra auto-detects the format when `language` is absent; sending
        an explicit null would defeat that, so the keys must be omitted."""
        with isolated_bridge() as bridge, patch.object(
            bridge.dispatch, "dispatch_post", return_value='{"data": {}}'
        ) as post:
            asyncio.run(bridge.import_file(r"C:\bins\game.exe"))

        post.assert_called_once_with(
            "/import_file",
            {
                "file_path": r"C:\bins\game.exe",
                "project_folder": "/",
                "auto_analyze": True,
            },
        )

    def test_raw_binary_payload_includes_language_and_compiler_spec(self):
        with isolated_bridge() as bridge, patch.object(
            bridge.dispatch, "dispatch_post", return_value='{"data": {}}'
        ) as post:
            asyncio.run(
                bridge.import_file(
                    "/fw/image.bin",
                    project_folder="/firmware",
                    language="ARM:LE:32:Cortex",
                    compiler_spec="default",
                    auto_analyze=False,
                )
            )

        post.assert_called_once_with(
            "/import_file",
            {
                "file_path": "/fw/image.bin",
                "project_folder": "/firmware",
                "auto_analyze": False,
                "language": "ARM:LE:32:Cortex",
                "compiler_spec": "default",
            },
        )

    def test_non_json_response_is_returned_verbatim(self):
        """The Ghidra server can answer with a plain-text error; import_file
        must pass it through instead of raising a JSONDecodeError."""
        with isolated_bridge() as bridge, patch.object(
            bridge.dispatch, "dispatch_post", return_value="Import failed: no such file"
        ):
            result = asyncio.run(bridge.import_file("/nope.bin"))

        self.assertEqual(result, "Import failed: no such file")

    def test_no_poll_task_when_analysis_not_started(self):
        fake = FakeAsyncio()
        with isolated_bridge() as bridge, patch.object(
            bridge.static_tools, "asyncio", fake
        ), patch.object(
            bridge.dispatch,
            "dispatch_post",
            return_value=json.dumps({"data": {"analyzing": False, "name": "x.exe"}}),
        ):
            asyncio.run(bridge.import_file("/x.exe", ctx=make_ctx()))

        self.assertEqual(fake.tasks, [])

    def test_no_poll_task_without_a_client_context(self):
        """Without a ctx there is no session to notify, so spawning a 30-minute
        poll loop would just burn requests forever."""
        fake = FakeAsyncio()
        with isolated_bridge() as bridge, patch.object(
            bridge.static_tools, "asyncio", fake
        ), patch.object(
            bridge.dispatch,
            "dispatch_post",
            return_value=json.dumps({"data": {"analyzing": True, "name": "x.exe"}}),
        ):
            asyncio.run(bridge.import_file("/x.exe"))

        self.assertEqual(fake.tasks, [])

    def test_poll_sends_log_notification_when_analysis_completes(self):
        fake = FakeAsyncio()
        ctx = make_ctx()
        status = json.dumps({"data": {"analyzing": False, "function_count": 1234}})

        async def scenario(bridge):
            result = await bridge.import_file("/x.exe", ctx=ctx)
            self.assertEqual(len(fake.tasks), 1)
            await fake.tasks[0]  # drive the poll loop to completion
            return result

        with isolated_bridge() as bridge, patch.object(
            bridge.static_tools, "asyncio", fake
        ), patch.object(
            bridge.dispatch,
            "dispatch_post",
            return_value=json.dumps({"data": {"analyzing": True, "name": "game.exe"}}),
        ), patch.object(
            bridge.dispatch, "dispatch_get", return_value=status
        ) as status_get:
            asyncio.run(scenario(bridge))

        status_get.assert_called_with("/analysis_status", {"program": "game.exe"})
        send = ctx.request_context.session.send_log_message
        send.assert_awaited_once()
        message = send.await_args.kwargs["data"]
        self.assertIn("game.exe", message)
        self.assertIn("1234", message)

    def test_poll_survives_transient_status_errors(self):
        """A dropped connection mid-analysis must not kill the poll loop --
        it retries until the status endpoint answers."""
        fake = FakeAsyncio()
        ctx = make_ctx()
        done = json.dumps({"data": {"analyzing": False, "function_count": 7}})

        async def scenario(bridge):
            await bridge.import_file("/x.exe", ctx=ctx)
            await fake.tasks[0]

        with isolated_bridge() as bridge, patch.object(
            bridge.static_tools, "asyncio", fake
        ), patch.object(
            bridge.dispatch,
            "dispatch_post",
            return_value=json.dumps({"data": {"analyzing": True, "name": "game.exe"}}),
        ), patch.object(
            bridge.dispatch,
            "dispatch_get",
            side_effect=[ConnectionError("boom"), "not json at all", done],
        ) as status_get:
            asyncio.run(scenario(bridge))

        self.assertEqual(status_get.call_count, 3)
        ctx.request_context.session.send_log_message.assert_awaited_once()


# ---------------------------------------------------------------------------
# _auto_connect
# ---------------------------------------------------------------------------


class TestAutoConnect(unittest.TestCase):
    """Startup auto-connect. The multi-instance refusal and the Windows/TCP
    enrichment paths are covered in test_bridge_utils.py; these are the
    single-UDS-instance and TCP-fallback arms."""

    def setUp(self):
        import bridge_mcp_ghidra as bridge

        self._bridge = bridge
        self._saved = (
            bridge.state._active_socket,
            bridge.state._active_tcp,
            bridge.state._transport_mode,
            bridge.state._connected_project,
        )
        bridge.state._active_socket = None
        bridge.state._active_tcp = None
        bridge.state._transport_mode = "none"
        bridge.state._connected_project = None

    def tearDown(self):
        (
            self._bridge.state._active_socket,
            self._bridge.state._active_tcp,
            self._bridge.state._transport_mode,
            self._bridge.state._connected_project,
        ) = self._saved

    def test_single_uds_instance_connects_and_registers(self):
        bridge = self._bridge
        one = [{"socket": "/tmp/d2.sock", "pid": 42, "project": "diablo2"}]

        with patch.object(
            bridge.discovery, "discover_instances", return_value=one
        ), patch.object(
            bridge.transport, "uds_supported", return_value=True
        ), patch.object(
            bridge.registry, "_fetch_and_register_schema", return_value=271
        ) as fetch:
            bridge._auto_connect()

        fetch.assert_called_once()
        self.assertEqual(bridge.state._transport_mode, "uds")
        self.assertEqual(bridge.state._active_socket, "/tmp/d2.sock")
        self.assertEqual(bridge.state._connected_project, "diablo2")

    def test_uds_schema_failure_leaves_bridge_disconnected(self):
        """A half-connected bridge (socket set, no tools) is worse than none --
        the failure arm must clear the transport so connect_instance can retry."""
        bridge = self._bridge
        one = [{"socket": "/tmp/d2.sock", "pid": 42, "project": "diablo2"}]

        with patch.object(
            bridge.discovery, "discover_instances", return_value=one
        ), patch.object(
            bridge.transport, "uds_supported", return_value=True
        ), patch.object(
            bridge.registry,
            "_fetch_and_register_schema",
            side_effect=RuntimeError("HTTP 500"),
        ), patch.dict(
            os.environ, {"GHIDRA_MCP_URL": "http://evil.example.com:8089"}
        ):
            bridge._auto_connect()

        # UDS failed and the (non-local) env URL is refused, so nothing sticks.
        self.assertEqual(bridge.state._transport_mode, "none")
        self.assertIsNone(bridge.state._active_socket)
        self.assertIsNone(bridge.state._active_tcp)

    def test_windows_tcp_auto_connect_failure_leaves_bridge_disconnected(self):
        """Same half-connected hazard as the UDS arm, on the Windows/enriched-
        url path: if the schema fetch fails the TCP transport must be torn
        back down instead of being left pointing at a dead instance."""
        bridge = self._bridge
        one = [
            {
                "socket": r"F:\tmp\ghidra-mcp-benam\ghidra-9020.sock",
                "pid": 9020,
                "project": "diablo2",
                "url": "http://127.0.0.1:8091",
            }
        ]
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_URL"}

        with patch.object(
            bridge.discovery, "discover_instances", return_value=one
        ), patch.object(
            bridge.transport, "uds_supported", return_value=False
        ), patch.object(
            bridge.registry,
            "_fetch_and_register_schema",
            side_effect=ConnectionRefusedError("nope"),
        ), patch.dict(
            os.environ, env, clear=True
        ):
            bridge._auto_connect()

        self.assertEqual(bridge.state._transport_mode, "none")
        self.assertIsNone(bridge.state._active_tcp)

    def test_tcp_fallback_when_no_instances_discovered(self):
        bridge = self._bridge
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_URL"}

        with patch.object(
            bridge.discovery, "discover_instances", return_value=[]
        ), patch.object(
            bridge.registry, "_fetch_and_register_schema", return_value=12
        ), patch.dict(
            os.environ, env, clear=True
        ):
            bridge._auto_connect()

        self.assertEqual(bridge.state._transport_mode, "tcp")
        self.assertEqual(bridge.state._active_tcp, bridge.DEFAULT_TCP_URL)

    def test_tcp_fallback_failure_leaves_bridge_disconnected(self):
        bridge = self._bridge
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_URL"}

        with patch.object(
            bridge.discovery, "discover_instances", return_value=[]
        ), patch.object(
            bridge.registry,
            "_fetch_and_register_schema",
            side_effect=ConnectionRefusedError("nope"),
        ), patch.dict(
            os.environ, env, clear=True
        ):
            bridge._auto_connect()

        self.assertEqual(bridge.state._transport_mode, "none")
        self.assertIsNone(bridge.state._active_tcp)

    def test_non_local_env_url_is_never_auto_connected(self):
        bridge = self._bridge

        with patch.object(
            bridge.discovery, "discover_instances", return_value=[]
        ), patch.object(
            bridge.registry, "_fetch_and_register_schema"
        ) as fetch, patch.dict(
            os.environ, {"GHIDRA_MCP_URL": "http://10.0.0.5:8089"}
        ):
            bridge._auto_connect()

        fetch.assert_not_called()
        self.assertEqual(bridge.state._transport_mode, "none")


if __name__ == "__main__":
    unittest.main()


class TestListInstancesPayloadSize(unittest.TestCase):
    """list_instances must stay small enough to actually return.

    Live failure 2026-07-24: connected to a 626-program project, the tool
    returned ~90KB because /mcp/instance_info hands back the entire program
    roster — so it broke exactly when it was pointed at a real project. The
    roster is summarized to a count plus the open programs; nothing
    downstream reads it (connect_instance matches on project name).
    """

    @staticmethod
    def _big_instance(n=626, open_index=18):
        programs = [
            {
                "name": f"Prog{i}.dll",
                "path": f"/Mods/PD2-S12/Prog{i}.dll",
                "open": i == open_index,
            }
            for i in range(n)
        ]
        return {
            "socket": "/tmp/ghidra.sock",
            "pid": 60196,
            "project": "diablo2",
            "programs": programs,
            "tcp_port": 8089,
        }

    def _run(self, instance):
        with isolated_bridge() as bridge, patch.object(
            bridge.discovery, "discover_instances", return_value=[instance]
        ), patch.object(
            bridge.discovery, "discover_active_tcp_instance", return_value=None
        ):
            raw = bridge.list_instances()
        return raw, json.loads(raw)["instances"][0]

    def test_large_project_roster_is_summarized(self):
        raw, inst = self._run(self._big_instance())

        self.assertNotIn("programs", inst, "full roster must not be inlined")
        self.assertEqual(inst["program_count"], 626)
        self.assertEqual(inst["open_programs"], ["/Mods/PD2-S12/Prog18.dll"])
        # The real payload was ~90k; anything in that neighborhood is a
        # regression regardless of how the summary is spelled.
        self.assertLess(len(raw), 8000, f"payload too large: {len(raw)} chars")

    def test_identifying_fields_survive_summarization(self):
        _, inst = self._run(self._big_instance())

        for key in ("socket", "pid", "project", "tcp_port", "connected"):
            self.assertIn(key, inst)

    def test_open_program_list_is_capped(self):
        """A pathological number of open programs must not reintroduce the
        original problem."""
        programs = [{"name": f"P{i}.dll", "open": True} for i in range(80)]
        inst = self._big_instance()
        inst["programs"] = programs
        _, summarized = self._run(inst)

        self.assertEqual(len(summarized["open_programs"]), 25)
        self.assertEqual(summarized["open_programs_truncated"], 55)

    def test_string_program_entries_are_treated_as_open(self):
        """/list_open_programs returns bare names — being listed is being open."""
        inst = self._big_instance()
        inst["programs"] = ["A.dll", "B.dll"]
        _, summarized = self._run(inst)

        self.assertEqual(summarized["program_count"], 2)
        self.assertEqual(summarized["open_programs"], ["A.dll", "B.dll"])

    def test_instance_without_programs_key_is_untouched(self):
        inst = {"socket": "/tmp/s", "pid": 1, "project": "p"}
        _, summarized = self._run(inst)

        self.assertEqual(summarized["project"], "p")
        self.assertNotIn("program_count", summarized)


class TestCheckToolsWithoutSchema(unittest.TestCase):
    """check_tools must distinguish "not connected" from "doesn't exist".

    Live failure 2026-07-24: called before connect_instance, every Ghidra
    tool came back "not_found" — the same answer a genuinely missing tool
    gets. That sent the caller looking for a deleted endpoint when the real
    fix was one connect_instance call away.
    """

    def test_unconnected_reports_unknown_not_missing(self):
        with isolated_bridge() as bridge:
            bridge.state._full_schema = []
            bridge.state._dynamic_tool_names[:] = []
            data = asyncio.run(bridge.check_tools("rename_function_by_address"))

        entry = json.loads(data)["results"]["rename_function_by_address"]
        self.assertEqual(entry["status"], "unknown")
        self.assertIn("connect_instance", entry["fix"])

    def test_static_tools_still_callable_without_schema(self):
        """The static tools work before any connection — they must not be
        swept up in the "unknown" answer."""
        with isolated_bridge() as bridge:
            bridge.state._full_schema = []
            data = asyncio.run(bridge.check_tools("list_instances"))

        self.assertEqual(
            json.loads(data)["results"]["list_instances"]["status"], "callable"
        )

    def test_missing_tool_is_still_not_found_when_schema_present(self):
        """With a schema loaded the distinction must still be made — this is
        what keeps the fix from degrading into "everything is unknown"."""
        with isolated_bridge() as bridge:
            bridge.state._full_schema = [
                {"name": "rename_function_by_address", "category": "rename"}
            ]
            bridge.state._dynamic_tool_names[:] = []
            data = asyncio.run(bridge.check_tools("no_such_tool"))

        self.assertEqual(json.loads(data)["results"]["no_such_tool"]["status"], "not_found")
