"""The bridge's side of the settings: session scope, tools.autoload, restoring last-loaded groups."""

import json
import os
import unittest
from unittest import mock

from bridge_mcp_ghidra import settings, state

SCHEMA = [{"name": f"t_{g}", "category": g} for g in ("listing", "function", "program", "datatype", "memory", "xref")]


def _settings_reply(**values):
    rows = [{"key": k.replace("__", "."), "value": v} for k, v in values.items()]
    return json.dumps({"settings": rows}), 200


class BridgeSettingsTest(unittest.TestCase):
    def setUp(self):
        self._saved = (
            set(state._default_groups),
            set(state._loaded_groups),
            state._lazy_mode,
            state._require_selectors,
            settings._last_recorded,
            dict(settings.SESSION),
        )
        state._lazy_mode = True
        settings.SESSION.clear()
        # a GHIDRA_MCP_TOOLS_* in the surrounding shell would be this session's value
        env = {k: v for k, v in os.environ.items() if not k.startswith("GHIDRA_MCP_TOOLS_")}
        patcher = mock.patch.dict("os.environ", env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        (
            state._default_groups,
            loaded,
            state._lazy_mode,
            state._require_selectors,
            settings._last_recorded,
            session,
        ) = self._saved
        state._loaded_groups.clear()
        state._loaded_groups.update(loaded)
        settings.SESSION.clear()
        settings.SESSION.update(session)

    def connect(self, reply):
        with mock.patch.object(settings.transport, "do_request", return_value=reply):
            return settings.connect_groups(SCHEMA)

    def test_deltas_adjust_and_a_bare_list_replaces(self):
        self.assertEqual(settings.apply_delta(["a", "b"], "+c,-a"), ["b", "c"])
        self.assertEqual(settings.apply_delta(["a", "b"], "c,+d"), ["c", "d"])
        self.assertEqual(settings.apply_delta(["a"], ""), [])

    def test_the_last_loaded_groups_come_back_when_restore_is_on(self):
        groups = self.connect(
            _settings_reply(
                tools__autoload=["listing", "function", "program"],
                tools__restore_loaded=True,
                tools__last_loaded=["memory", "xref"],
            )
        )
        self.assertEqual(groups, {"listing", "function", "program", "memory", "xref"})
        self.assertEqual(state._default_groups, {"listing", "function", "program"})

    def test_restore_off_loads_only_autoload(self):
        groups = self.connect(
            _settings_reply(
                tools__autoload=["listing", "datatype"],
                tools__restore_loaded=False,
                tools__last_loaded=["memory"],
            )
        )
        self.assertEqual(groups, {"listing", "datatype"})

    def test_the_session_flag_adjusts_the_projects_autoload(self):
        settings.SESSION["tools.autoload"] = "+xref,-program"
        groups = self.connect(_settings_reply(tools__autoload=["listing", "function", "program"]))
        self.assertEqual(groups, {"listing", "function", "xref"})

    def test_unknown_groups_warn_with_the_valid_list(self):
        with self.assertLogs("bridge_mcp_ghidra.settings", level="WARNING") as logs:
            groups = self.connect(_settings_reply(tools__last_loaded=["memory", "nonesuch"]))
        self.assertNotIn("nonesuch", groups)
        self.assertIn("memory", groups)
        self.assertTrue(any("nonesuch" in m and "datatype" in m for m in logs.output), logs.output)

    def test_eager_mode_registers_everything(self):
        state._lazy_mode = False
        self.assertIsNone(self.connect(_settings_reply()))

    def test_a_server_without_get_settings_uses_the_defaults(self):
        groups = self.connect(("not found", 404))
        self.assertEqual(groups, {"listing", "function", "program"})

    def test_require_program_follows_the_project(self):
        self.connect(_settings_reply(tools__require_program=True))
        self.assertTrue(state._require_selectors)

    def test_loaded_groups_beyond_autoload_are_recorded_once(self):
        self.connect(_settings_reply(tools__autoload=["listing"], tools__last_loaded=[]))
        state._loaded_groups.clear()
        state._loaded_groups.update({"listing", "memory", "datatype"})
        with mock.patch.object(settings.transport, "do_request", return_value=('{"value": []}', 200)) as req:
            settings.record_loaded_groups()
            settings.record_loaded_groups()
        req.assert_called_once()
        body = req.call_args.kwargs["json_data"]
        self.assertEqual(body, {"key": "tools.last_loaded", "value": "datatype,memory", "scope": "local"})

    def test_a_refused_record_is_retried_next_time(self):
        self.connect(_settings_reply(tools__autoload=["listing"]))
        state._loaded_groups.clear()
        state._loaded_groups.update({"listing", "memory"})
        refused = ('{"error": "No local scope here: no project is open."}', 200)
        with mock.patch.object(settings.transport, "do_request", return_value=refused) as req:
            with self.assertLogs("bridge_mcp_ghidra.settings", level="WARNING"):
                settings.record_loaded_groups()
            with self.assertLogs("bridge_mcp_ghidra.settings", level="WARNING"):
                settings.record_loaded_groups()
        self.assertEqual(req.call_count, 2)


if __name__ == "__main__":
    unittest.main()
