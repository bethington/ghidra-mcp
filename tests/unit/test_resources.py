"""Unit tests for MCP function-resource URI helpers and read handlers.

No Ghidra process required — upstream HTTP is stubbed.
"""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "python"))

from bridge_mcp_ghidra.resources import (  # noqa: E402
    _MAX_INDEX_FUNCTIONS,
    canonical_function_uri,
    tree_resource,
    function_by_name_resource,
    function_bundle_resource,
    function_index_resource,
    function_search_resource,
    parse_function_hit,
    program_changes_resource,
    programs_resource,
)
from bridge_mcp_ghidra.server import mcp  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


class TestCanonicalFunctionUri(unittest.TestCase):
    def test_plain_address(self):
        self.assertEqual(
            canonical_function_uri("ls", "001f4000"),
            "ghidra://function/ls/001f4000",
        )

    def test_encodes_program_slash_and_keeps_address_space_colon(self):
        self.assertEqual(
            canonical_function_uri("proj/bin", "mem:1000"),
            "ghidra://function/proj%2Fbin/mem:1000",
        )

    def test_encodes_spaces_in_program_name(self):
        self.assertEqual(
            canonical_function_uri("my prog", "00401000"),
            "ghidra://function/my%20prog/00401000",
        )


class TestParseFunctionHit(unittest.TestCase):
    def test_dict_row(self):
        self.assertEqual(
            parse_function_hit({"name": "foo", "address": "00100000"}),
            ("foo", "00100000"),
        )

    def test_legacy_search_string(self):
        self.assertEqual(
            parse_function_hit("__snprintf_chk @ 001f4030"),
            ("__snprintf_chk", "001f4030"),
        )

    def test_name_containing_separator_uses_rsplit(self):
        self.assertEqual(
            parse_function_hit("odd @ name @ 00aabbcc"),
            ("odd @ name", "00aabbcc"),
        )

    def test_rejects_junk(self):
        self.assertEqual(parse_function_hit("nope"), (None, None))
        self.assertEqual(parse_function_hit({"name": "x"}), (None, None))


class TestResourceRegistration(unittest.TestCase):
    def test_programs_is_the_only_concrete_list_entry(self):
        resources = mcp._resource_manager.list_resources()
        uris = sorted(str(r.uri) for r in resources)
        self.assertEqual(uris, ["ghidra://programs"])

    def test_templates_cover_index_bundle_by_name_and_search(self):
        templates = mcp._resource_manager.list_templates()
        uris = sorted(str(getattr(t, "uriTemplate", None) or t.uri_template) for t in templates)
        self.assertIn("ghidra://program/{program}/index", uris)
        self.assertIn("ghidra://program/{program}/functions", uris)
        self.assertIn("ghidra://function/{program}/{address}", uris)
        self.assertIn("ghidra://function/{program}/by-name/{name}", uris)
        self.assertIn("ghidra://search/{program}/functions/{pattern}", uris)
        self.assertIn("ghidra://program/{program}/changes", uris)
        self.assertIn("ghidra://decompile-tree/{tree_id}", uris)

    def test_tree_template_is_markdown(self):
        for template in mcp._resource_manager.list_templates():
            uri = str(getattr(template, "uriTemplate", None) or template.uri_template)
            if uri == "ghidra://decompile-tree/{tree_id}":
                self.assertEqual(template.mime_type, "text/markdown")
                break
        else:
            self.fail("tree template not registered")


class TestResourceHandlers(unittest.TestCase):
    def test_programs_resource_documents_uri_contract(self):
        payload = {
            "programs": [{"name": "ls", "is_current": True}],
            "count": 1,
        }
        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(return_value=json.dumps(payload)),
        ):
            body = json.loads(_run(programs_resource()))
        self.assertTrue(body["connected"])
        self.assertEqual(body["programs"][0]["program"], "ls")
        self.assertEqual(
            body["programs"][0]["functions"],
            "ghidra://program/ls/functions",
        )
        self.assertIn("function_by_address", body["uri_contract"])
        self.assertEqual(
            body["uri_contract"]["trees"],
            "ghidra://decompile-tree/{tree_id}",
        )

    def test_changes_resource_publishes_the_token_and_its_caveats(self):
        """The token is published, not only polled: a lost notification must
        still be detectable by comparing it with a bundle's revision."""
        async def fake_read(endpoint, **params):
            self.assertEqual(endpoint, "/get_change_token")
            return json.dumps({"program": "ls", "modification_number": 42})

        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=fake_read),
        ):
            body = json.loads(_run(program_changes_resource("ls")))
        self.assertEqual(body["modification_number"], 42)
        self.assertTrue(body["notifications"]["subscribe_supported"])
        self.assertTrue(any("json-response" in c for c in body["notifications"]["caveats"]))

    def test_changes_resource_survives_an_unreachable_ghidra(self):
        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=RuntimeError("boom")),
        ):
            body = json.loads(_run(program_changes_resource("ls")))
        self.assertIn("error", body)
        self.assertIn("notifications", body)

    def test_function_index_rows_are_name_address_plus_one_template(self):
        listing = {
            "functions": [
                {"name": "_DT_INIT", "address": "001f4000"},
                {"name": "FUN_001f4020", "address": "001f4020"},
            ],
            "count": 2,
            "limit": _MAX_INDEX_FUNCTIONS,
        }

        async def fake_read(endpoint, **params):
            self.assertEqual(endpoint, "/find_functions")
            self.assertEqual(params.get("limit"), _MAX_INDEX_FUNCTIONS)
            return json.dumps(listing)

        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=fake_read),
        ):
            body = json.loads(_run(function_index_resource("ls")))
        self.assertEqual(body["count"], 2)
        self.assertFalse(body["truncated"])
        # A per-row uri was a third of this payload and is derivable, so the
        # template is carried once instead.
        self.assertEqual(
            body["functions"][0], {"name": "_DT_INIT", "address": "001f4000"}
        )
        self.assertEqual(body["uri_template"], "ghidra://function/ls/{address}")

    def test_function_index_marks_truncation_from_program_info(self):
        rows = [
            {"name": f"f{i}", "address": f"{i:08x}"}
            for i in range(_MAX_INDEX_FUNCTIONS)
        ]

        async def fake_read(endpoint, **params):
            if endpoint == "/find_functions":
                return json.dumps({"functions": rows, "count": len(rows)})
            if endpoint == "/get_ui_cursor":
                return json.dumps({"name": "ls", "function_count": 25514})
            raise AssertionError(endpoint)

        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=fake_read),
        ):
            body = json.loads(_run(function_index_resource("ls")))
        self.assertTrue(body["truncated"])
        self.assertEqual(body["total"], 25514)
        self.assertEqual(body["count"], _MAX_INDEX_FUNCTIONS)

    def test_by_name_uses_address_param_and_returns_canonical_uri(self):
        captured = {}

        async def fake_read(endpoint, **params):
            captured["endpoint"] = endpoint
            captured["params"] = params
            return json.dumps({
                "name": "_DT_INIT",
                "address": "001f4000",
                "signature": "undefined _DT_INIT(void)",
            })

        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=fake_read),
        ):
            body = json.loads(_run(function_by_name_resource("ls", "_DT_INIT")))
        self.assertEqual(captured["endpoint"], "/get_functions")
        self.assertEqual(captured["params"]["address"], "_DT_INIT")
        self.assertEqual(captured["params"]["fields"], "entry_point,signature")
        self.assertTrue(body["resolved"])
        self.assertEqual(body["canonical_uri"], "ghidra://function/ls/001f4000")

    def test_search_parses_legacy_at_strings(self):
        payload = {
            "functions": [
                "__snprintf_chk @ 001f4030",
                "__vsnprintf_chk @ 001f4050",
            ],
            "count": 2,
            "total": 2,
        }
        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(return_value=json.dumps(payload)),
        ):
            body = json.loads(_run(function_search_resource("ls", "printf")))
        self.assertEqual(body["count"], 2)
        self.assertEqual(
            body["matches"][0], {"name": "__snprintf_chk", "address": "001f4030"}
        )
        self.assertEqual(body["uri_template"], "ghidra://function/ls/{address}")

    def test_bundle_is_markdown_and_names_its_own_uri(self):
        """The body is Markdown, not JSON — a JSON body inside a resource read's
        JSON string reaches the model doubly escaped (see render.py)."""
        payload = {
            "name": "_DT_INIT",
            "address": "001f4000",
            "program": "ls",
            "decompiled_code": "void _DT_INIT(void) {}",
            "call_context": [
                {
                    "caller": "entry",
                    "caller_address": "001f4100",
                    "site_address": "001f4108",
                    "text": "11:   if (once == 0) {\n12:     _DT_INIT();\n13:   }",
                }
            ],
        }
        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(return_value=json.dumps(payload)),
        ):
            body = _run(function_bundle_resource("ls", "001f4000"))
        self.assertTrue(body.startswith("# _DT_INIT"))
        self.assertIn("```c", body)
        self.assertIn("void _DT_INIT(void) {}", body)
        # Every line of a multi-line call window keeps the list indent, or the
        # fence closes early and the rest renders as prose.
        self.assertIn("  11:   if (once == 0) {", body)
        self.assertIn("  12:     _DT_INIT();", body)
        self.assertIn("ghidra://function/ls/001f4000", body)

    def test_bundle_mime_type_is_markdown(self):
        for template in mcp._resource_manager.list_templates():
            uri = str(getattr(template, "uriTemplate", None) or template.uri_template)
            if uri == "ghidra://function/{program}/{address}":
                self.assertEqual(template.mime_type, "text/markdown")
                break
        else:
            self.fail("bundle template not registered")

    def test_tree_resource_renders_markdown(self):
        payload = {
            "tree_id": "tree_7de33ad7",
            "program_name": "synaWudfBioUsb.dll",
            "program": "synaWudfBioUsb.dll",
            "live_modification_number": 3,
            "root": "/tmp/ghidra-mcp-tree/synaWudfBioUsb.dll-7de33ad7",
            "root_present": True,
            "root_recreated": 0,
            "phase": "complete",
            "functions_total": 3230,
            "functions_done": 3230,
            "functions_failed": 0,
            "bytes_written": 5886248,
            "status_revision": 311,
            "resource_uri": "ghidra://decompile-tree/tree_7de33ad7",
            "config": {
                "enabled_strategies": [],
                "band_size": 20,
                "max_file_bytes": 32768,
                "exclusions": [],
                "include_only": [],
                "throttle_percent": 10,
                "decompile_timeout_seconds": 30,
                "analysis_wait_seconds": 600,
            },
            "status_state": "clean",
            "swept_at_modification_number": 3,
        }

        async def fake_read(endpoint, **params):
            self.assertEqual(endpoint, "/decompile_tree_status")
            self.assertEqual(params.get("tree"), "tree_7de33ad7")
            return json.dumps(payload)

        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=fake_read),
        ), patch(
            "bridge_mcp_ghidra.resources.subscriptions.note_resource_read",
        ) as note:
            body = _run(tree_resource("tree_7de33ad7"))
        note.assert_called_once_with("ghidra://decompile-tree/tree_7de33ad7")
        self.assertTrue(body.startswith("# Tree tree_7de33ad7"))
        self.assertIn("## Status", body)
        self.assertIn("## How to read this tree", body)
        self.assertIn("Glob /tmp/ghidra-mcp-tree/synaWudfBioUsb.dll-7de33ad7/modules/*/*.c", body)

    def test_tree_resource_degrades_upstream_failure_into_body(self):
        """A transient failure mid-sweep must not look like a broken resource."""
        with patch(
            "bridge_mcp_ghidra.resources._read_async",
            new=AsyncMock(side_effect=RuntimeError("connection reset")),
        ):
            body = _run(tree_resource("tree_deadbeef"))
        self.assertIn("error", body.lower())
        self.assertIn("connection reset", body)
        self.assertTrue(body.startswith("# Tree tree_deadbeef"))


if __name__ == "__main__":
    unittest.main()
