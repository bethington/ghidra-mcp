"""
Non-destructive integration tests for GhidraMCP.

These tests ONLY use read-only endpoints and will NOT modify any data in Ghidra.
Safe to run against production projects.

Run with: pytest tests/integration/test_readonly_endpoints.py -v

Note: Tests will be automatically skipped if the MCP server is not running.

Test coverage:
- Server health and connectivity (2 tests)
- Program info and metadata (5 tests)
- Function listing and search (5 tests)
- Data types listing and search (6 tests)
- Strings and data items (4 tests)
- Imports and exports (3 tests)
- Namespaces and globals (3 tests)
- Calling conventions (1 test)
- Project files (1 test)
- Scripts listing (2 tests)
- Call graph (1 test)
- Documentation (1 test)
- Function analysis (13 tests)
- Cross-references (2 tests)
- Memory inspection (2 tests)
- Bulk operations (1 test)
- Selection state (1 test)
- Byte pattern search (1 test)
- Response format validation (3 tests)

Total: 57 read-only tests
"""

import pytest
import json


# Mark all tests as readonly integration tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.readonly,
    pytest.mark.usefixtures("require_server"),
]


@pytest.fixture(scope="module")
def require_server(server_available):
    """Skip all tests in module if server is not available."""
    if not server_available:
        pytest.skip(
            "MCP server is not running (start with Tools → GhidraMCP → Start MCP Server)"
        )


class TestServerHealth:
    """Test server connectivity and health endpoints."""

    def test_check_connection(self, http_client):
        """Server should respond to health check."""
        response = http_client.get("/check_connection")
        assert response.status_code == 200
        assert "ok" in response.text.lower() or "connected" in response.text.lower()

    def test_get_version(self, http_client):
        """Server should return version info."""
        response = http_client.get("/get_version")
        assert response.status_code == 200
        text = response.text
        # Should contain version info
        assert "version" in text.lower() or "ghidra" in text.lower()


class TestProgramInfo:
    """Test read-only program information endpoints."""

    def test_get_current_program_info(self, http_client):
        """Get current program info."""
        response = http_client.get("/get_current_program_info")
        assert response.status_code == 200
        # May return error if no program open, that's OK
        assert len(response.text) > 0

    def test_get_metadata(self, http_client):
        """Get program metadata."""
        response = http_client.get("/get_metadata")
        assert response.status_code == 200

    def test_list_open_programs(self, http_client):
        """List all open programs."""
        response = http_client.get("/list_open_programs")
        assert response.status_code == 200

    def test_list_segments(self, http_client):
        """List memory segments."""
        response = http_client.get("/list_segments")
        assert response.status_code == 200

    def test_get_entry_points(self, http_client):
        """Get program entry points."""
        response = http_client.get("/get_entry_points")
        assert response.status_code == 200

    def test_get_language_metadata(self, http_client):
        """Issue #192: language metadata dump (address spaces, registers,
        default symbols, endianness). Skip the heavy sections to keep the
        readonly suite fast — they're exercised separately in
        TestGetLanguageMetadataFull."""
        response = http_client.get(
            "/get_language_metadata",
            params={"include_registers": "false", "include_default_symbols": "false"},
        )
        assert response.status_code == 200
        # Endpoint returns flat JSON (no `data` wrapper).
        data = response.json()
        # Core SLEIGH facts must always be present
        for key in (
            "language_id", "processor", "endian", "size", "default_space",
            "address_spaces",
        ):
            assert key in data, f"missing '{key}' in language metadata: {data}"
        assert isinstance(data["address_spaces"], list)
        assert len(data["address_spaces"]) > 0
        # When the heavy sections are off they should not be in the payload.
        assert "registers" not in data
        assert "default_symbols" not in data

    def test_get_language_metadata_with_registers(self, http_client):
        """Issue #192: register list is included when requested. x86 typically
        has 100+ registers; ARM has fewer; either way the list must be
        non-empty. After Copilot review: every register entry has a stable
        shape (name/bit_length/is_big_endian/children/aliases always present)
        and richer fields (description/parent) appear when non-null. Gson
        strips null values so absence of a key means the underlying value
        was null, not that the endpoint forgot to emit it."""
        response = http_client.get(
            "/get_language_metadata",
            params={"include_registers": "true", "include_default_symbols": "false"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "registers" in data
        regs = data["registers"]
        assert isinstance(regs, list)
        assert len(regs) > 0
        # Stable fields present on every entry.
        for r in regs[:5]:
            for key in ("name", "bit_length", "is_big_endian", "children", "aliases"):
                assert key in r, f"missing key '{key}' on register: {list(r.keys())}"
            assert isinstance(r["children"], list)
            assert isinstance(r["aliases"], list)
        # At least one register reports a parent (e.g. AX → EAX on x86).
        # If none do, the parent linkage isn't being emitted at all -- bug.
        parent_count = sum(1 for r in regs if "parent" in r)
        assert parent_count > 0, "no register reported a parent linkage"
        # At least one register reports a description (e.g. EFLAGS bits on x86
        # carry descriptions). If none do, the description is being silently
        # dropped server-side.
        desc_count = sum(1 for r in regs if "description" in r)
        assert desc_count > 0, "no register reported a description"

    def test_mcp_instance_info_on_tcp(self, http_client):
        """Issue #175 + Copilot review: /mcp/instance_info must be served
        on the TCP transport too (was UDS-only before this PR). The
        bridge's TCP port-range scanner relies on this endpoint to identify
        which project lives on which port. Must include `tcp_port` so the
        scanner can distinguish port-fallback-aware plugins from older ones
        that only ever bound to 8089."""
        response = http_client.get("/mcp/instance_info")
        assert response.status_code == 200
        info = response.json()
        # Required fields the bridge's scanner reads.
        assert "project" in info, f"missing 'project' in instance_info: {info}"
        assert "pid" in info
        assert "tcp_port" in info, "tcp_port must be advertised so port-fallback works"
        # tcp_port may legitimately be -1 (TCP transport stopped) but the
        # key must be present so the scanner doesn't false-positive on
        # older plugins that simply omit it.
        assert isinstance(info["tcp_port"], int)


class TestFunctionListing:
    """Test function listing and query endpoints (read-only)."""

    def test_list_functions_default(self, http_client):
        """List functions with default parameters."""
        response = http_client.get("/list_functions")
        assert response.status_code == 200
        # Should return some text (may be empty list or error if no program)
        assert len(response.text) > 0

    def test_list_functions_enhanced_with_limit(self, http_client):
        """Pagination lives on /list_functions_enhanced, not /list_functions.

        /list_functions declares only `program` -- ListingService documents it
        as "List all functions (no pagination)". This test used to send
        `limit` there, which the plugin silently drops, so it asserted nothing.
        """
        response = http_client.get("/list_functions_enhanced", params={"limit": 5})
        assert response.status_code == 200
        functions = response.json()["functions"]
        assert len(functions) <= 5

    def test_list_functions_enhanced_with_offset(self, http_client):
        """`offset` is declared on /list_functions_enhanced and must be honored."""
        response = http_client.get(
            "/list_functions_enhanced", params={"offset": 0, "limit": 5}
        )
        assert response.status_code == 200
        payload = response.json()
        assert "functions" in payload
        assert len(payload["functions"]) <= 5

    def test_search_functions_by_name(self, http_client):
        """Search functions by name pattern.

        /search_functions_by_name is not an endpoint; /search_functions is,
        and its declared selector is `name_pattern`.
        """
        response = http_client.get("/search_functions", params={"name_pattern": "a"})
        assert response.status_code == 200
        assert "functions" in response.json()

    def test_search_functions_enhanced(self, http_client):
        """Enhanced function search.

        The declared selector is `name_pattern`; sent as `pattern` the filter
        was dropped entirely and this returned an unfiltered listing.
        """
        response = http_client.get(
            "/search_functions_enhanced", params={"name_pattern": "FUN_", "limit": 10}
        )
        assert response.status_code == 200
        results = response.json()["results"]
        assert len(results) <= 10
        assert all("FUN_" in r["name"] for r in results)


class TestDataTypes:
    """Test data type listing endpoints (read-only)."""

    def test_list_data_types(self, http_client):
        """List data types."""
        response = http_client.get("/list_data_types")
        assert response.status_code == 200

    def test_list_data_types_with_limit(self, http_client):
        """List data types with limit."""
        response = http_client.get("/list_data_types", params={"limit": 20})
        assert response.status_code == 200

    def test_search_data_types(self, http_client):
        """Search for data types."""
        response = http_client.get("/search_data_types", params={"pattern": "int"})
        assert response.status_code == 200

    def test_get_valid_data_types(self, http_client):
        """Get list of valid builtin data types."""
        response = http_client.get("/get_valid_data_types")
        assert response.status_code == 200

    def test_validate_data_type_existence_only(self, http_client):
        """Validate a common data type exists."""
        response = http_client.get(
            "/validate_data_type", params={"type_name": "int"}
        )
        assert response.status_code == 200

    def test_get_type_size(self, http_client):
        """Get size of a data type."""
        response = http_client.get("/get_type_size", params={"type_name": "int"})
        # May be 404 if headless-only endpoint
        assert response.status_code in [200, 404]


class TestStringsAndData:
    """Test string and data listing endpoints (read-only)."""

    def test_list_strings(self, http_client):
        """List defined strings."""
        response = http_client.get("/list_strings")
        assert response.status_code == 200

    def test_list_strings_with_limit(self, http_client):
        """List strings with limit."""
        response = http_client.get("/list_strings", params={"limit": 20})
        assert response.status_code == 200

    def test_list_data_items(self, http_client):
        """List data items."""
        response = http_client.get("/list_data_items")
        assert response.status_code == 200

    def test_list_data_items_by_xrefs(self, http_client):
        """List data items sorted by xref count."""
        response = http_client.get(
            "/list_data_items_by_xrefs", params={"min_xrefs": 1, "limit": 10}
        )
        assert response.status_code == 200


class TestImportsExports:
    """Test import/export listing endpoints (read-only)."""

    def test_list_imports(self, http_client):
        """List imported symbols."""
        response = http_client.get("/list_imports")
        assert response.status_code == 200

    def test_list_exports(self, http_client):
        """List exported symbols."""
        response = http_client.get("/list_exports")
        assert response.status_code == 200

    def test_list_external_locations(self, http_client):
        """List external locations."""
        response = http_client.get("/list_external_locations")
        assert response.status_code == 200


class TestNamespaces:
    """Test namespace and class listing endpoints (read-only)."""

    def test_list_namespaces(self, http_client):
        """List namespaces."""
        response = http_client.get("/list_namespaces")
        assert response.status_code == 200

    def test_list_classes(self, http_client):
        """List classes."""
        response = http_client.get("/list_classes")
        assert response.status_code == 200

    def test_list_globals(self, http_client):
        """List global variables."""
        response = http_client.get("/list_globals")
        assert response.status_code == 200


class TestCallingConventions:
    """Test calling convention endpoints (read-only)."""

    def test_list_calling_conventions(self, http_client):
        """List available calling conventions."""
        response = http_client.get("/list_calling_conventions")
        assert response.status_code == 200
        # Should contain common conventions
        text = response.text.lower()
        # At least one of these should be present
        has_convention = any(
            conv in text
            for conv in ["stdcall", "cdecl", "fastcall", "thiscall", "default"]
        )
        if "error" not in text.lower():
            assert has_convention or "convention" in text


class TestProjectFiles:
    """Test project file listing endpoints (read-only)."""

    def test_list_project_files(self, http_client):
        """List project files."""
        response = http_client.get("/list_project_files")
        assert response.status_code == 200


class TestScripts:
    """Test script listing endpoints (read-only)."""

    def test_list_scripts(self, http_client):
        """List available scripts."""
        response = http_client.get("/list_scripts")
        assert response.status_code == 200

    def test_list_scripts_with_filter(self, http_client):
        """`filter` is the endpoint's only declared parameter.

        Replaces test_list_ghidra_scripts, which called /list_ghidra_scripts --
        not an endpoint. It accepted [200, 404] and so was a permanent 404
        no-op; /list_scripts is the real route and test_list_scripts already
        covers the unfiltered call, so this covers the parameter instead.
        """
        response = http_client.get("/list_scripts", params={"filter": "Backfill"})
        assert response.status_code == 200


class TestCallGraph:
    """Test call graph endpoints (read-only) - requires valid function address."""

    def test_get_full_call_graph(self, http_client):
        """Get full call graph, bounded by the declared `limit`.

        This used to send `max_depth`, which the endpoint does not declare --
        silently dropped, so no bound was ever exercised. Declared parameters
        are format, limit and program.
        """
        response = http_client.get("/get_full_call_graph", params={"limit": 5})
        assert response.status_code == 200
        edges = response.json()["edges"]
        assert len(edges) <= 5


class TestDocumentation:
    """Test documentation comparison endpoints (read-only)."""

    def test_compare_programs_documentation(self, http_client):
        """Compare documentation across open programs."""
        response = http_client.get("/compare_programs_documentation")
        assert response.status_code == 200


class TestFunctionAnalysis:
    """Test function analysis endpoints with first available function."""

    @pytest.fixture
    def first_function_address(self, http_client):
        """Get address of first function in program.

        /list_functions takes no `limit` -- it lists all functions -- so the
        first match in the full listing is what the regex below finds.
        """
        response = http_client.get("/list_functions")
        if response.status_code != 200:
            pytest.skip("Cannot list functions")
        text = response.text
        # Try to extract address from response
        # Format is typically "FunctionName at 10001000" (no 0x prefix)
        import re

        # Match "at 10001000" or "at 0x10001000" or JSON format
        match = re.search(r"at\s+(?:0x)?([0-9a-fA-F]+)", text)
        if not match:
            match = re.search(r'"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?', text)
        if not match:
            pytest.skip("No functions found in program")
        return f"0x{match.group(1)}"

    def test_get_function_by_address(self, http_client, first_function_address):
        """Get function details by address."""
        response = http_client.get(
            "/get_function_by_address", params={"address": first_function_address}
        )
        assert response.status_code == 200

    def test_decompile_function(self, http_client, first_function_address):
        """Decompile a function (read-only)."""
        response = http_client.get(
            "/decompile_function", params={"address": first_function_address}
        )
        assert response.status_code == 200

    # test_get_decompiled_code removed: /get_decompiled_code is not an
    # endpoint. It accepted [200, 404] and so passed on the permanent 404,
    # asserting nothing. The real route is /decompile_function, already
    # covered by test_decompile_function directly above.

    def test_disassemble_function(self, http_client, first_function_address):
        """Disassemble a function."""
        response = http_client.get(
            "/disassemble_function", params={"address": first_function_address}
        )
        assert response.status_code == 200

    # test_get_disassembly removed: /get_disassembly is not an endpoint, and
    # the test accepted [200, 404]. /disassemble_function is the real route,
    # covered by test_disassemble_function directly above.

    def test_get_function_variables(self, http_client, first_function_address):
        """Get function variables."""
        response = http_client.get(
            "/get_function_variables", params={"address": first_function_address}
        )
        assert response.status_code in [200, 404]

    def test_get_function_labels(self, http_client, first_function_address):
        """Get function labels.

        The declared selector is `name` (which accepts a function name OR an
        address). `address` is a back-compat alias the resolver still honors,
        but /mcp/schema advertises only the canonical spelling, so that is
        what a test should exercise.
        """
        response = http_client.get(
            "/get_function_labels", params={"name": first_function_address}
        )
        # May not exist in all versions
        assert response.status_code in [200, 404]

    def test_get_function_callers(self, http_client, first_function_address):
        """Get function callers (xrefs to)."""
        response = http_client.get(
            "/get_function_callers", params={"address": first_function_address}
        )
        # May not exist in all versions
        assert response.status_code in [200, 404]

    def test_get_function_callees(self, http_client, first_function_address):
        """Get function callees (xrefs from)."""
        response = http_client.get(
            "/get_function_callees", params={"address": first_function_address}
        )
        # May not exist in all versions
        assert response.status_code in [200, 404]

    def test_get_function_xrefs(self, http_client, first_function_address):
        """Get function cross-references."""
        response = http_client.get(
            "/get_function_xrefs", params={"address": first_function_address}
        )
        assert response.status_code in [200, 404]

    def test_get_function_call_graph(self, http_client, first_function_address):
        """Get function call graph."""
        response = http_client.get(
            "/get_function_call_graph",
            params={"address": first_function_address, "depth": 2},
        )
        # May not exist in all versions
        assert response.status_code in [200, 404]

    def test_get_function_hash(self, http_client, first_function_address):
        """Get function hash."""
        response = http_client.get(
            "/get_function_hash", params={"address": first_function_address}
        )
        assert response.status_code == 200

    def test_get_function_documentation(self, http_client, first_function_address):
        """Get function documentation."""
        response = http_client.get(
            "/get_function_documentation", params={"address": first_function_address}
        )
        assert response.status_code == 200

    def test_analyze_function_completeness(self, http_client, first_function_address):
        """Analyze function completeness score.

        The declared selector is `function_address`, with no alias for
        `address`. Sent as `address` it was dropped, so this scored whatever
        function happened to be current.
        """
        response = http_client.get(
            "/analyze_function_completeness",
            params={"function_address": first_function_address},
        )
        assert response.status_code == 200
        assert "completeness_score" in response.json()

    def test_get_function_pcode_basic(self, http_client, first_function_address):
        """Issue #192: dump P-code for a function (basic-block iter only).
        Validates that basic_blocks is a list and each entry has start/stop
        addresses + a pcodes list."""
        response = http_client.get(
            "/get_function_pcode",
            params={
                "function_address": first_function_address,
                "granularity": "basic",
            },
        )
        assert response.status_code == 200
        # Endpoint returns flat JSON (no `data` wrapper).
        data = response.json()
        assert "basic_blocks" in data
        assert isinstance(data["basic_blocks"], list)
        # `basic` granularity omits the high-PcodeOp graph
        assert "high_pcodes" not in data
        # Validate shape of the first basic block (if any). Start/stop are
        # nested ServiceUtils.addressToJson objects with a guaranteed
        # 'address' key (and optional address_full/address_space on multi-
        # space binaries).
        if data["basic_blocks"]:
            bb = data["basic_blocks"][0]
            assert "start" in bb and isinstance(bb["start"], dict)
            assert "stop" in bb and isinstance(bb["stop"], dict)
            assert "address" in bb["start"]
            assert "address" in bb["stop"]
            assert "pcodes" in bb
            assert isinstance(bb["pcodes"], list)
            # PcodeOps carry mnemonic + opcode + SSA varnode flags
            if bb["pcodes"]:
                op = bb["pcodes"][0]
                assert "mnemonic" in op
                assert "opcode" in op
                assert "inputs" in op
                # SSA flags now present on every varnode
                if op["inputs"]:
                    vn = op["inputs"][0]
                    for key in ("is_addrtied", "is_hash", "is_persistent", "merge_group"):
                        assert key in vn, f"missing SSA flag '{key}' on varnode: {vn}"

    def test_get_function_pcode_high_granularity(self, http_client, first_function_address):
        """Issue #192: `high` granularity (default) adds the full HighFunction
        PcodeOp graph. Verify both basic_blocks and high_pcodes appear."""
        response = http_client.get(
            "/get_function_pcode",
            params={
                "function_address": first_function_address,
                "granularity": "high",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "basic_blocks" in data
        assert "high_pcodes" in data
        assert isinstance(data["high_pcodes"], list)


class TestXRefEndpoints:
    """Test cross-reference endpoints (read-only)."""

    @pytest.fixture
    def sample_address(self, http_client):
        """Get a sample address from the program.

        /list_functions declares only `program`; `limit` was silently dropped.
        """
        response = http_client.get("/list_functions")
        if response.status_code != 200:
            pytest.skip("Cannot get sample address")
        import re

        # Match "at 10001000" or JSON format
        match = re.search(r"at\s+(?:0x)?([0-9a-fA-F]+)", response.text)
        if not match:
            match = re.search(
                r'"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?', response.text
            )
        if not match:
            pytest.skip("No address found")
        return f"0x{match.group(1)}"

    def test_get_xrefs_to(self, http_client, sample_address):
        """Get cross-references to an address."""
        response = http_client.get("/get_xrefs_to", params={"address": sample_address})
        assert response.status_code == 200

    def test_get_xrefs_from(self, http_client, sample_address):
        """Get cross-references from an address."""
        response = http_client.get(
            "/get_xrefs_from", params={"address": sample_address}
        )
        assert response.status_code == 200


class TestMemoryInspection:
    """Test memory inspection endpoints (read-only)."""

    @pytest.fixture
    def sample_address(self, http_client):
        """Get a sample address from segments."""
        response = http_client.get("/list_segments")
        if response.status_code != 200:
            pytest.skip("Cannot get segments")
        import re

        # Match addresses with or without 0x prefix
        match = re.search(r"(?:0x)?([0-9a-fA-F]{6,})", response.text)
        if not match:
            pytest.skip("No segment address found")
        return f"0x{match.group(1)}"

    def test_inspect_memory_content(self, http_client, sample_address):
        """Inspect memory content at address."""
        response = http_client.get(
            "/inspect_memory_content",
            params={"address": sample_address, "length": 16},
        )
        # May be 404 if not available
        assert response.status_code in [200, 404]

    # test_disassemble_bytes removed from the READ-ONLY suite.
    #
    # It GET-ed /disassemble_bytes with `address`, and accepted [200, 404].
    # /disassemble_bytes is declared `method = "POST"` with `start_address` in
    # the JSON body, so a live server answered 404 every time and the test
    # could not tell that from a pass.
    #
    # Calling it correctly is NOT a read: FunctionService.disassembleBytes
    # creates instructions over undefined bytes, inside a transaction. That
    # belongs in the write tier (tests/integration/test_safe_write_endpoints.py
    # or a mutating file), not here -- rewriting it in place would have turned
    # a no-op into a listing mutation in the suite whose contract is that it
    # never writes. Read-only memory inspection is covered by
    # test_inspect_memory_content above.


class TestSearchInstructions:
    """`/search_instructions` (#172) — operand-pattern instruction search.

    Auto-skips when the endpoint isn't registered (deployed JAR older
    than the source). All assertions are response-shape — they don't
    pin to a specific binary's contents so the suite is portable
    across the team's various analysis sessions.
    """

    def _request(self, http_client, **params):
        return http_client.get("/search_instructions", params=params)

    def test_endpoint_present(self, http_client):
        """Quick health check — endpoint should respond (200) when called
        with a valid mnemonic filter, or 404 if not deployed."""
        r = self._request(http_client, mnemonic="ret")
        if r.status_code == 404:
            pytest.skip("/search_instructions not deployed in current Ghidra JAR")
        assert r.status_code == 200

    def test_response_shape_for_mnemonic_search(self, http_client):
        r = self._request(http_client, mnemonic="ret", limit=5)
        if r.status_code == 404:
            pytest.skip("/search_instructions not deployed")
        assert r.status_code == 200
        body = r.json()
        # Top-level fields the docstring promises.
        for key in (
            "matches",
            "match_count",
            "instructions_scanned",
            "truncated",
            "scope",
            "mnemonic_filter",
            "operand_filter",
        ):
            assert key in body, f"missing top-level field: {key}"
        assert isinstance(body["matches"], list)
        # Both filter-echo keys are always present; empty string means "no filter".
        assert body["mnemonic_filter"] == "ret"
        assert body["operand_filter"] == ""

        # Each match record carries the documented shape.
        for m in body["matches"]:
            for key in ("address", "function", "mnemonic", "operands", "length", "bytes"):
                assert key in m, f"match missing field: {key}"
            assert isinstance(m["length"], int) and m["length"] >= 1
            # bytes is lowercase hex with exactly 2 chars per byte.
            assert len(m["bytes"]) == m["length"] * 2
            assert m["bytes"] == m["bytes"].lower()
            # mnemonic match is case-insensitive but exact.
            assert m["mnemonic"].lower() == "ret"

    def test_rejects_empty_filters(self, http_client):
        """Both filters empty → server-side error (must specify at least one)."""
        r = self._request(http_client, mnemonic="", operand_pattern="", limit=1)
        if r.status_code == 404:
            pytest.skip("/search_instructions not deployed")
        # The endpoint returns {"error": "..."} with HTTP 200 OR an HTTP-level
        # 4xx — both are acceptable signals of "you didn't filter anything".
        if r.status_code == 200:
            body = r.json()
            assert "error" in body
            assert "mnemonic" in body["error"].lower() or "operand" in body["error"].lower()
        else:
            assert r.status_code in (400, 422)

    def test_limit_clamping(self, http_client):
        """Limit ≤ 0 or > 50000 is rejected."""
        r = self._request(http_client, mnemonic="ret", limit=0)
        if r.status_code == 404:
            pytest.skip("/search_instructions not deployed")
        if r.status_code == 200:
            body = r.json()
            assert "error" in body
            assert "limit" in body["error"].lower()
        else:
            assert r.status_code in (400, 422)

    def test_truncated_flag_when_limit_hit(self, http_client):
        """limit=1 on a mnemonic that has many matches sets truncated=True."""
        r = self._request(http_client, mnemonic="ret", limit=1)
        if r.status_code == 404:
            pytest.skip("/search_instructions not deployed")
        assert r.status_code == 200
        body = r.json()
        if body["match_count"] == 0:
            # Binary genuinely has zero `ret` — implausible but skip cleanly.
            pytest.skip("No `ret` instructions in this binary; can't verify truncation")
        assert body["match_count"] == 1
        # `truncated` is True iff the iterator stopped because the limit
        # was reached; it's possible (but unlikely) for a binary to have
        # exactly one `ret` total, in which case truncated stays False.
        # Just assert the field is a bool.
        assert isinstance(body["truncated"], bool)

    def test_operand_filter_substring_match(self, http_client):
        """operand_pattern is a case-insensitive substring on the joined
        operand string — should never match instructions whose operands
        don't contain the substring."""
        r = self._request(http_client, operand_pattern="zzznonexistentzzz", limit=10)
        if r.status_code == 404:
            pytest.skip("/search_instructions not deployed")
        assert r.status_code == 200
        body = r.json()
        assert body["match_count"] == 0
        assert body["matches"] == []
        assert body["operand_filter"] == "zzznonexistentzzz"


class TestBulkHashing:
    """Test bulk hash endpoints (read-only)."""

    def test_get_bulk_function_hashes(self, http_client):
        """Get bulk function hashes."""
        response = http_client.get(
            "/get_bulk_function_hashes", params={"offset": 0, "limit": 10}
        )
        assert response.status_code == 200


class TestCurrentSelection:
    """Test current selection/state endpoints (read-only)."""

    def test_get_current_selection(self, http_client):
        """Get current cursor/selection in Ghidra."""
        response = http_client.get("/get_current_selection")
        # May be 404 if selection endpoint not available
        assert response.status_code in [200, 404]


class TestBytePatternSearch:
    """Test byte pattern search (read-only)."""

    def test_search_byte_patterns(self, http_client):
        """Search for byte patterns."""
        # Search for common function prologue
        response = http_client.get(
            "/search_byte_patterns", params={"pattern": "55 8B EC"}
        )
        assert response.status_code == 200


class TestResponseFormats:
    """Verify response format consistency."""

    def test_version_is_json_parseable(self, http_client):
        """Version response should be JSON."""
        response = http_client.get("/get_version")
        assert response.status_code == 200
        try:
            data = json.loads(response.text)
            assert isinstance(data, dict)
        except json.JSONDecodeError:
            # Plain text is also acceptable
            assert len(response.text) > 0

    def test_list_functions_parseable(self, http_client):
        """Function list should be parseable.

        Sent without `limit`: the endpoint does not declare one.
        """
        response = http_client.get("/list_functions")
        assert response.status_code == 200
        # Should be non-empty
        assert len(response.text) > 0


class TestOverlayAddressSpaces:
    """Overlay-space round-trip. Auto-skips on programs without overlay spaces."""

    def test_get_address_spaces_lists_overlays_and_round_trips(self, http_client):
        import json
        resp = http_client.get("/get_address_spaces")
        assert resp.status_code == 200
        spaces = json.loads(resp.text)["address_spaces"]
        overlays = [s for s in spaces if s.get("is_overlay")]
        if not overlays:
            pytest.skip("program has no overlay address spaces")

        ov = overlays[0]
        assert ov.get("overlayed_space"), "overlay entry must name its base space"
        # Address the overlay at its start; read_memory must resolve it (no error).
        addr = f"{ov['name']}::{ov['start']}"
        r = http_client.get("/read_memory", params={"address": addr, "length": "4"})
        assert r.status_code == 200, r.text
        result = json.loads(r.text)
        assert "error" not in result, f"overlay read failed for {addr}: {result}"


class TestShadowedGlobalsConsistency:
    """`/list_shadowed_globals` must stay a strict SUBSET of `/list_globals`.

    These are two views of one population and their counts render side by side
    on the dashboard's Globals panel, so a divergence between them shows up as
    two numbers that disagree about the same binary. The Java side shares one
    gate (`isGlobalDataSymbol`) precisely so they cannot drift; this test is the
    live proof that the sharing actually holds end to end.

    Background (2026-08-03): `/list_shadowed_globals` was originally written
    with hand-copied gates, which is the same two-code-paths-one-question shape
    that produced every other bug in this area.
    """

    @pytest.fixture
    def shadow_program(self, http_client):
        """An OPEN program that actually has shadowed globals.

        Without this the suite runs against whatever program happens to be
        active -- which after a deploy is the benchmark fixture, has none, and
        skips all three checks. A test that skips is not a test that passes;
        this searches the open set and only skips when the whole session has
        nothing to assert on.
        """
        r = http_client.get("/list_open_programs")
        if r.status_code != 200:
            pytest.skip("cannot enumerate open programs")
        progs = [p.get("path") for p in (json.loads(r.text).get("programs") or [])
                 if isinstance(p, dict) and p.get("path")]
        for path in progs:
            resp = http_client.get("/list_shadowed_globals",
                                   params={"program": path, "limit": 5})
            if resp.status_code == 200 and (json.loads(resp.text).get("shadowed") or []):
                return path
        pytest.skip("no open program has shadowed globals to assert on")

    def _globals(self, http_client, program=None, **params):
        params = {"limit": 100000, "min_xrefs": 0, **params}
        if program:
            params["program"] = program
        r = http_client.get("/list_globals", params=params)
        assert r.status_code == 200
        return json.loads(r.text).get("globals") or []

    def _shadowed(self, http_client, program=None):
        params = {"limit": 100000}
        if program:
            params["program"] = program
        r = http_client.get("/list_shadowed_globals", params=params)
        assert r.status_code == 200
        return json.loads(r.text).get("shadowed") or []

    @staticmethod
    def _addr_of(line):
        # "name @ 1001517a [Label] (undefined) xrefs=1"
        parts = str(line).split(" @ ")
        return parts[1].split()[0].lower().lstrip("0") if len(parts) > 1 else None

    def test_shadowed_is_a_subset_of_list_globals(self, http_client, shadow_program):
        shadowed = self._shadowed(http_client, shadow_program)
        assert shadowed, "fixture guarantees a non-empty set"
        listed = {self._addr_of(l) for l in self._globals(http_client, shadow_program)}
        missing = [s["address"].lower().lstrip("0") for s in shadowed
                   if s["address"].lower().lstrip("0") not in listed]
        assert not missing, (
            f"{len(missing)} shadowed globals are absent from /list_globals — the "
            f"two scanners have drifted: {missing[:5]}")

    def test_shadowed_globals_report_no_type_in_list_globals(self, http_client, shadow_program):
        """The whole point of the formatGlobalSymbol fix.

        A shadowed global has no type AT its address; `symbol.getObject()` used
        to hand back the CONTAINING data unit, so the listing printed the
        covering neighbour's type and every consumer read the global as typed.
        """
        shadowed = self._shadowed(http_client, shadow_program)
        by_addr = {self._addr_of(l): str(l)
                   for l in self._globals(http_client, shadow_program)}
        wrong = []
        for s in shadowed[:50]:
            line = by_addr.get(s["address"].lower().lstrip("0"))
            if line and "(undefined)" not in line:
                wrong.append(line)
        assert not wrong, (
            "shadowed globals still report a type in /list_globals (the "
            f"container's): {wrong[:3]}")

    def test_shadowed_globals_are_selected_by_the_untyped_axis(self, http_client, shadow_program):
        """`type_filter=undefined` derives from getDefinedDataAt, so it already
        selected these correctly even when the printed line contradicted it.
        Selection and display must now agree."""
        shadowed = self._shadowed(http_client, shadow_program)
        untyped = {self._addr_of(l) for l in self._globals(
            http_client, shadow_program, filter="defined", type_filter="undefined")}
        missing = [s["address"].lower().lstrip("0") for s in shadowed
                   if s["address"].lower().lstrip("0") not in untyped]
        assert not missing, (
            f"shadowed globals not selected by type_filter=undefined: {missing[:5]}")
