"""Offline guards on the conformance corpus and its golden snapshots.

The conformance suite itself needs a live Ghidra with the benchmark pair open,
so it is not a pytest target. These checks are the part that can be verified
without one -- and they cover the failure that motivated them.

**The failure.** A generated case's arguments were wrong, the server correctly
refused, and `--record` wrote the refusal out as the golden. The case then
passed forever while asserting that the endpoint stays broken:

* `assert: is_error: false` checks the MCP *protocol* flag `isError`. A tool
  that returns `{"error": "..."}` in its body did not raise a protocol error,
  so the flag is false and the assertion passes.
* `assert: nonempty: true` passes because an error string is not empty.
* The snapshot layer then recorded the refusal, so on every later run the
  golden matched and the case stayed green.

Measured on the committed corpus: **20 of 124 goldens** were bodies consisting
of nothing but `{"error": ...}`. `search_instructions` was fixed (see
`TOOL_ARG_OVERRIDES` in `tests/conformance/cases.py`); the rest are listed
below with their diagnosis and are debt, not intent.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_DIR = REPO_ROOT / "tests" / "conformance" / "snapshots"
CORPUS_DIR = REPO_ROOT / "tests" / "conformance" / "corpus"

# Goldens that are a bare `{"error": ...}` body and are KNOWN to be wrong.
#
# Every entry is a case whose own arguments the server refused -- not a tool
# that is broken. They are enumerated rather than silently tolerated so the
# list can only shrink: a new error golden fails
# `test_no_new_error_payload_goldens`, and fixing one fails
# `test_known_error_goldens_are_still_error_goldens` until it is removed here.
#
# Fixing one requires a live Ghidra with the benchmark pair open and a reset
# fixture, which is why they are recorded as debt instead of guessed at.
KNOWN_ERROR_PAYLOAD_GOLDENS = {
    # --- the synthesizer omitted a required-in-practice argument ------------
    "add_function_tag.snap": "no 'tags' supplied",
    "remove_function_tag.snap": "no 'tags' supplied",
    "search_functions.snap": "no search term supplied",
    # --- one parameter name, different meanings in different tools ----------
    # `pattern` is a type name for search_data_types but a hex byte string here.
    "search_byte_patterns.snap": "pattern='int' is not hex",
    # `source_type` is a Ghidra reference SourceType, not a data type.
    "add_memory_reference.snap": "source_type='int' is not a SourceType",
    # `group` was filled with the tool CATEGORY name.
    "get_program_options.snap": "group='function' is not an option group",
    # `direction` must be forward|backward; the synthesizer sends 'both'.
    "analyze_dataflow.snap": "direction='both' is not accepted here",
    # `name` was filled with the function name for a tool that wants an address.
    "get_function_labels.snap": "function lookup got '0xcalc_crc16'",
    "get_function_tags.snap": "function lookup got '0xcalc_crc16'",
    # --- the synthesized address is real but wrong for this tool ------------
    "clear_instruction_flow_override.snap": "no instruction at the synthesized address",
    "suggest_field_names.snap": "no struct at the synthesized address",
    "diff_functions.snap": "address_b is not a function entry",
    "disassemble_bytes.snap": "the synthesized address is already disassembled",
    # --- the call is a no-op against already-existing state -----------------
    "create_function.snap": "a function already exists at that address",
    "create_property_map.snap": "the property map already exists",
    # --- environment-gated: belongs in a skip, not a snapshot ---------------
    "archive_ingest_function.snap": "archive exchange disabled (GHIDRA_MCP_ARCHIVE_URL unset)",
    "archive_ingest_program.snap": "archive exchange disabled (GHIDRA_MCP_ARCHIVE_URL unset)",
    "tool_goto_address.snap": "needs a GUI CodeBrowser session",
    "tool_launch_codebrowser.snap": "needs a GUI CodeBrowser session",
}


def _is_error_payload(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    return isinstance(parsed, dict) and set(parsed) == {"error"}


def _error_goldens() -> dict[str, str]:
    found = {}
    for path in sorted(SNAPSHOT_DIR.glob("*.snap")):
        text = path.read_text(encoding="utf-8")
        if _is_error_payload(text):
            found[path.name] = json.loads(text)["error"]
    return found


class TestErrorPayloadGoldens:
    """A refusal must never become a golden by accident."""

    def test_no_new_error_payload_goldens(self):
        """A newly recorded refusal fails here rather than passing forever."""
        unexpected = set(_error_goldens()) - set(KNOWN_ERROR_PAYLOAD_GOLDENS)
        assert not unexpected, (
            "these goldens are a bare {'error': ...} body, which makes the case "
            "assert that the endpoint stays broken. Fix the case's arguments "
            "(see TOOL_ARG_OVERRIDES in tests/conformance/cases.py) or, if the "
            "refusal is the point of the case, set expect_error_payload: true "
            f"and add it here with its diagnosis: {sorted(unexpected)}"
        )

    def test_known_error_goldens_are_still_error_goldens(self):
        """The debt list can only shrink -- a fixed entry must be removed."""
        stale = set(KNOWN_ERROR_PAYLOAD_GOLDENS) - set(_error_goldens())
        assert not stale, (
            "these are listed as known-bad error goldens but no longer are. "
            "Delete them from KNOWN_ERROR_PAYLOAD_GOLDENS so the list keeps "
            f"telling the truth: {sorted(stale)}"
        )

    def test_search_instructions_golden_is_not_a_recorded_refusal(self):
        """The specific regression this file exists for.

        The old golden was
        `{"error": "At least one of 'mnemonic' or 'operand_pattern' must be
        non-empty"}` -- the endpoint's correct refusal of a call that supplied
        neither. Verified against the live server that supplying `mnemonic`
        returns matches, so the endpoint was never broken; the case was.
        """
        path = SNAPSHOT_DIR / "search_instructions.snap"
        if path.exists():
            assert not _is_error_payload(path.read_text(encoding="utf-8"))


class TestGeneratorOverrides:
    """`TOOL_ARG_OVERRIDES` is what keeps the fix alive across `--generate`."""

    def test_search_instructions_case_supplies_a_filter(self):
        """Regenerating the baseline must not reintroduce the empty-filter call."""
        from tests.conformance.cases import TOOL_ARG_OVERRIDES, ProgramFacts, synthesize_args

        assert "search_instructions" in TOOL_ARG_OVERRIDES
        tool = {
            "path": "/search_instructions",
            "params": [
                {"name": "mnemonic", "required": False},
                {"name": "operand_pattern", "required": False},
                {"name": "function", "required": False},
                {"name": "limit", "required": False},
                {"name": "program", "required": False},
            ],
        }
        facts = ProgramFacts(program="Benchmark.dll",
                             function_address="0x10001000",
                             function_name="calc_crc16")
        args, unresolved = synthesize_args(tool, facts)
        assert unresolved is None
        assert args.get("mnemonic") or args.get("operand_pattern"), (
            "the endpoint refuses a call with neither filter set"
        )
        assert "function" not in args, "the override drops the function scope"

    def test_override_none_drops_a_synthesized_param(self):
        from tests.conformance.cases import TOOL_ARG_OVERRIDES, ProgramFacts, synthesize_args

        tool = {"path": "/zz_fake_tool",
                "params": [{"name": "program", "required": False}]}
        facts = ProgramFacts(program="Benchmark.dll",
                             function_address="0x10001000",
                             function_name="calc_crc16")
        TOOL_ARG_OVERRIDES["zz_fake_tool"] = {"program": None, "extra": 7}
        try:
            args, unresolved = synthesize_args(tool, facts)
        finally:
            del TOOL_ARG_OVERRIDES["zz_fake_tool"]
        assert unresolved is None
        assert "program" not in args
        assert args["extra"] == 7

    def test_committed_case_matches_what_the_generator_would_emit(self):
        """Corpus and generator must not drift apart.

        `--generate` overwrites generated_baseline.yaml wholesale, so a fix
        hand-edited into the YAML alone would be silently reverted by the next
        regeneration. The override is the durable half; this pins the two
        together.
        """
        yaml = pytest.importorskip("yaml")
        from tests.conformance.cases import TOOL_ARG_OVERRIDES

        spec = yaml.safe_load(
            (CORPUS_DIR / "generated_baseline.yaml").read_text(encoding="utf-8")
        )
        cases = [c for c in spec["tool_cases"] if c["tool"] == "search_instructions"]
        assert len(cases) == 1
        args = cases[0].get("args") or {}
        override = TOOL_ARG_OVERRIDES["search_instructions"]
        for key, value in override.items():
            if value is None:
                assert key not in args, f"{key} should have been dropped"
            else:
                assert args.get(key) == value


class TestRunnerRefusesToBlessRefusals:
    """The record-time guard, exercised directly."""

    def test_is_error_payload_detection(self):
        from tests.conformance.runner import is_error_payload

        assert is_error_payload('{"error": "nope"}')
        assert not is_error_payload('{"error": "nope", "matches": []}')
        assert not is_error_payload('{"matches": [], "match_count": 0}')
        assert not is_error_payload("not json at all")

    def _runner(self, tmp_path, **kwargs):
        from tests.conformance.runner import ConformanceRunner

        return ConformanceRunner(transport=None, snapshot_dir=tmp_path, **kwargs)

    def _result(self, text):
        from tests.conformance.mcp_client import ToolResult

        return ToolResult(tool="t", text=text, is_error=False, raw={}, elapsed_ms=1)

    def test_record_refuses_an_error_payload(self, tmp_path):
        from tests.conformance.runner import Case

        runner = self._runner(tmp_path, record=True)
        case = Case(tool="search_instructions")
        status, detail = runner._handle_snapshot(case, self._result('{"error": "no"}'))
        assert status == "refused"
        assert "refusing to record" in detail
        assert not (tmp_path / "search_instructions.snap").exists()

    def test_record_allows_an_opted_in_error_payload(self, tmp_path):
        from tests.conformance.runner import Case

        runner = self._runner(tmp_path, record=True)
        case = Case(tool="bad_input_case", expect_error_payload=True)
        status, _ = runner._handle_snapshot(case, self._result('{"error": "no"}'))
        assert status == "new"
        assert (tmp_path / "bad_input_case.snap").exists()

    def test_record_allows_a_normal_response(self, tmp_path):
        from tests.conformance.runner import Case

        runner = self._runner(tmp_path, record=True)
        case = Case(tool="search_instructions")
        status, _ = runner._handle_snapshot(
            case, self._result('{"matches": [], "match_count": 0}')
        )
        assert status == "new"
        assert (tmp_path / "search_instructions.snap").exists()

    def test_refusal_is_reported_as_a_case_failure(self, tmp_path):
        """`refused` must reach the fail list, not just the snapshot tally."""
        from tests.conformance.runner import Case, ConformanceRunner

        class _T:
            def call_tool(self, name, args, timeout=60):
                return TestRunnerRefusesToBlessRefusals()._result('{"error": "no"}')

        runner = ConformanceRunner(transport=_T(), snapshot_dir=tmp_path, record=True)
        outcome = runner.run_case(Case(tool="search_instructions",
                                       asserts={"is_error": False, "nonempty": True}))
        assert outcome.status == "fail", (
            "an is_error/nonempty case passes on an error body -- the snapshot "
            "guard is the only thing that can catch it"
        )
        assert outcome.snapshot_status == "refused"


class TestCorpusYamlRoundTrip:
    def test_expect_error_payload_survives_load(self, tmp_path):
        yaml = pytest.importorskip("yaml")
        from tests.conformance.cases import load_cases

        path = tmp_path / "c.yaml"
        path.write_text(yaml.safe_dump({"tool_cases": [
            {"tool": "a", "expect_error_payload": True},
            {"tool": "b"},
        ]}), encoding="utf-8")
        cases = {c.tool: c for c in load_cases(path)}
        assert cases["a"].expect_error_payload is True
        assert cases["b"].expect_error_payload is False


class TestCaseSelection:
    """`--only` exists so ONE golden can be re-recorded.

    `--update-snapshots` is otherwise all-or-nothing: re-recording
    `mcp_schema.snap` after a deploy meant accepting whatever the other 118
    goldens happened to return in the same pass. That is 118 unreviewed
    rewrites to fix 1, so in practice the schema snapshot simply went stale --
    which is how four GUI-served endpoints ended up exempt from the offline
    tier's parameter checking (`SCHEMA_RECORDING_PREDATES`).
    """

    @staticmethod
    def _cases():
        from tests.conformance.runner import Case

        return [
            Case(tool="mcp_schema", tier="read"),
            Case(tool="list_functions", tier="read"),
            Case(tool="rename_function", tier="write"),
            Case(tool="delete_function", tier="destructive"),
        ]

    def test_only_narrows_to_one_case(self):
        from tests.conformance.run_conformance import select_cases

        picked = select_cases(self._cases(), only=["mcp_schema"], tier="all")
        assert [c.tool for c in picked] == ["mcp_schema"]

    def test_only_accepts_glob_and_repeats(self):
        from tests.conformance.run_conformance import select_cases

        picked = select_cases(self._cases(), only=["mcp_*", "rename_function"],
                              tier="all")
        assert sorted(c.tool for c in picked) == ["mcp_schema", "rename_function"]

    def test_unmatched_pattern_is_fatal(self):
        """A typo must not exit 0 having recorded nothing."""
        from tests.conformance.run_conformance import NoCasesSelected, select_cases

        with pytest.raises(NoCasesSelected, match="matched none"):
            select_cases(self._cases(), only=["mcp_scheme"], tier="all")

    def test_tier_exclusion_is_a_distinct_message(self):
        from tests.conformance.run_conformance import NoCasesSelected, select_cases

        with pytest.raises(NoCasesSelected, match="excludes all of them"):
            select_cases(self._cases(), only=["mcp_schema"], tier="write")

    def test_no_only_keeps_existing_behaviour(self):
        """Default path must still drop destructive/debugger and sort read-first."""
        from tests.conformance.run_conformance import select_cases

        picked = select_cases(self._cases(), only=[], tier="all")
        assert [c.tool for c in picked] == [
            "mcp_schema", "list_functions", "rename_function"
        ]


class TestRunnerRefusesToBlessTransportErrors:
    """An `isError` result means the call never reached the tool.

    Measured 2026-09-18: #440 made the bridge lazy by default, so `mcp_schema`
    was no longer registered, and `--update-snapshots` overwrote the committed
    7,119-line `mcp_schema.snap` with the single line
    `Unknown tool: mcp_schema` -- reporting `new=1` as if it had recorded a
    response. `is_error_payload` could not catch it: that guard tests for a
    JSON `{"error": ...}` body, and a transport error is not JSON.
    """

    @staticmethod
    def _error_result(text):
        from tests.conformance.mcp_client import ToolResult

        return ToolResult(tool="t", text=text, is_error=True, raw={},
                          elapsed_ms=1)

    def _runner(self, tmp_path, **kw):
        from tests.conformance.runner import ConformanceRunner

        return ConformanceRunner(transport=None, snapshot_dir=tmp_path, **kw)

    def test_transport_error_is_not_recorded(self, tmp_path):
        from tests.conformance.runner import Case

        runner = self._runner(tmp_path, update=True)
        status, detail = runner._handle_snapshot(
            Case(tool="mcp_schema"), self._error_result("Unknown tool: mcp_schema")
        )
        assert status == "refused"
        assert "never reached the tool" in detail
        assert not (tmp_path / "mcp_schema.snap").exists()

    def test_transport_error_does_not_clobber_an_existing_golden(self, tmp_path):
        """The damage this actually did: an existing snapshot was destroyed."""
        from tests.conformance.runner import Case

        golden = tmp_path / "mcp_schema.snap"
        golden.write_text('{"count": 239}', encoding="utf-8")

        runner = self._runner(tmp_path, update=True)
        status, _ = runner._handle_snapshot(
            Case(tool="mcp_schema"), self._error_result("Unknown tool: mcp_schema")
        )
        assert status == "refused"
        assert golden.read_text(encoding="utf-8") == '{"count": 239}'

    def test_expect_error_payload_does_not_excuse_a_transport_error(self, tmp_path):
        """`expect_error_payload` opts into a refusal BODY, not a dead call."""
        from tests.conformance.runner import Case

        runner = self._runner(tmp_path, update=True)
        status, _ = runner._handle_snapshot(
            Case(tool="search_instructions", expect_error_payload=True),
            self._error_result("Unknown tool: search_instructions"),
        )
        assert status == "refused"


def test_conformance_transport_disables_lazy_tool_loading():
    """The corpus describes the SERVER's surface, not a client's default.

    Without `--no-lazy` the bridge advertises CORE_GROUPS only (118 of 239
    tools), and every corpus case outside those groups dies on
    `Unknown tool: <name>`.
    """
    from tests.conformance.mcp_client import bridge_transport

    transport = bridge_transport("/repo")
    assert "--no-lazy" in transport.command, (
        f"bridge_transport must disable lazy loading; got {transport.command}"
    )
