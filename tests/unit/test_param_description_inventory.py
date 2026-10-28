"""Unit tests for tools.param_description_inventory.

This script is the reproducible measurement behind "294 undescribed schema
parameters went to 0" — the number in the CHANGELOG, and the one anybody
re-checking the claim will re-run against an old checkout. A parser whose
output is quoted as evidence has to be tested, or the evidence is just an
assertion.

The Java side already has `ParamDescriptionCoverageTest` as the build-time gate.
These tests cover the thing that gate cannot: whether the counting is right.
Most of them are about the ways naive parsing gets Java wrong — a `//` inside a
string literal, a comma inside `Map<String, String>`, a second annotation
stacked before the signature, a description split across `+` concatenation.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from tools.param_description_inventory import (
    SKIP_FILES,
    SRC,
    _display_path,
    _skip_annotations,
    collect,
    concat_string_literals,
    iter_sources,
    main,
    match_paren,
    parse_param_anno,
    render,
    scan_file,
    split_top_level,
    strip_comments,
    summarize,
    unescape_java,
    unquote,
)


# ---------------------------------------------------------------------------
# strip_comments
# ---------------------------------------------------------------------------

class TestStripComments:
    def test_blanks_line_comment_but_keeps_newline(self):
        out = strip_comments("int a; // gone\nint b;")
        assert out.startswith("int a; ")
        assert "gone" not in out
        assert out.endswith("\nint b;")

    def test_offsets_and_line_count_survive(self):
        src = "a\n/* one\n   two */\nb"
        out = strip_comments(src)
        assert len(out) == len(src), "offsets must be preserved for line reporting"
        assert out.count("\n") == src.count("\n")
        assert "one" not in out and "two" not in out

    def test_string_literal_containing_slashes_is_not_a_comment(self):
        # The real trigger: a description mentioning a path or a URL.
        src = 'description = "see http://x and // not a comment"'
        assert strip_comments(src) == src

    def test_block_comment_opener_inside_string_is_ignored(self):
        src = 'String s = "/* not a comment */"; int a;'
        assert strip_comments(src) == src

    def test_escaped_quote_does_not_end_the_string(self):
        src = 'String s = "he said \\"hi\\" // still string"; // gone'
        out = strip_comments(src)
        assert "still string" in out
        assert "gone" not in out

    def test_char_literal_quote_does_not_open_a_string(self):
        # A lone '"' char literal used to swallow the rest of the file.
        src = "char q = '\"'; // gone\nint after;"
        out = strip_comments(src)
        assert "gone" not in out
        assert "int after;" in out

    def test_escaped_char_literal(self):
        src = "char c = '\\''; // gone\nint after;"
        out = strip_comments(src)
        assert "gone" not in out
        assert "int after;" in out

    def test_unterminated_block_comment_does_not_hang(self):
        assert "x" not in strip_comments("int a; /* x")


# ---------------------------------------------------------------------------
# match_paren
# ---------------------------------------------------------------------------

class TestMatchParen:
    def test_simple(self):
        assert match_paren("f(a)", 1) == 3

    def test_nested(self):
        text = "f(g(x), h(y))"
        assert match_paren(text, 1) == len(text) - 1

    def test_paren_inside_string_is_ignored(self):
        text = 'f("a) not the end", b)'
        assert text[match_paren(text, 1)] == ")"
        assert match_paren(text, 1) == len(text) - 1

    def test_escaped_quote_inside_string(self):
        text = 'f("a\\") still string", b)'
        assert match_paren(text, 1) == len(text) - 1

    def test_unbalanced_raises(self):
        with pytest.raises(ValueError, match="unbalanced"):
            match_paren("f(a", 1)


# ---------------------------------------------------------------------------
# split_top_level
# ---------------------------------------------------------------------------

class TestSplitTopLevel:
    def test_plain_split(self):
        assert [p.strip() for p in split_top_level("a, b, c")] == ["a", "b", "c"]

    def test_generic_comma_is_not_a_separator(self):
        # Map<String, String> is a real parameter type in FunctionService.
        parts = split_top_level("Map<String, String> renames, String program")
        assert len(parts) == 2
        assert "Map<String, String>" in parts[0]

    def test_nested_parens_and_braces(self):
        parts = split_top_level('@Param(value = "a", aliases = {"x", "y"}) String a, int b')
        assert len(parts) == 2
        assert parts[1].strip() == "int b"

    def test_comma_inside_string_is_not_a_separator(self):
        parts = split_top_level('@Param(description = "one, two") String a, int b')
        assert len(parts) == 2

    def test_escaped_quote_inside_string(self):
        parts = split_top_level('@Param(description = "say \\"a, b\\"") String a, int b')
        assert len(parts) == 2

    def test_trailing_whitespace_only_chunk_is_dropped(self):
        assert split_top_level("a,   ") == ["a"]

    def test_empty_input(self):
        assert split_top_level("") == []


# ---------------------------------------------------------------------------
# annotation element parsing
# ---------------------------------------------------------------------------

class TestParseParamAnno:
    def test_named_elements(self):
        elems = parse_param_anno('value = "program", defaultValue = "", source = ParamSource.BODY')
        assert unquote(elems["value"]) == "program"
        assert unquote(elems["defaultValue"]) == ""
        assert elems["source"] == "ParamSource.BODY"

    def test_positional_form_gets_a_value(self):
        assert unquote(parse_param_anno('"address"')["value"]) == "address"

    def test_array_element(self):
        elems = parse_param_anno('value = "a", aliases = {"x", "y"}')
        assert elems["aliases"] == '{"x", "y"}'
        assert unquote(elems["value"]) == "a"

    def test_boolean_and_dotted_values(self):
        elems = parse_param_anno("fieldsJson = true, source = ParamSource.QUERY")
        assert elems["fieldsJson"] == "true"
        assert elems["source"] == "ParamSource.QUERY"

    def test_no_elements_at_all(self):
        assert parse_param_anno("") == {}


class TestUnquote:
    def test_none_passes_through(self):
        assert unquote(None) is None

    def test_strips_quotes_and_whitespace(self):
        assert unquote('  "abc" ') == "abc"

    def test_bare_token_passes_through(self):
        assert unquote("ParamSource.BODY") == "ParamSource.BODY"

    def test_empty_string_literal(self):
        assert unquote('""') == ""

    def test_concatenated_value_is_joined_not_truncated(self):
        assert unquote('"aa" + "bb"') == "aabb"


class TestConcatStringLiterals:
    def test_joins_java_concatenation(self):
        raw = '"Address in the program. " + "Accepts 0x<hex>."'
        assert concat_string_literals(raw) == "Address in the program. Accepts 0x<hex>."

    def test_joins_across_newlines(self):
        # How every long description in the tree is actually written.
        raw = '"one "\n            + "two "\n            + "three"'
        assert concat_string_literals(raw) == "one two three"

    def test_single_literal(self):
        assert concat_string_literals('"one"') == "one"

    def test_non_literal_passes_through(self):
        assert concat_string_literals("SOME_CONSTANT") == "SOME_CONSTANT"

    def test_escapes_are_resolved(self):
        assert concat_string_literals(r'"say \"hi\""') == 'say "hi"'


class TestUnescapeJava:
    @pytest.mark.parametrize("raw,expected", [
        (r"\"", '"'),
        (r"\'", "'"),
        (r"\n", "\n"),
        (r"\t", "\t"),
        (r"\r", "\r"),
        ("\\\\", "\\"),
        ("plain", "plain"),
    ])
    def test_known_escapes(self, raw, expected):
        assert unescape_java(raw) == expected

    def test_backslash_before_quote_is_one_pass(self):
        # A single left-to-right pass: the \\ must not be re-read as escaping
        # the following quote.
        assert unescape_java(r"a\\" + r'\"b') == 'a\\"b'

    def test_unknown_escape_is_left_alone(self):
        assert unescape_java(r"\q") == r"\q"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class TestDisplayPath:
    def test_relative_to_repo_uses_forward_slashes(self, tmp_path: Path):
        target = tmp_path / "src" / "main" / "X.java"
        assert _display_path(target, tmp_path) == "src/main/X.java"

    def test_off_tree_path_falls_back_to_the_name(self, tmp_path: Path):
        # Scanning an extracted old checkout puts sources outside the repo root.
        assert _display_path(Path("/elsewhere/Y.java"), tmp_path) == "Y.java"


class TestSkipAnnotations:
    def test_stops_at_the_signature(self):
        code = "  public Response f("
        assert code[_skip_annotations(code, 0)] == "p"

    def test_skips_a_stacked_annotation_with_parens(self):
        code = '\n    @SuppressWarnings("unchecked")\n    public Response f('
        assert code[_skip_annotations(code, 0):].startswith("public Response f(")

    def test_skips_a_marker_annotation_without_parens(self):
        code = "\n    @Override\n    public Response f("
        assert code[_skip_annotations(code, 0):].startswith("public Response f(")

    def test_end_of_input(self):
        code = "   \n  "
        assert _skip_annotations(code, 0) == 0


# ---------------------------------------------------------------------------
# scan_file — the whole pipeline over real-shaped Java
# ---------------------------------------------------------------------------

JAVA = '''package com.xebyte.core;

/** Javadoc mentioning @Param(value = "ghost") must not become a parameter. */
public class FakeService {

    @McpTool(path = "/documented_tool", method = "POST", description = "d", category = "c")
    public Response documented(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> "
                               + "or <space>:<hex>.") String addressStr,
            @Param(value = "renames", source = ParamSource.BODY) Map<String, String> renames,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "quoted", description = "Send {\\"a\\": 1}.\\nSecond line.") String quoted,
            TaskMonitor monitor) {
        // @Param(value = "commented_out") int ignored
        return null;
    }

    @McpTool(path = "/blank_description", description = "d", category = "c")
    @SuppressWarnings("unchecked")
    public Response blank(
            @Param(value = "empty", description = "") String empty,
            @Param(value = "spaces", description = "   ") String spaces) {
        return null;
    }

    @McpTool(path = "/no_params", description = "d", category = "c")
    public Response noParams() {
        return null;
    }

    // Legacy helper: annotated but NOT an @McpTool, so it is not in the schema.
    public Response helper(
            @Param(value = "unreachable") String unreachable) {
        return null;
    }
}
'''


@pytest.fixture()
def java_file(tmp_path: Path) -> Path:
    src = tmp_path / "src" / "main" / "java" / "com" / "xebyte"
    src.mkdir(parents=True)
    path = src / "FakeService.java"
    path.write_text(JAVA, encoding="utf-8")
    return path


class TestScanFile:
    def test_finds_exactly_the_mcptool_parameters(self, java_file: Path, tmp_path: Path):
        rows = scan_file(java_file, tmp_path)
        assert [r["param"] for r in rows] == [
            "address", "renames", "limit", "quoted", "empty", "spaces",
        ]

    def test_unannotated_signature_parameter_is_not_a_schema_parameter(
            self, java_file: Path, tmp_path: Path):
        # `TaskMonitor monitor` is a plain Java argument, never an MCP input.
        assert "monitor" not in {r["param"] for r in scan_file(java_file, tmp_path)}

    def test_escapes_in_a_description_are_resolved(self, java_file: Path, tmp_path: Path):
        row = next(r for r in scan_file(java_file, tmp_path) if r["param"] == "quoted")
        assert row["description"] == 'Send {"a": 1}.\nSecond line.'

    def test_ignores_params_on_non_mcptool_helpers(self, java_file: Path, tmp_path: Path):
        names = {r["param"] for r in scan_file(java_file, tmp_path)}
        assert "unreachable" not in names, "a helper's dead annotation is not in the schema"

    def test_ignores_params_in_javadoc_and_comments(self, java_file: Path, tmp_path: Path):
        names = {r["param"] for r in scan_file(java_file, tmp_path)}
        assert "ghost" not in names
        assert "commented_out" not in names

    def test_concatenated_description_counts_as_documented(self, java_file: Path, tmp_path: Path):
        row = next(r for r in scan_file(java_file, tmp_path) if r["param"] == "address")
        assert row["documented"] is True
        assert row["description"] == "Address in the program. Accepts 0x<hex> or <space>:<hex>."

    def test_empty_and_whitespace_descriptions_count_as_undocumented(
            self, java_file: Path, tmp_path: Path):
        rows = {r["param"]: r for r in scan_file(java_file, tmp_path)}
        assert rows["empty"]["documented"] is False
        assert rows["spaces"]["documented"] is False, "whitespace is not a description"

    def test_missing_description_element_counts_as_undocumented(
            self, java_file: Path, tmp_path: Path):
        rows = {r["param"]: r for r in scan_file(java_file, tmp_path)}
        assert rows["limit"]["documented"] is False
        assert rows["limit"]["description"] == ""

    def test_records_tool_path_source_and_default(self, java_file: Path, tmp_path: Path):
        rows = {r["param"]: r for r in scan_file(java_file, tmp_path)}
        assert rows["address"]["path"] == "/documented_tool"
        assert rows["address"]["source"] == "ParamSource.BODY"
        assert rows["limit"]["source"] == "QUERY(default)", "QUERY is the annotation's default"
        assert rows["limit"]["default"] == "100"
        assert rows["address"]["default"] is None

    def test_generic_type_survives_the_comma(self, java_file: Path, tmp_path: Path):
        row = next(r for r in scan_file(java_file, tmp_path) if r["param"] == "renames")
        assert row["java_type"] == "Map<String, String>"

    def test_stacked_annotation_does_not_hide_the_parameters(
            self, java_file: Path, tmp_path: Path):
        # /blank_description carries @SuppressWarnings between @McpTool and the
        # signature; a scanner that grabs the next '(' finds zero params there.
        assert {r["param"] for r in scan_file(java_file, tmp_path)
                if r["path"] == "/blank_description"} == {"empty", "spaces"}

    def test_line_numbers_point_into_the_original_source(self, java_file: Path, tmp_path: Path):
        lines = java_file.read_text(encoding="utf-8").split("\n")
        for row in scan_file(java_file, tmp_path):
            assert "public Response" in lines[row["line"] - 1]

    def test_service_and_file_fields(self, java_file: Path, tmp_path: Path):
        row = scan_file(java_file, tmp_path)[0]
        assert row["service"] == "FakeService"
        assert row["file"].endswith("com/xebyte/FakeService.java")

    def test_tool_with_no_parameters_yields_no_rows(self, java_file: Path, tmp_path: Path):
        assert not [r for r in scan_file(java_file, tmp_path) if r["path"] == "/no_params"]

    def test_tool_name_falls_back_when_path_is_absent(self, tmp_path: Path):
        path = tmp_path / "N.java"
        path.write_text(
            '@McpTool(name = "named_tool")\npublic Response f(@Param("a") String a) {}\n',
            encoding="utf-8")
        row = scan_file(path, tmp_path)[0]
        assert row["tool"] == "named_tool"
        assert row["path"] == ""
        assert row["param"] == "a", "positional @Param(\"a\") must resolve"

    def test_truncated_annotation_at_eof_is_skipped_not_crashed(self, tmp_path: Path):
        path = tmp_path / "T.java"
        path.write_text('@McpTool(path = "/x")', encoding="utf-8")
        assert scan_file(path, tmp_path) == []


# ---------------------------------------------------------------------------
# tree walk + aggregation
# ---------------------------------------------------------------------------

class TestIterSources:
    def test_skips_the_annotation_declarations(self, tmp_path: Path):
        for name in ("Param.java", "McpTool.java", "Service.java"):
            (tmp_path / name).write_text("", encoding="utf-8")
        assert [p.name for p in iter_sources(tmp_path)] == ["Service.java"]

    def test_skip_set_is_what_it_claims(self):
        assert SKIP_FILES == {"Param.java", "McpTool.java"}

    def test_recurses_and_sorts(self, tmp_path: Path):
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "B.java").write_text("", encoding="utf-8")
        (tmp_path / "A.java").write_text("", encoding="utf-8")
        (tmp_path / "notes.txt").write_text("", encoding="utf-8")
        assert [p.name for p in iter_sources(tmp_path)] == ["A.java", "B.java"]


class TestSummarize:
    def test_counts_per_service(self):
        rows = [
            {"service": "A", "documented": True},
            {"service": "A", "documented": False},
            {"service": "B", "documented": True},
        ]
        assert summarize(rows) == {"A": (2, 1), "B": (1, 0)}

    def test_empty(self):
        assert summarize([]) == {}


class TestCollect:
    def test_scans_the_tree(self, java_file: Path, tmp_path: Path):
        rows = collect(java_file.parent, tmp_path)
        assert len(rows) == 6
        assert sum(1 for r in rows if not r["documented"]) == 4


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestMain:
    def test_summary_report(self, java_file: Path, tmp_path: Path):
        out = io.StringIO()
        assert main([], src_root=java_file.parent, repo=tmp_path, out=out) == 0
        text = out.getvalue()
        assert "FakeService" in text
        assert "TOTAL" in text
        assert "@McpTool methods with params: 2" in text, "no_params contributes no rows"

    def test_list_flag_names_each_undocumented_parameter(self, java_file: Path, tmp_path: Path):
        out = io.StringIO()
        main(["--list"], src_root=java_file.parent, repo=tmp_path, out=out)
        text = out.getvalue()
        assert "Undocumented parameters:" in text
        for name in ("limit", "renames", "empty", "spaces"):
            assert f"({name})" in text
        assert "(address)" not in text, "documented params must not be listed"

    def test_json_flag_emits_parseable_rows(self, java_file: Path, tmp_path: Path):
        out = io.StringIO()
        main(["--json"], src_root=java_file.parent, repo=tmp_path, out=out)
        rows = json.loads(out.getvalue())
        assert len(rows) == 6
        assert {"file", "service", "tool", "path", "line", "param", "java_type",
                "source", "default", "documented", "description"} == set(rows[0])

    def test_defaults_to_stdout(self, java_file: Path, tmp_path: Path, capsys):
        assert main([], src_root=java_file.parent, repo=tmp_path) == 0
        assert "TOTAL" in capsys.readouterr().out

    def test_render_without_list_omits_the_detail_section(self):
        out = io.StringIO()
        render([{"service": "S", "documented": False, "file": "f", "tool": "t",
                 "param": "p", "java_type": "int", "source": "q", "default": None}],
               show_list=False, out=out)
        assert "Undocumented parameters:" not in out.getvalue()


# ---------------------------------------------------------------------------
# The claim itself
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SRC.is_dir(), reason="Java sources not present in this checkout")
def test_repo_has_no_undescribed_schema_parameters():
    """The Python-side twin of ParamDescriptionCoverageTest.

    That Java test is the build gate; this one keeps the *measurement* honest,
    so a parser regression that silently stopped finding parameters would show
    up here as a suspiciously small total rather than as a clean zero.
    """
    rows = collect()
    assert len(rows) > 500, "scanner found implausibly few parameters — parser regression?"
    undocumented = [f"{r['path'] or r['tool']}({r['param']})"
                    for r in rows if not r["documented"]]
    assert undocumented == [], (
        f"{len(undocumented)} @Param declarations reach /mcp/schema with no description: "
        + ", ".join(undocumented[:20]))
