"""Case loading and bootstrap generation.

Cases live in YAML next to the binaries they target. Hand-authoring ~264 of
them from a blank page is slow and, worse, biased toward the tools you already
suspect. So generation is two-phase:

1. `generate_cases()` synthesizes a runnable skeleton for every tool in the live
   schema, filling required parameters from facts probed off the real program.
2. Those skeletons get curated -- tightened assertions, extra edge cases, write
   round-trips -- and committed. Generation is a starting point, never the
   final artifact, because a generated assertion only ever proves "it responded".

The parameter synthesizer is the interesting part: it maps a parameter *name*
to a live value (addresses, function names, type names, struct names probed
from the program under test), which is what makes a generated case actually
exercise the tool instead of bouncing off a validation error.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .runner import Case

# Tools that must never be auto-invoked: they end the session, execute
# arbitrary code, or destroy project state. They get hand-written cases in the
# opt-in destructive tier instead.
DESTRUCTIVE = {
    "exit_ghidra", "delete_file", "delete_function", "close_program",
    "open_program", "open_project", "create_folder", "set_image_base",
    "run_ghidra_script", "run_script_inline", "import_file", "reanalyze",
    "run_analysis", "create_memory_block", "switch_program",
    "save_all_programs", "delete_data_type", "delete_project",
    "archive_project", "restore_project", "move_file", "move_folder",
    "create_project", "import_program", "export_program", "checkin_program",
    "load_program", "load_program_from_project", "close_project",
    "delete_property_map", "remove_program_option", "clear_flow_and_repair",
}

# Environment-gated: registered, but unusable without a fixture that does not
# exist in a plain GUI session. Skipped with a reason rather than failed, so
# the suite stays honest about what it did and did not prove.
GATED_PREFIXES = ("debugger", "server_", "server/")
GATED_EXACT = {
    "debugger_launch", "debugger_attach", "debugger_detach",
    "emulate_function", "emulate_hash_batch",
}
GATE_REASONS = {
    "debugger": "needs a live TraceRmi debug session (Phase 2 fixture)",
    "server": "needs a Ghidra Server instance (Phase 2 fixture)",
    "headless": "needs the standalone headless server (Phase 2 fixture)",
}

# Tools whose output describes the *operator's session* rather than the program
# under test: which programs happen to be open, the project name, the Ghidra
# Server address, file counts. Snapshotting these is wrong twice over -- the
# golden churns whenever the operator opens a different binary, and it commits
# infrastructure details to a public repo.
#
# Not hypothetical: the first recording pass wrote a private Ghidra Server
# address into project_info.snap, and the repo's own data-egress guard failed
# the build over it. These get shape assertions instead of snapshots.
ENVIRONMENT_COUPLED = {
    "project_info", "list_open_programs", "list_project_files", "list_instances",
    "mcp_instance_info", "mcp_health", "compare_programs_documentation",
    "merge_program_documentation", "tool_running_tools", "server_status",
    "get_current_program_info", "analysis_status", "list_scripts",
}


class ProgramFacts:
    """Live values probed from the program under test.

    Generated cases are only as good as these: a synthesized `address` that
    isn't a real function entry makes the case assert nothing but an error path.
    """

    def __init__(self, program: str, function_address: str, function_name: str,
                 data_address: str | None = None, string_address: str | None = None,
                 label_name: str | None = None, struct_name: str | None = None,
                 type_name: str = "int", tag_name: str | None = None,
                 segment_name: str = ".text", second_function_address: str | None = None,
                 second_program: str | None = None):
        self.program = program
        self.function_address = function_address
        self.function_name = function_name
        self.data_address = data_address or function_address
        self.string_address = string_address or data_address or function_address
        self.label_name = label_name or function_name
        self.struct_name = struct_name
        self.type_name = type_name
        self.tag_name = tag_name
        self.segment_name = segment_name
        self.second_function_address = second_function_address or function_address
        self.second_program = second_program or program


def synthesize_args(tool: dict[str, Any], facts: ProgramFacts) -> tuple[dict[str, Any], str | None]:
    """Build arguments for a tool from its schema plus live program facts.

    Returns (args, unresolved_reason). `unresolved_reason` is non-None when a
    required parameter has no sensible synthetic value -- those cases are
    emitted as skips rather than as cases that would fail for the wrong reason.
    """
    by_name: dict[str, Any] = {
        "program": facts.program,
        "address": facts.function_address,
        "function_address": facts.function_address,
        "function": facts.function_name,
        "function_name": facts.function_name,
        "name": facts.function_name,
        "start_address": facts.function_address,
        "from_address": facts.function_address,
        "to_address": facts.second_function_address,
        "address_a": facts.function_address,
        "address_b": facts.second_function_address,
        "struct_address": facts.data_address,
        "type_name": facts.type_name,
        "base_type": facts.type_name,
        "source_type": facts.type_name,
        "new_type": facts.type_name,
        "program_a": facts.program,
        "program_b": facts.second_program,
        "source_program": facts.program,
        "target_program": facts.second_program,
        "pattern": "int",
        "filter": "",
        "category": "",
        "category_path": "/",
        "limit": 5,
        "offset": 0,
        "group": "function",
        "direction": "both",
    }
    if facts.struct_name:
        by_name["struct_name"] = facts.struct_name
        by_name["parent_struct"] = facts.struct_name

    args: dict[str, Any] = {}
    unresolved: list[str] = []
    for param in tool.get("params", []) or []:
        pname = param.get("name")
        if pname is None:
            continue
        if pname in by_name:
            value = by_name[pname]
            # Don't send empty strings for optional params; let defaults apply.
            if value == "" and not param.get("required"):
                continue
            args[pname] = value
        elif param.get("required"):
            unresolved.append(pname)

    if unresolved:
        return args, f"no synthetic value for required param(s): {sorted(unresolved)}"
    return args, None


def gate_reason(tool_name: str, category: str) -> str | None:
    if category in GATE_REASONS:
        return GATE_REASONS[category]
    if tool_name in GATED_EXACT:
        return GATE_REASONS.get("debugger", "needs an environment fixture")
    for prefix in GATED_PREFIXES:
        if tool_name.startswith(prefix):
            key = "debugger" if "debug" in prefix else "server"
            return GATE_REASONS[key]
    return None


def generate_cases(schema_tools: list[dict[str, Any]], facts: ProgramFacts,
                   include_destructive: bool = False) -> list[Case]:
    """Bootstrap one smoke case per tool from the live schema."""
    cases: list[Case] = []
    for tool in sorted(schema_tools, key=lambda t: t.get("path", "")):
        path = (tool.get("path") or "").lstrip("/")
        if not path:
            continue
        name = path.replace("/", "_")
        category = tool.get("category", "")
        method = (tool.get("method") or "GET").upper()

        if name in DESTRUCTIVE and not include_destructive:
            cases.append(Case(
                tool=name, skip="destructive: covered by the opt-in --destructive tier",
                tier="destructive", snapshot=False,
            ))
            continue

        gate = gate_reason(name, category)
        if gate:
            cases.append(Case(tool=name, skip=gate, snapshot=False,
                              tier="write" if method == "POST" else "read"))
            continue

        args, unresolved = synthesize_args(tool, facts)
        if unresolved:
            cases.append(Case(tool=name, skip=unresolved, snapshot=False,
                              tier="write" if method == "POST" else "read"))
            continue

        cases.append(Case(
            tool=name,
            args=args,
            # Generated baseline only asserts the call completed without an
            # MCP-level error. Real assertions are added during curation --
            # a generated case proves reachability, not correctness.
            asserts={"is_error": False, "nonempty": True},
            # Environment-coupled output is asserted for shape, never snapshotted.
            snapshot=name not in ENVIRONMENT_COUPLED,
            tier="write" if method == "POST" else "read",
        ))
    return cases


def load_cases(path: Path) -> list[Case]:
    """Load curated cases from a YAML file's `tool_cases:` block."""
    import yaml

    spec = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults = spec.get("defaults") or {}
    out: list[Case] = []
    for raw in spec.get("tool_cases") or []:
        args = {**(defaults.get("args") or {}), **(raw.get("args") or {})}
        out.append(Case(
            tool=raw["tool"],
            args=args,
            asserts=raw.get("assert") or {},
            snapshot=raw.get("snapshot", True),
            timeout=float(raw.get("timeout", defaults.get("timeout", 60))),
            skip=raw.get("skip"),
            tier=raw.get("tier", "read"),
            name=raw.get("name"),
            normalize_extra=[tuple(p) for p in (raw.get("normalize") or [])],
            extract=raw.get("extract") or {},
        ))
    return out


def dump_cases(cases: list[Case], path: Path, header: str = "") -> None:
    """Write cases back out as YAML for curation."""
    import yaml

    payload = {
        "tool_cases": [
            {
                k: v for k, v in {
                    "tool": c.tool,
                    "name": c.name,
                    "tier": c.tier,
                    "args": c.args or None,
                    "assert": c.asserts or None,
                    "snapshot": c.snapshot,
                    "skip": c.skip,
                    "extract": c.extract or None,
                }.items() if v not in (None, {}, [])
            }
            for c in cases
        ]
    }
    text = yaml.safe_dump(payload, sort_keys=False, width=100, allow_unicode=True)
    path.write_text((header + "\n" if header else "") + text, encoding="utf-8")
