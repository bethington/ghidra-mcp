"""MCP conformance suite CLI.

    # bootstrap a case skeleton for every tool in the live schema
    python -m tests.conformance.run_conformance --generate

    # run the curated corpus, recording any missing golden snapshots
    python -m tests.conformance.run_conformance --record

    # normal run: semantic assertions + snapshot diffing
    python -m tests.conformance.run_conformance

    # read-only tier only (safe to run while fun-doc workers are active)
    python -m tests.conformance.run_conformance --tier read

Its real purpose is differential: run the same corpus against the Python bridge
today and the Java-native MCP endpoint later, then diff. Snapshot drift between
the two *is* the list of behavioral differences the port introduced.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.conformance.cases import (  # noqa: E402
    ProgramFacts, dump_cases, generate_cases, load_cases,
)
from tests.conformance.mcp_client import bridge_transport  # noqa: E402
from tests.conformance.runner import ConformanceRunner  # noqa: E402

CORPUS_DIR = Path(__file__).parent / "corpus"
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"

# The benchmark pair: purpose-built throwaway targets, safe to mutate.
DEFAULT_PROGRAM = "Benchmark.dll"
DEFAULT_SECOND_PROGRAM = "BenchmarkDebug.exe"

# Read-before-write when tiers are combined (--tier all, the default) -- see
# the sort in main() for why this matters.
_TIER_ORDER = {"read": 0, "write": 1}


def probe_facts(transport, program: str, second: str) -> ProgramFacts:
    """Discover live values to feed generated cases.

    Probing beats hardcoding: addresses shift when the benchmark binaries are
    rebuilt, and a suite that hardcodes them fails for a reason that has
    nothing to do with the server.
    """
    listing = transport.call_tool("list_functions_enhanced",
                                  {"program": program, "limit": 40}, timeout=90)
    functions = (listing.json() or {}).get("functions") or []
    real = [f for f in functions if not f.get("isThunk") and not f.get("isExternal")]
    if not real:
        raise SystemExit(f"no non-thunk functions found in {program}; cannot generate cases")
    first = real[0]
    second_fn = real[1] if len(real) > 1 else first

    def addr(f):
        a = str(f.get("address", "")).lower()
        return a if a.startswith("0x") else f"0x{a}"

    struct_name = None
    types = transport.call_tool("search_data_types",
                                {"program": program, "pattern": "_s", "limit": 5}, timeout=60)
    parsed = types.json()
    if isinstance(parsed, dict):
        for entry in (parsed.get("types") or parsed.get("results") or [])[:1]:
            if isinstance(entry, dict):
                struct_name = entry.get("name")

    return ProgramFacts(
        program=program,
        function_address=addr(first),
        function_name=first.get("name") or "entry",
        second_function_address=addr(second_fn),
        second_program=second,
        struct_name=struct_name,
        type_name="int",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Ghidra MCP conformance suite")
    ap.add_argument("--generate", action="store_true",
                    help="bootstrap case skeletons from the live schema and exit")
    ap.add_argument("--record", action="store_true",
                    help="write golden snapshots for cases that have none")
    ap.add_argument("--update-snapshots", action="store_true",
                    help="overwrite existing snapshots (accept current behavior as correct)")
    ap.add_argument("--tier", choices=["read", "write", "destructive", "all"], default="all",
                    help="which tier to run (default: all non-destructive)")
    ap.add_argument("--program", default=DEFAULT_PROGRAM)
    ap.add_argument("--second-program", default=DEFAULT_SECOND_PROGRAM)
    ap.add_argument("--ghidra-url", default="http://127.0.0.1:8089")
    ap.add_argument("--corpus", default=str(CORPUS_DIR))
    ap.add_argument("--json-report", default="",
                    help="write the full outcome report to this path")
    ap.add_argument("--fail-fast", action="store_true")
    args = ap.parse_args()

    transport = bridge_transport(str(REPO_ROOT), ghidra_url=args.ghidra_url)
    print("starting MCP transport (bridge, stdio)...", flush=True)
    init = transport.start()
    server = init.get("serverInfo", {})
    print(f"  connected: {server.get('name')} v{server.get('version')}")

    try:
        tools = transport.list_tools()
        print(f"  {len(tools)} tools registered")

        if args.generate:
            schema = json.loads(
                transport.call_tool("mcp_schema", {}, timeout=60).text or "{}"
            )
            schema_tools = schema.get("tools") or []
            if not schema_tools:
                schema_tools = [{"path": "/" + t["name"], "params": [
                    {"name": k, "required": k in (t.get("inputSchema", {}).get("required") or [])}
                    for k in (t.get("inputSchema", {}).get("properties") or {})
                ]} for t in tools]
            facts = probe_facts(transport, args.program, args.second_program)
            print(f"  probed facts: {facts.function_name} @ {facts.function_address}")
            cases = generate_cases(schema_tools, facts)
            CORPUS_DIR.mkdir(parents=True, exist_ok=True)
            out = CORPUS_DIR / "generated_baseline.yaml"
            dump_cases(cases, out, header=(
                "# GENERATED baseline -- one smoke case per tool.\n"
                "# Generated cases assert only that the call completes without an\n"
                "# MCP-level error. Curate them: tighten assertions, add edge cases\n"
                "# and write round-trips, then move them into a curated corpus file.\n"
                "# Regenerate with: python -m tests.conformance.run_conformance --generate"
            ))
            runnable = sum(1 for c in cases if not c.skip)
            print(f"  wrote {len(cases)} cases ({runnable} runnable) -> {out}")
            return 0

        corpus_dir = Path(args.corpus)
        files = sorted(corpus_dir.glob("*.yaml")) if corpus_dir.is_dir() else []
        if not files:
            print(f"no corpus YAML found in {corpus_dir}; run --generate first", file=sys.stderr)
            return 2
        cases = []
        for f in files:
            cases.extend(load_cases(f))
        if args.tier != "all":
            cases = [c for c in cases if c.tier == args.tier]
        else:
            cases = [c for c in cases if c.tier != "destructive"]
            # Corpus files interleave read and write cases in file order, not
            # tier order -- generated_baseline.yaml's write-tier smoke cases
            # (e.g. clear_function_comments) would otherwise run before
            # read_assertions*.yaml's read-tier assertions and leave their
            # target address mutated out from under them. Stable sort keeps
            # each tier's relative order, just read-before-write.
            cases.sort(key=lambda c: _TIER_ORDER.get(c.tier, 99))
        print(f"  {len(cases)} cases loaded from {len(files)} file(s)\n")

        runner = ConformanceRunner(
            transport, SNAPSHOT_DIR, record=args.record, update=args.update_snapshots,
        )

        def progress(i, total, outcome):
            mark = {"pass": ".", "fail": "F", "skip": "s", "error": "E"}[outcome.status]
            print(mark, end="", flush=True)
            if i % 72 == 0:
                print(f"  [{i}/{total}]", flush=True)
            if args.fail_fast and outcome.status in ("fail", "error"):
                raise SystemExit(f"\nfail-fast: {outcome.case_id}: {outcome.detail}")

        runner.run(cases, progress=progress)
        print()
        summary = runner.summary()
        print("\n=== conformance summary ===")
        for status, n in sorted(summary["by_status"].items()):
            print(f"  {status:8s} {n}")
        print("  snapshots: " + ", ".join(
            f"{k}={v}" for k, v in sorted(summary["by_snapshot"].items())))
        if summary["failures"]:
            print(f"\n=== {len(summary['failures'])} failure(s) ===")
            for f in summary["failures"][:40]:
                print(f"  {f['case']}\n      {f['detail']}")
                if f["preview"]:
                    print(f"      response: {f['preview'][:160]}")
        if args.json_report:
            report = {
                "summary": summary,
                "outcomes": [vars(o) for o in runner.outcomes],
            }
            Path(args.json_report).write_text(
                json.dumps(report, indent=2, default=str), encoding="utf-8")
            print(f"\nreport -> {args.json_report}")
        return 1 if summary["failures"] else 0
    finally:
        transport.stop()


if __name__ == "__main__":
    raise SystemExit(main())
