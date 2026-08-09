"""Turn runtime observations into Ghidra documentation.

The capture agents live in D2MOO (`conformance/behavioral/pd2_frida_*`) because
they are game-side tooling; this is the other half — it reads their JSONL and
writes the conclusions into Ghidra through the MCP HTTP API.

Two inputs, both produced by observing the live game:

  global-writes   pd2_frida_global_writes.py -> per-access records
                  Aggregated into: the VALUE SET a global actually holds (a type,
                  and often an enum), WHO writes it (a name and a plate), and
                  whether it is ever written at all (const-ness).

  call-edges      pd2_frida_indirect_calls.py -> resolved indirect call edges
                  Written back as cross-references Ghidra could not compute,
                  which is what lets bottom-up documentation ordering see through
                  a dispatch table.

REPORT-FIRST, like every other corpus lane here: dry-run is the default and
prints exactly what it would write. `--apply` writes. This is deliberate — a
runtime observation is evidence, not proof, and the failure mode below is real.

THE ONE RULE THAT MATTERS: absence of an observation is NOT evidence of absence.
"never written during my 60s session" means the code path was not exercised, not
that the global is read-only, and a session that never entered combat says
nothing about combat globals. So this script only ever writes claims supported by
a POSITIVE observation (a value that WAS held, a writer that DID write, an edge
that WAS taken). It never writes a negative claim ("read-only", "unused",
"always 0"), because it cannot distinguish those from "not exercised".
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

GHIDRA_URL = "http://127.0.0.1:8089"

# A value set this large is a counter/pointer/handle, not an enum. Enum inference
# past this is noise, and a wrong enum is worse than no enum: it is a confident
# false claim that survives into the plate.
MAX_ENUM_VALUES = 16
# Below this many observations a "value set" is one lucky sample, not a range.
MIN_OBSERVATIONS_FOR_TYPE = 8


def _get(path: str, params: dict | None = None, timeout: int = 30):
    url = GHIDRA_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _post(path: str, body: dict, params: dict | None = None, timeout: int = 60):
    url = GHIDRA_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _ghidra_addr(program: str, module_rva: tuple[str, int], bases: dict) -> str | None:
    """live module+rva -> Ghidra absolute address for `program`.

    Ghidra image base, NOT the live base: the whole point of recording module+rva
    is that the two differ for any relocated module.
    """
    mod, rva = module_rva
    base = bases.get(mod.lower())
    if base is None:
        return None
    return f"{base + rva:x}"


def load_program_bases(programs: list[str]) -> dict:
    """Ghidra image base per program name (lowercased key)."""
    out = {}
    try:
        data = _get("/list_open_programs")
        for p in data.get("programs", []):
            out[p["name"].lower()] = int(p["image_base"], 16)
    except Exception as e:
        print(f"warning: could not read Ghidra program list: {e}", file=sys.stderr)
    return out


# --------------------------------------------------------------------------
# global writes
# --------------------------------------------------------------------------

def summarize_globals(events: list[dict]) -> dict:
    """Aggregate raw accesses into per-global evidence."""
    by = collections.defaultdict(lambda: {
        "reads": 0, "writes": 0, "values": set(), "writers": set(),
        "module": None, "rva": None,
    })
    for e in events:
        g = by[e["global"]]
        g["module"] = e.get("global_module")
        g["rva"] = e.get("global_rva")
        if e.get("op") == "write":
            g["writes"] += 1
        else:
            g["reads"] += 1
        if e.get("value") is not None:
            g["values"].add(e["value"])
        if e.get("writer_module") and e.get("op") == "write":
            g["writers"].add((e["writer_module"], e["writer_rva"]))
    return by


def plan_global_updates(summary: dict) -> list[dict]:
    """Decide what may legitimately be written for each global."""
    plan = []
    for name, g in sorted(summary.items()):
        obs = g["reads"] + g["writes"]
        values = sorted(v for v in g["values"] if isinstance(v, int))
        actions = []

        # A value set is only meaningful with enough samples behind it.
        if values and obs >= MIN_OBSERVATIONS_FOR_TYPE:
            if len(values) <= MAX_ENUM_VALUES and all(0 <= v < 256 for v in values):
                actions.append(("enum_candidate", values))
            width = max(values)
            if width < 256:
                actions.append(("type_hint", "byte-range"))

        if g["writers"]:
            actions.append(("writers", sorted(g["writers"])))

        # Deliberately NOT emitted: "read-only" when writes == 0. A session that
        # never triggered the writer proves nothing, and stamping const on a
        # mutable global is a false claim that outlives the session.
        plan.append({
            "global": name, "module": g["module"], "rva": g["rva"],
            "observations": obs, "reads": g["reads"], "writes": g["writes"],
            "values": values, "actions": actions,
        })
    return plan


def render_global_plate(entry: dict) -> str:
    """Plate text stating ONLY what was observed, and saying so explicitly."""
    lines = ["Runtime-observed behaviour (live PD2 session):"]
    if entry["values"]:
        vals = ", ".join(str(v) for v in entry["values"][:MAX_ENUM_VALUES])
        lines.append(f"  Observed values: {vals}")
    lines.append(f"  Accesses observed: {entry['observations']} "
                 f"({entry['writes']} write, {entry['reads']} read)")
    for kind, payload in entry["actions"]:
        if kind == "writers":
            for mod, rva in payload[:6]:
                lines.append(f"  Written by: {mod}+{rva}")
    lines.append("  NOTE: observed during one session; absence of a value or a")
    lines.append("  writer here means it was not exercised, not that it cannot occur.")
    return "\n".join(lines)


def cmd_global_writes(args) -> int:
    events = [json.loads(l) for l in Path(args.input).read_text(encoding="utf-8").splitlines() if l.strip()]
    if not events:
        print("no events in input")
        return 1
    summary = summarize_globals(events)
    plan = plan_global_updates(summary)

    print(f"{len(events)} accesses over {len(plan)} globals "
          f"({'APPLY' if args.apply else 'dry-run'})\n")
    bases = load_program_bases([args.program]) if args.apply else {}

    wrote = 0
    for entry in plan:
        print(f"{entry['global']}  ({entry['module']}+{entry['rva']})")
        print(f"  observations={entry['observations']} writes={entry['writes']} "
              f"values={entry['values'][:MAX_ENUM_VALUES]}")
        if not entry["actions"]:
            print("  -> nothing supportable (too few observations)\n")
            continue
        plate = render_global_plate(entry)
        for line in plate.splitlines():
            print(f"  | {line}")
        if args.apply:
            addr = _ghidra_addr(args.program, (entry["module"], int(entry["rva"], 16)), bases)
            if addr is None:
                print(f"  !! no Ghidra image base for {entry['module']}; skipped")
            else:
                try:
                    _post("/set_comment", {"address": addr, "comment": plate, "type": "plate"},
                          params={"program": args.program})
                    wrote += 1
                    print(f"  -> wrote plate at {addr}")
                except Exception as e:
                    print(f"  !! write failed at {addr}: {e}")
        print()

    if not args.apply:
        print("dry run — nothing written. Re-run with --apply to write plates.")
    else:
        print(f"wrote {wrote} plate(s)")
    return 0


# --------------------------------------------------------------------------
# indirect call edges
# --------------------------------------------------------------------------

def cmd_call_edges(args) -> int:
    text = Path(args.input).read_text(encoding="utf-8")
    try:
        blob = json.loads(text)
        edges = []
        if isinstance(blob, dict) and "slots" in blob:   # table-mode output
            for s in blob["slots"]:
                if s.get("callable"):
                    edges.append({
                        "from_module": blob["module"], "from_rva": None,
                        "to_module": s["target_module"], "to_rva": s["target_rva"],
                        "slot": s["index"], "count": None,
                    })
        else:
            edges = blob if isinstance(blob, list) else []
    except json.JSONDecodeError:
        edges = [json.loads(l) for l in text.splitlines() if l.strip()]

    edges = [e for e in edges if e.get("to_module")]
    if not edges:
        print("no resolved edges in input")
        return 1

    by_target = collections.Counter(f"{e['to_module']}+{e['to_rva']}" for e in edges)
    print(f"{len(edges)} resolved edges -> {len(by_target)} distinct targets "
          f"({'APPLY' if args.apply else 'dry-run'})\n")
    print(f"{'target':<40}{'edges':>7}")
    print("-" * 50)
    for tgt, n in by_target.most_common(40):
        print(f"{tgt:<40}{n:>7}")

    if not args.apply:
        print("\ndry run — nothing written. Re-run with --apply to stamp comments.")
        return 0

    bases = load_program_bases([args.program])
    wrote = 0
    for tgt, n in by_target.items():
        mod, rva = tgt.split("+")
        addr = _ghidra_addr(args.program, (mod, int(rva, 16)), bases)
        if addr is None:
            continue
        note = (f"Runtime-resolved indirect call target (observed {n} edge(s) in a "
                f"live session). Static xrefs cannot see this edge; it is reached "
                f"through a function pointer.")
        try:
            _post("/set_comment", {"address": addr, "comment": note, "type": "plate"},
                  params={"program": args.program})
            wrote += 1
        except Exception as e:
            print(f"  !! write failed at {addr}: {e}")
    print(f"\nwrote {wrote} comment(s)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", default="D2Common.dll",
                    help="Ghidra program the addresses belong to")
    ap.add_argument("--apply", action="store_true",
                    help="actually write to Ghidra (default is a dry run)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("global-writes", help="ingest pd2_frida_global_writes.py JSONL")
    g.add_argument("--input", required=True)
    g.set_defaults(func=cmd_global_writes)

    c = sub.add_parser("call-edges", help="ingest pd2_frida_indirect_calls.py output")
    c.add_argument("--input", required=True)
    c.set_defaults(func=cmd_call_edges)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
