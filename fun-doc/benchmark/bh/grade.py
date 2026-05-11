#!/usr/bin/env python3
"""BH.dll documentation-quality grader.

Tier-2 smoke gate. Reads mapping.yaml (source-symbol -> binary-address
pins + truth oracles), pulls the worker's current documentation for
each mapped function from a live Ghidra MCP server, scores it against
the truth, and emits a per-function + corpus-aggregate quality score.

Run before/after any change that could affect doc quality, and as part
of pre-release regression. Commit the resulting runs/*.json alongside
the code change so `git blame` on runs/latest.json says which release
moved each score.

Usage:
    python grade.py --ghidra-url http://127.0.0.1:8089 [--binary BH.dll]
                    [--mapping mapping.yaml] [--output runs/<ts>.json]
                    [--resolve-addresses]   # one-time: fill null addresses
                                            # in mapping.yaml from exports
    python grade.py --compare runs/latest.json runs/prev.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. pip install pyyaml", file=sys.stderr)
    sys.exit(1)


SCRIPT_DIR = Path(__file__).resolve().parent

DEFAULT_GHIDRA_URL = "http://127.0.0.1:8089"
DEFAULT_BINARY = "BH.dll"
DEFAULT_MAPPING = SCRIPT_DIR / "mapping.yaml"
RUNS_DIR = SCRIPT_DIR / "runs"


# ---------------------------------------------------------------------------
# Ghidra HTTP client (minimal — no auth, no retry — this is a local tool)
# ---------------------------------------------------------------------------

class GhidraClient:
    def __init__(self, base_url: str, binary: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.binary = binary
        self.timeout = timeout

    def _get(self, path: str, **params) -> dict | list | str:
        params["program"] = self.binary
        qs = urllib.parse.urlencode(params)
        url = f"{self.base}{path}?{qs}"
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:
            body = resp.read().decode("utf-8")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    def list_exports(self) -> list[dict]:
        """Parse /list_exports' "name -> address" plain-text format.

        MSVC name mangling is stripped: leading underscore + trailing `@N`
        wrapping `__stdcall` arg-size is removed so `_BHGetConfig@4`
        matches the source's `BHGetConfig`. Ordinal_N entries are dropped
        (they shadow the named entries at the same address)."""
        out = self._get("/list_exports")
        if isinstance(out, list):
            return out
        if isinstance(out, dict):
            return out.get("exports") or out.get("results") or []
        # Plain text mode — "Symbol -> address" per line
        if not isinstance(out, str):
            return []
        exports = []
        for line in out.splitlines():
            line = line.strip()
            if not line or " -> " not in line:
                continue
            name, addr = line.rsplit(" -> ", 1)
            name = name.strip()
            addr = addr.strip()
            if name.startswith("Ordinal_") or not addr:
                continue
            # MSVC mangling: `_Name@SIZE` -> `Name`; `Name@SIZE` -> `Name`
            demangled = re.sub(r"^_", "", name)
            demangled = re.sub(r"@\d+$", "", demangled)
            exports.append({"name": demangled, "raw_name": name, "address": addr})
        return exports

    def get_function_by_address(self, address: str) -> dict:
        """Parse get_function_by_address' plain-text reply into a dict.

        Server response shape:
            Function: <name> at <address>
            Signature: <return> <conv> <name>(<args>)
            Entry: <address>
            Body: <address> - <address>
        """
        out = self._get("/get_function_by_address", address=address)
        if isinstance(out, dict):
            return out
        if not isinstance(out, str):
            return {}
        result: dict[str, object] = {"raw": out}
        for line in out.splitlines():
            if line.startswith("Function:"):
                # "Function: <name> at <addr>"
                m = re.match(r"Function:\s*(\S+)\s+at\s+(\S+)", line)
                if m:
                    result["name"] = m.group(1)
                    result["entry"] = m.group(2)
            elif line.startswith("Signature:"):
                result["signature"] = line.split(":", 1)[1].strip()
                # Try to count parameters from the signature
                paren = re.search(r"\(([^)]*)\)", result["signature"])
                if paren:
                    args = paren.group(1).strip()
                    if not args or args.lower() == "void":
                        result["parameters"] = []
                    else:
                        result["parameters"] = [a.strip() for a in args.split(",")]
            elif line.startswith("Entry:"):
                result.setdefault("entry", line.split(":", 1)[1].strip())
            elif line.startswith("Body:"):
                result["body"] = line.split(":", 1)[1].strip()
        return result

    def get_plate_comment(self, address: str) -> str:
        out = self._get("/get_plate_comment", address=address)
        if isinstance(out, dict):
            return out.get("plate_comment") or out.get("comment") or ""
        return str(out or "")

    def get_function_variables(self, address: str) -> list[dict]:
        out = self._get("/get_function_variables", address=address)
        if isinstance(out, dict):
            return out.get("variables") or (out.get("parameters") or []) + (out.get("locals") or [])
        return out if isinstance(out, list) else []


# ---------------------------------------------------------------------------
# Scoring primitives
# ---------------------------------------------------------------------------

def score_name_exact(actual: str, expected_symbol: str) -> float:
    """1.0 if names match exactly (case-insensitive), else 0.0."""
    if not actual:
        return 0.0
    return 1.0 if actual.lower() == expected_symbol.lower() else 0.0


def score_name_resemblance(actual: str, name_tokens: list[str]) -> float:
    """How many of the expected tokens appear in the actual name (case-insensitive)?

    Returns the fraction of tokens that hit, clamped to [0, 1]. An actual
    name containing 2 of 3 expected tokens scores 0.67.
    """
    if not actual or not name_tokens:
        return 0.0
    actual_lower = actual.lower()
    hits = sum(1 for tok in name_tokens if tok.lower() in actual_lower)
    return min(1.0, hits / len(name_tokens))


def score_plate_quality(plate: str, plate_keywords: list[str]) -> float:
    """Plate quality: 0 if empty; 0.5 if non-empty but no keyword match;
    fraction-of-keywords-hit if keywords match."""
    if not plate or not plate.strip():
        return 0.0
    if not plate_keywords:
        return 0.5  # non-empty plate, no expectation -> partial credit
    plate_lower = plate.lower()
    hits = sum(1 for kw in plate_keywords if kw.lower() in plate_lower)
    if hits == 0:
        return 0.3   # non-empty but off-topic -> low score, not zero
    return min(1.0, 0.5 + 0.5 * (hits / len(plate_keywords)))


def score_prototype(func_info: dict, expected: dict) -> float:
    """Return type + arg count vs expected. 0 / 0.5 / 1.0."""
    score = 0.0
    expected_ret = (expected.get("return_type") or "").lower()
    expected_args = expected.get("arg_count")

    actual_sig = (func_info.get("signature") or func_info.get("prototype") or "").lower()
    actual_params = func_info.get("parameters") or func_info.get("args") or []
    if isinstance(actual_params, str):
        actual_params = []  # signature-as-string case
    actual_arg_count = len(actual_params)

    # Return type match (loose — "int" matches "uint32_t", "BOOL" etc.)
    if expected_ret:
        type_aliases = {
            "int": ["int", "uint", "long", "dword", "bool", "boolean"],
            "void": ["void"],
            "bool": ["bool", "boolean", "int", "byte"],
            "pointer": ["*", "ptr", "void *", "lpvoid"],
        }
        if expected_ret in type_aliases:
            if any(alias in actual_sig for alias in type_aliases[expected_ret]):
                score += 0.5
        elif expected_ret in actual_sig:
            score += 0.5

    # Arg count match (exact only — fun-doc workers should infer this precisely)
    if expected_args is not None and actual_arg_count == expected_args:
        score += 0.5

    return min(1.0, score)


def score_variable_typing(variables: list[dict]) -> float:
    """Of the function's local variables, what fraction have a non-default type?

    Default types are undefined / undefined1 / undefined2 / undefined4 /
    undefined8 — fun-doc is supposed to retype these. We give credit for
    the fraction that aren't undefined.
    """
    if not variables:
        return 0.5   # no locals to grade, neither pass nor fail
    typed = 0
    total = 0
    for v in variables:
        vtype = (v.get("type") or "").lower()
        if not vtype:
            continue
        total += 1
        if not vtype.startswith("undefined"):
            typed += 1
    if total == 0:
        return 0.5
    return typed / total


# ---------------------------------------------------------------------------
# Address resolution (exports table -> address)
# ---------------------------------------------------------------------------

def resolve_export_addresses(client: GhidraClient, mapping: dict) -> dict:
    """Walk the binary's export table; for each entry whose export name
    matches a mapping `binary_export`, fill in the address.

    Returns the mutated mapping (in-place modification of the input dict).
    """
    exports_by_name = {e.get("name"): e for e in client.list_exports()}
    if not exports_by_name:
        print(f"  warn: /list_exports returned nothing — is {client.binary} open?",
              file=sys.stderr)
        return mapping

    resolved = 0
    for entry in mapping.get("exports", []):
        if entry.get("address"):
            continue   # already pinned
        bin_name = entry.get("binary_export") or entry.get("source_symbol")
        if not bin_name:
            continue
        export = exports_by_name.get(bin_name)
        if not export:
            print(f"  warn: export '{bin_name}' not in {client.binary}'s export table",
                  file=sys.stderr)
            continue
        addr = export.get("address") or export.get("addr") or export.get("ea")
        if addr:
            entry["address"] = addr if isinstance(addr, str) else hex(addr)
            resolved += 1
    print(f"  resolved {resolved} export addresses from {client.binary}", file=sys.stderr)
    return mapping


# ---------------------------------------------------------------------------
# Per-entry grading
# ---------------------------------------------------------------------------

def grade_entry(client: GhidraClient, entry: dict, weights: dict) -> dict:
    """Grade a single mapping entry against live Ghidra state."""
    result = {
        "source_symbol": entry.get("source_symbol"),
        "source_file": entry.get("source_file"),
        "address": entry.get("address"),
        "binary_export": entry.get("binary_export"),
        "actual": {},
        "scores": {},
        "total": 0.0,
        "error": None,
    }
    addr = entry.get("address")
    if not addr:
        result["error"] = "no address pinned (run with --resolve-addresses first or pin manually)"
        return result

    expected = entry.get("expected") or {}

    try:
        func_info = client.get_function_by_address(addr)
        plate = client.get_plate_comment(addr)
        variables = client.get_function_variables(addr)
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code} from Ghidra: {e.reason}"
        return result
    except urllib.error.URLError as e:
        result["error"] = f"connection failed: {e.reason}"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    actual_name = (func_info or {}).get("name", "")
    result["actual"] = {
        "name": actual_name,
        "plate_first_line": plate.splitlines()[0] if plate else "",
        "signature": (func_info or {}).get("signature") or (func_info or {}).get("prototype"),
        "variable_count": len(variables),
    }

    s = {
        "name_exact":       score_name_exact(actual_name, entry.get("source_symbol", "")),
        "name_resemblance": score_name_resemblance(actual_name, expected.get("name_tokens") or []),
        "plate_quality":    score_plate_quality(plate, expected.get("plate_keywords") or []),
        "prototype_match":  score_prototype(func_info or {}, expected),
        "variable_typing":  score_variable_typing(variables),
    }
    result["scores"] = s
    result["total"] = round(sum(s[k] * weights.get(k, 0) for k in s), 4)
    return result


# ---------------------------------------------------------------------------
# Run + report
# ---------------------------------------------------------------------------

def do_run(args) -> int:
    mapping_path = Path(args.mapping)
    if not mapping_path.is_file():
        print(f"ERROR: mapping not found at {mapping_path}", file=sys.stderr)
        return 1
    mapping = yaml.safe_load(mapping_path.read_text())
    weights = mapping.get("weights") or {}
    binary = args.binary or mapping.get("binary") or DEFAULT_BINARY
    client = GhidraClient(args.ghidra_url, binary)

    if args.resolve_addresses:
        print(f"resolving export addresses for {binary} ...", file=sys.stderr)
        resolve_export_addresses(client, mapping)
        if args.write_mapping:
            mapping_path.write_text(yaml.safe_dump(mapping, sort_keys=False))
            print(f"  wrote resolved addresses back to {mapping_path}", file=sys.stderr)

    all_entries = (mapping.get("exports") or []) + (mapping.get("string_anchored") or [])
    if not all_entries:
        print("ERROR: mapping has no entries", file=sys.stderr)
        return 1

    results = []
    skipped = 0
    print(f"grading {len(all_entries)} entries against {binary} via {args.ghidra_url} ...",
          file=sys.stderr)
    for entry in all_entries:
        result = grade_entry(client, entry, weights)
        if result.get("error"):
            skipped += 1
        results.append(result)

    graded = [r for r in results if not r.get("error")]
    if graded:
        corpus_score = sum(r["total"] for r in graded) / len(graded)
    else:
        corpus_score = 0.0

    summary = {
        "ts": int(time.time()),
        "binary": binary,
        "ghidra_url": args.ghidra_url,
        "weights": weights,
        "corpus_score": round(corpus_score, 4),
        "graded": len(graded),
        "skipped": skipped,
        "results": results,
    }

    # Output
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2, default=str))
        # Also maintain runs/latest.json as a stable pointer
        latest = RUNS_DIR / "latest.json"
        latest.parent.mkdir(parents=True, exist_ok=True)
        latest.write_text(json.dumps(summary, indent=2, default=str))
        print(f"wrote {out_path} (+ {latest})", file=sys.stderr)

    # Human-readable summary
    print()
    print(f"{'symbol':<32} {'actual_name':<32} {'score':>6} {'note'}")
    print("-" * 96)
    for r in results:
        sym = (r.get("source_symbol") or "")[:32]
        actual = r.get("actual", {}).get("name", "")[:32]
        score = r.get("total") if not r.get("error") else None
        note = r.get("error") or ""
        score_str = f"{score:.2f}" if isinstance(score, (int, float)) else "  -- "
        print(f"{sym:<32} {actual:<32} {score_str:>6} {note}")
    print("-" * 96)
    print(f"corpus score: {corpus_score:.3f}   graded {len(graded)} of {len(all_entries)}",
          f"({skipped} skipped)")
    return 0


def do_compare(args) -> int:
    a = json.loads(Path(args.new).read_text())
    b = json.loads(Path(args.old).read_text())
    print(f"\nCorpus score: {b['corpus_score']:.3f} -> {a['corpus_score']:.3f}  "
          f"({'+' if a['corpus_score'] >= b['corpus_score'] else ''}"
          f"{a['corpus_score'] - b['corpus_score']:+.3f})\n")

    by_sym_a = {r["source_symbol"]: r for r in a.get("results", [])}
    by_sym_b = {r["source_symbol"]: r for r in b.get("results", [])}
    all_syms = sorted(set(by_sym_a) | set(by_sym_b))
    print(f"{'symbol':<32} {'old':>6} {'new':>6} {'delta':>7}")
    print("-" * 60)
    for sym in all_syms:
        ra = by_sym_a.get(sym)
        rb = by_sym_b.get(sym)
        sa = ra["total"] if ra and not ra.get("error") else None
        sb = rb["total"] if rb and not rb.get("error") else None
        sa_str = f"{sa:.2f}" if sa is not None else " -- "
        sb_str = f"{sb:.2f}" if sb is not None else " -- "
        delta = (sa - sb) if (sa is not None and sb is not None) else None
        delta_str = f"{delta:+.2f}" if delta is not None else "  -- "
        print(f"{sym[:32]:<32} {sb_str:>6} {sa_str:>6} {delta_str:>7}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ghidra-url", default=DEFAULT_GHIDRA_URL)
    p.add_argument("--binary", default=None)
    p.add_argument("--mapping", default=str(DEFAULT_MAPPING))
    p.add_argument("--output", default=None,
                   help="path to write the run JSON (and runs/latest.json)")
    p.add_argument("--resolve-addresses", action="store_true",
                   help="fill in null export addresses from /list_exports")
    p.add_argument("--write-mapping", action="store_true",
                   help="persist resolved addresses back to mapping.yaml")
    p.add_argument("--compare", nargs=2, metavar=("NEW", "OLD"), default=None,
                   help="diff two run JSON files (NEW vs OLD)")

    args = p.parse_args(argv)
    if args.compare:
        args.new, args.old = args.compare
        return do_compare(args)
    return do_run(args)


if __name__ == "__main__":
    sys.exit(main())
