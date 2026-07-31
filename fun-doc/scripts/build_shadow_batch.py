"""Stage Class-A shadow-dispatcher candidates directly from the shadow-first
backlog, skipping the CONF_LIVE oracle pre-filter the normal promotion path
requires.

WHY
---
D2COMMON_FULL_SHADOW_PLAN.md's documented promotion gate requires a function
be CONF_LIVE (oracle-proven bit-exact) before shadow_promote.py will stage
it. But conformance/profiler/shadow_leaf_backlog.jsonl exists precisely
because ~3,000+ functions were judged UNSAFE to prove via the oracle's
synthetic round-robin object capture (a wrong-typed/degenerate captured
object can fault the oracle uncatchably -- see fun_doc.py's
_note_shadow_backlog call sites). That leaves them stuck: too risky for the
oracle, and the oracle is the only documented on-ramp to a shadow dispatcher.

The way out: a real shadow dispatcher hooks the function's REAL call site
and hands it the REAL object the game itself supplies -- never a synthetic
capture. The exact hazard that blocks the oracle for these functions does
not apply there (see fun_doc.py: "in the live game it receives REAL objects
... judged on divergence counters rather than on synthesized state"). So
this script builds the missing on-ramp for the classes that are genuinely
safe to skip straight to a manifest entry.

SCOPE (deliberately conservative -- see D2COMMON_FULL_SHADOW_PLAN.md
"Dispatcher classes" section)
--------------------------------------------------------------------
Class A (read-only getter: "leaf"/"global_leaf"/"shadow_leaf" per
port_pipeline.classify_function) ONLY, for this first cut. Re-classifies
every backlog candidate FRESH against the CURRENT classifier -- never trusts
the backlog's possibly-stale reason label.

Deliberately NOT staged (see notes inline for why each is out of scope):
  * Any module other than D2Common.dll / D2Client.dll. gen_shadow_dispatch.py
    only has base-address + manifest config for these two
    (conformance/tools/gen_shadow_dispatch.py MODULES) -- every other binary
    in the backlog (D2Game, Fog, Storm, BH, ...) has no generator wired up
    yet. Staging entries there would sit in a manifest nothing ever reads.
  * Anything that (re-)classifies as "stateful", "mutator_leaf", or
    "unknown". The backlog's dominant reason (~1,187 of the D2Common/D2Client
    subset) is "void_delegate_mutator" -- a delegate-calling mutator. That
    does NOT meet fun_doc.py's own existing Class-B-eligibility bar
    (_class_b_outbuf_eligible requires stateful_reason == "ptr_write", no
    delegate) and classify_function's own mutator_leaf docstring says so
    explicitly (2026-07-30): "the delegate-calling majority needs a
    call-through reimpl, which is the next capability, not this one." This
    script does not attempt Class B/C dispatch at all yet -- those stay in
    the backlog for a follow-up once Class A staging is validated end to end.
  * Anything already present in the target manifest by name.
  * A fresh "leaf" classification (no globals, no live pointer at all) --
    that's a plain static-provable function; it belongs in the NORMAL port
    worker queue (which reaches CONF_LIVE the ordinary way), not here.

WHAT IT DOES
------------
1. Reads shadow_leaf_backlog.jsonl, dedupes by (program, name) keeping the
   last-seen row.
2. Filters to D2Common.dll / D2Client.dll, skips names already present in
   the applicable manifest.
3. Fetches decompile + disassembly from Ghidra, re-classifies via
   port_pipeline.classify_function. Only "global_leaf" / "shadow_leaf"
   survive.
4. Drafts an extern-C reimpl with the SAME prompts/parsers the live-prove
   path already uses (build_live_draft_prompt/build_handle_draft_prompt +
   parse_live_response/parse_handle_response) -- ONE bounded LLM call, no
   fix-retry loop (this stages a best-effort candidate, it does not prove
   one).
5. Ground-truths callconv from abi_static.derive_abi (never the model's
   guess). Skips anything not stdcall/fastcall (thiscall/register-explicit/
   unknown aren't in the existing Class A/B/D thunk repertoire).
6. Writes the reimpl via port_live_prove.write_candidate (the existing
   build-poison guard -- catches a bad draft here, same as every other
   lane) and appends a manifest entry tagged "source": "shadow_first" so a
   human (and battletest_promoter.py, if it chooses to) can tell this
   entry skipped the oracle pre-filter and apply a stricter real-play bar.
7. NEVER regenerates the .gen.h header, never rebuilds, never restarts the
   game. gen_shadow_dispatch.py's own validate_ret_bits/validate_argc catch
   a wrong ABI guess (queried live against Ghidra) before anything reaches
   the generated header -- run that manually after staging a batch, exactly
   like any other manifest edit.

USAGE
-----
    uv run --group fun-doc python fun-doc/scripts/build_shadow_batch.py                    # dry run
    uv run --group fun-doc python fun-doc/scripts/build_shadow_batch.py --apply --limit 10
    uv run --group fun-doc python fun-doc/scripts/build_shadow_batch.py --module D2Client --apply --limit 10

Requires the fun-doc dependency group (fun_doc.py imports SQLAlchemy at
module load). Run with a live Ghidra on :8089 with the target program(s)
open. Does NOT require the D2Debugger oracle or the game running --
that's the entire point.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
BACKLOG_PATH = D2MOO_REPO / "conformance" / "profiler" / "shadow_leaf_backlog.jsonl"

# Mirrors conformance/tools/gen_shadow_dispatch.py's MODULES exactly -- the
# only two binaries with a shadow-dispatch generator + manifest wired up.
MODULE_CONFIG = {
    "D2Common.dll": {
        "base": 0x6FD50000,
        "manifest": D2MOO_REPO / "conformance" / "shadow_manifest.json",
    },
    "D2Client.dll": {
        "base": 0x6FAB0000,
        "manifest": D2MOO_REPO / "conformance" / "shadow_manifest.D2Client.json",
    },
}

_CALLCONV_OK = {"stdcall", "fastcall"}


def _load_backlog():
    """{(program_basename, name): reason} -- last-seen row wins, matches the
    append-only log's own semantics (a later entry supersedes an earlier
    classification for the same function)."""
    out = {}
    if not BACKLOG_PATH.exists():
        print(f"[build_shadow_batch] backlog not found: {BACKLOG_PATH}")
        return out
    with open(BACKLOG_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            prog = (d.get("program") or "").split("/")[-1].split("\\")[-1]
            name = d.get("name")
            address = d.get("address")
            if not prog or not name or not address:
                continue
            out[(prog, name)] = {
                "program": d.get("program"), "address": address,
                "reason": d.get("reason"),
            }
    return out


def _load_manifest(path: Path):
    if not path.exists():
        return {"_comment": "shadow-first candidates staged by build_shadow_batch.py "
                             "and the normal CONF_LIVE->shadow_promote.py path.",
                "entries": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _staged_names(manifest: dict) -> set:
    return {e.get("name") for e in manifest.get("entries", []) if e.get("name")}


def _ret_bits_from_layout(ret_hint) -> int:
    r = (ret_hint or "").lower()
    if r in ("u8", "i8", "byte"):
        return 8
    if r in ("u16", "i16", "short"):
        return 16
    if r in ("void",):
        return 0
    return 32


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                     help="Actually draft + write candidates/manifest entries. "
                          "Default is dry-run (classify + report only).")
    ap.add_argument("--limit", type=int, default=10,
                     help="Max candidates to ATTEMPT (decompile+classify+draft) "
                          "this run. Default 10 -- deliberately small for a first "
                          "batch; raise once spot-checked.")
    ap.add_argument("--module", choices=["D2Common", "D2Client", "both"], default="both",
                     help="Restrict to one module's backlog subset.")
    ap.add_argument("--provider", default="minimax",
                     help="LLM provider for the one-shot draft (default: minimax, "
                          "matching the currently-configured Prove fleet).")
    args = ap.parse_args()

    modules = (["D2Common.dll", "D2Client.dll"] if args.module == "both"
               else [f"{args.module}.dll"])

    import fun_doc as fd
    import port_pipeline as pp
    import port_live_prove as plp
    import abi_static

    backlog = _load_backlog()
    print(f"[build_shadow_batch] {len(backlog)} unique (program,name) backlog rows total")

    manifests = {m: _load_manifest(MODULE_CONFIG[m]["manifest"]) for m in modules}
    staged = {m: _staged_names(manifests[m]) for m in modules}

    candidates = [
        (prog, name, row) for (prog, name), row in backlog.items()
        if prog in modules and name not in staged[prog]
    ]
    print(f"[build_shadow_batch] {len(candidates)} candidates in {modules}, "
          f"not already staged; attempting up to {args.limit}")

    attempted = 0
    skip_reasons = {}
    staged_count = {m: 0 for m in modules}

    def _skip(name, reason):
        skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
        print(f"  SKIP  {name:40s} {reason}")

    for prog, name, row in candidates:
        if attempted >= args.limit:
            break
        attempted += 1
        address = row["address"]
        program = row["program"]

        dec_resp = fd.ghidra_get("/decompile_function",
                                  params={"address": f"0x{address}", "program": program})
        if not dec_resp or fd._is_error_response(dec_resp):
            _skip(name, "decompile_fetch_failed")
            continue
        decompiled = fd.decompiled_text(dec_resp)

        dis_resp = fd.ghidra_get("/disassemble_function",
                                  params={"address": f"0x{address}", "program": program})
        if not dis_resp or fd._is_error_response(dis_resp):
            _skip(name, "disassemble_fetch_failed")
            continue
        disasm = fd.disasm_text(dis_resp)

        classification = pp.classify_function(decompiled)
        if classification not in ("global_leaf", "shadow_leaf"):
            _skip(name, f"not_class_a:{classification} (backlog reason was "
                        f"{row['reason']})")
            continue

        abi = abi_static.derive_abi(disasm)
        callconv = abi.get("callconv")
        if callconv not in _CALLCONV_OK:
            _skip(name, f"unsupported_callconv:{callconv}")
            continue

        model = None
        try:
            model = fd.get_configured_model(args.provider, "FULL")
        except Exception:
            pass

        manifest_args = None
        ret_bits = 32
        reimpl = layout = None

        if classification == "global_leaf":
            prompt = plp.build_live_draft_prompt(name, address, decompiled, program=program)
            if args.apply:
                text, meta = fd.invoke_claude(prompt, model=model, max_turns=15,
                                              provider=args.provider,
                                              complexity_tier="complex", use_tools=False)
                if (meta or {}).get("stopped"):
                    print("  stop requested -- halting batch")
                    break
                if (meta or {}).get("quota_paused") or (meta or {}).get("timed_out"):
                    _skip(name, "provider_hiccup")
                    continue
                reimpl, layout, _inputs = plp.parse_live_response(text or "")
                if not reimpl and (meta or {}).get("reasoning_text"):
                    reimpl, layout, _inputs = plp.parse_live_response(
                        meta["reasoning_text"] + (text or ""))
                if not reimpl:
                    _skip(name, "draft_did_not_parse")
                    continue
                if fd._unknown_resolve_names(reimpl):
                    _skip(name, "draft_used_unresolvable_global")
                    continue
                manifest_args = ["i32"] * len(layout.get("inputs") or [])
            else:
                print(f"  WOULD DRAFT (global_leaf) {name} @ 0x{address} "
                      f"[{callconv}] -- backlog reason was {row['reason']}")
        else:  # shadow_leaf -- live-pointer read-only getter
            prompt = plp.build_handle_draft_prompt(name, address, decompiled, program=program)
            if args.apply:
                text, meta = fd.invoke_claude(prompt, model=model, max_turns=15,
                                              provider=args.provider,
                                              complexity_tier="complex", use_tools=False)
                if (meta or {}).get("stopped"):
                    print("  stop requested -- halting batch")
                    break
                if (meta or {}).get("quota_paused") or (meta or {}).get("timed_out"):
                    _skip(name, "provider_hiccup")
                    continue
                reimpl, layout, _inputs = plp.parse_handle_response(text or "")
                if not reimpl and (meta or {}).get("reasoning_text"):
                    reimpl, layout, _inputs = plp.parse_handle_response(
                        meta["reasoning_text"] + (text or ""))
                if not reimpl:
                    _skip(name, "draft_did_not_parse")
                    continue
                declared_callconv = (layout.get("callconv") or callconv)
                if declared_callconv not in _CALLCONV_OK:
                    _skip(name, f"unsupported_callconv:{declared_callconv}")
                    continue
                ret_bits = _ret_bits_from_layout(layout.get("ret"))
                manifest_args = ["ptr"] + ["i32" for _ in (layout.get("scalar_args") or [])]
            else:
                print(f"  WOULD DRAFT (shadow_leaf) {name} @ 0x{address} "
                      f"[{callconv}] -- backlog reason was {row['reason']}")

        if not args.apply:
            continue

        # Last line of defense (same guard write_candidate applies) before we
        # bother building a manifest entry for a draft that can't be a
        # provider candidate at all.
        if not plp._is_provider_reimpl(reimpl):
            _skip(name, "draft_not_provider_shaped")
            continue

        offset = f"0x{int(address, 16) - MODULE_CONFIG[prog]['base']:x}"
        entry = {
            "name": name,
            "offset": offset,
            "callconv": callconv,
            "args": manifest_args,
            "ret_bits": ret_bits,
            "class": "A",
            "source": "shadow_first",
            "note": (f"shadow-first: skipped CONF_LIVE (backlog reason: "
                     f"{row['reason']}); classified {classification}"),
        }

        try:
            plp.write_candidate(reimpl, name)
        except ValueError as e:
            _skip(name, f"write_candidate_rejected:{e}")
            continue

        manifests[prog]["entries"].append(entry)
        staged[prog].add(name)
        staged_count[prog] += 1
        print(f"  STAGED {name:40s} {prog} offset={offset} class=A [{callconv}]")

    if args.apply:
        for m in modules:
            if staged_count[m]:
                path = MODULE_CONFIG[m]["manifest"]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(manifests[m], f, indent=2)
                    f.write("\n")
                print(f"[build_shadow_batch] wrote {staged_count[m]} new entries -> {path}")

    print()
    print(f"[build_shadow_batch] attempted={attempted} staged={sum(staged_count.values())} "
          f"({', '.join(f'{m}={n}' for m, n in staged_count.items())})")
    print("[build_shadow_batch] skip reasons:")
    for reason, n in sorted(skip_reasons.items(), key=lambda kv: -kv[1]):
        print(f"    {n:5d}  {reason}")
    if not args.apply:
        print("\n[build_shadow_batch] DRY RUN -- no files written. Re-run with --apply "
              "to draft + stage.")
    else:
        print("\n[build_shadow_batch] Staged only -- .gen.h NOT regenerated, nothing "
              "rebuilt, game NOT restarted. Run gen_shadow_dispatch.py manually next "
              "(it will validate ret_bits/argc against live Ghidra before emitting).")


if __name__ == "__main__":
    main()
