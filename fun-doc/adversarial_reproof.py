"""adversarial_reproof.py -- Rung V1 of the shipping-promotion ladder
(conformance/SHIPPING_PROMOTION_PLAN.md).

A CONF_LIVE reimpl is bit-exact vs the original across *the vectors the drafting
model chose*, in one game state. Two residual risks make that not shipping-grade:
  #1 self-consistency bias -- the SAME model wrote the reimpl AND its test
     vectors, so it tends to test what it implemented, not what the original does;
  #2 input-coverage gaps -- 12-15 vectors miss exact boundaries / overflows.

V1 closes both by re-proving each CONF_LIVE function against an INDEPENDENT
adversarial vector set that is derived ONLY from the original's decompile (never
the reimpl) and is aimed at breaking it: every branch boundary the decompile
tests, a dense sweep, and extremes (0, +-1, INT_MIN/MAX, powers of two). The
vectors are replayed through the SAME live `/oracle` seam prove_candidate.py uses
(the reimpl is already staged in the running provider). All-match => stamp the
registry row `vetted: adversarial`; any mismatch REOPENS the reimpl (writes a
permanent regression case + a needs_review flag), exactly like a shadow divergence.

Two independence layers, both free of the drafting model:
  - ALGORITHMIC floor (always): a deterministic extremes+sweep+power-of-two set.
    Needs no model and already breaks the self-consistency bias for coverage.
  - MODEL augmentation (default on; --no-model to skip): a separate Claude call,
    shown ONLY the decompile + arg schema, asked for the branch-boundary values
    it can SEE in the code. This is the risk-#1 killer the plan describes.

Scope: oracle input-sweep only works for SCALAR-input functions (i32/buf args
keyed by arg id). `handle`-input functions (the unit getters) take a live game
object, not a vector value -- they can't be adversarially swept via the oracle
and are reported as shadow-only (they earn evidence through V2 shadowing instead).

Standalone. CLI:
    python adversarial_reproof.py --function GetDataTableRowEntryCount
    python adversarial_reproof.py --all            # every CONF_LIVE scalar row
    python adversarial_reproof.py --all --no-model # algorithmic floor only

Model mode needs claude_agent_sdk (fun-doc/.venv). Algorithmic-only mode is
stdlib-only and runs under any python.
"""
from __future__ import annotations

import argparse
import glob
import http.client
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse, urlencode

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROVEN_REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
VECTORS_DIR = D2MOO_REPO / "conformance" / "vectors"
DIVERGENCE_DIR = VECTORS_DIR / "divergences"

ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790")
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
GHIDRA_PROGRAM = os.environ.get("GHIDRA_PROGRAM", "D2Common.dll")
_D2COMMON_BASE = 0x6FD50000

# A hard cap so a wide multi-arg cartesian can't explode the oracle call.
MAX_VECTORS = int(os.environ.get("V1_MAX_VECTORS", "256"))
# Model id for the adversary call. Left unset => claude_agent_sdk default.
V1_MODEL = os.environ.get("V1_MODEL") or None


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
class OracleDied(Exception):
    """The oracle server thread stopped accepting connections mid-run -- almost
    always because a vector crashed it. We abort loudly rather than bisect into
    a corpse, and name the function/vectors that were in flight."""


def _oracle_reachable() -> bool:
    try:
        return _oracle_get("/status", timeout=4).get("ok", False)
    except OSError:
        return False


def _oracle_post(path: str, body: dict, timeout: int = 60) -> dict:
    u = urlparse(ORACLE_URL)
    try:
        conn = http.client.HTTPConnection(u.hostname, u.port or 8790, timeout=timeout)
        conn.request("POST", path, body=json.dumps(body).encode(),
                     headers={"Content-Type": "application/json"})
        raw = conn.getresponse().read().decode("utf-8", "replace")
        conn.close()
    except OSError as e:
        # Connection reset/refused: the server may have died on a prior vector.
        # Confirm with a status probe; if truly gone, this is fatal, not a per-
        # vector fault (bisecting further would just keep failing).
        if not _oracle_reachable():
            raise OracleDied(f"oracle unreachable after {type(e).__name__}: {e}")
        return {"ok": False, "error": f"conn-error(server alive): {e}"}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"non-JSON: {raw[:200]}"}


def _oracle_get(path: str, timeout: int = 10) -> dict:
    u = urlparse(ORACLE_URL)
    conn = http.client.HTTPConnection(u.hostname, u.port or 8790, timeout=timeout)
    try:
        conn.request("GET", path)
        raw = conn.getresponse().read().decode("utf-8", "replace")
    finally:
        conn.close()
    return json.loads(raw)


def _ghidra_decompile(address_hex: str, timeout: int = 60) -> str | None:
    """GET /decompile_function?address=..&program=.. -- pseudocode text or None."""
    u = urlparse(GHIDRA_HTTP)
    qs = urlencode({"address": address_hex, "program": GHIDRA_PROGRAM, "timeout": timeout})
    conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=timeout + 5)
    try:
        conn.request("GET", f"/decompile_function?{qs}")
        raw = conn.getresponse().read().decode("utf-8", "replace")
    except OSError as e:
        return None
    finally:
        conn.close()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return raw if raw and "404" not in raw else None
    if isinstance(obj, dict):
        if obj.get("error"):
            return None
        for k in ("decompiled", "decompilation", "code", "result", "pseudocode"):
            if obj.get(k):
                return obj[k]
    return None


# --------------------------------------------------------------------------- #
# Registry + spec resolution
# --------------------------------------------------------------------------- #
def _load_registry() -> list[dict]:
    if not PROVEN_REGISTRY.exists():
        return []
    return [json.loads(l) for l in PROVEN_REGISTRY.read_text(encoding="utf-8").splitlines() if l.strip()]


def _save_registry(rows: list[dict]) -> None:
    with open(PROVEN_REGISTRY, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _spec_by_name() -> dict[str, Path]:
    """Index every conformance/vectors/*.spec.json by its declared `name`."""
    out: dict[str, Path] = {}
    for p in glob.glob(str(VECTORS_DIR / "*.spec.json")):
        try:
            nm = json.load(open(p, encoding="utf-8")).get("name")
        except (OSError, json.JSONDecodeError):
            continue
        if nm and nm not in out:
            out[nm] = Path(p)
    return out


SCALAR_KINDS = {"i32", "u32", "int", "uint", "buf"}


def _scalar_args(spec: dict) -> list[dict]:
    """Args whose value is supplied by the vector (i32/buf), i.e. sweepable.
    `buf` args are output/inout buffers seeded by an int; still vector-driven."""
    return [a for a in spec.get("args", []) if a.get("kind") in SCALAR_KINDS]


def _handle_args(spec: dict) -> list[dict]:
    return [a for a in spec.get("args", []) if a.get("kind") == "handle"]


# --------------------------------------------------------------------------- #
# Adversarial vector generation -- SAFE BY CONSTRUCTION
#
# Hard lesson (2026-07-07): blindly sweeping extremes CRASHED the oracle server
# thread on DUNGEON_GetTownLevelIdFromActNo -- it dispatches through a jump table
# indexed by `act`, so an out-of-domain value jumps into garbage and executes it,
# a fault SEH cannot catch (unlike a wild READ, which it catches and we quarantine).
# The spec even documented "act 0..4 ONLY -- the original ABORTS for act>4".
#
# Safety principle: the EXISTING PROVEN spec vectors define the known-safe input
# ENVELOPE. We densify adversarially WITHIN that envelope (always safe), and only
# widen PAST it when the model -- reading the decompile -- certifies out-of-domain
# behavior is graceful or an at-worst SEH-recoverable wild read (never abort/jump).
# --------------------------------------------------------------------------- #
INT_MAX = 0x7FFFFFFF
INT_MIN = -0x80000000

# out-of-domain classes the model may assign. Only these two permit widening the
# sweep past the proven envelope; everything else stays strictly inside it.
WIDEN_OK = {"graceful", "wild_read"}


def _vec_value(v: dict, arg_id: str):
    """Read an int arg's value from a spec vector, tolerating the legacy
    mis-keying where some specs stored the value under a stray key (e.g.
    `example_index`) instead of the arg id. Falls back to the sole numeric
    value in the vector."""
    if arg_id in v and isinstance(v[arg_id], (int, float)):
        return int(v[arg_id])
    nums = [x for x in v.values() if isinstance(x, (int, float))]
    return int(nums[0]) if len(nums) == 1 else None


def _spec_envelope(spec: dict, int_args: list[dict]) -> dict[str, tuple[int, int, list[int]]]:
    """Per int-arg: (lo, hi, observed_values) from the spec's PROVEN vectors --
    the domain a prior live oracle proof demonstrated is safe to call."""
    env: dict[str, tuple[int, int, list[int]]] = {}
    for a in int_args:
        i = a["id"]
        obs = [val for val in (_vec_value(v, i) for v in spec.get("vectors", [])) if val is not None]
        if obs:
            env[i] = (min(obs), max(obs), sorted(set(obs)))
        else:
            env[i] = (0, 0, [0])  # no proven inputs -> only 0 is known-safe
    return env


def _densify_in(lo: int, hi: int) -> list[int]:
    """A deterministic break-it spread CLAMPED to [lo, hi]: the endpoints, a
    dense sweep near lo, every value in a small range, and power-of-two / round
    boundaries that fall inside the envelope. Never emits anything outside."""
    if hi < lo:
        lo, hi = hi, lo
    vals = {lo, hi}
    span = hi - lo
    # full dense fill for tiny domains (the town/act case: prove every valid input)
    if span <= 64:
        vals.update(range(lo, hi + 1))
    else:
        vals.update(range(lo, lo + 33))           # dense near the low end
        vals.update(range(hi - 32, hi + 1))        # dense near the high end
        mid = (lo + hi) // 2
        vals.update(range(mid - 8, mid + 9))
    for b in range(0, 31):                          # power-of-two boundaries in range
        for cand in (1 << b, (1 << b) - 1, (1 << b) + 1, -(1 << b)):
            if lo <= cand <= hi:
                vals.add(cand)
    for cand in (0, 1, -1, 255, 256, 32767, -32768, 65535):
        if lo <= cand <= hi:
            vals.add(cand)
    return sorted(vals)


def _extremes_in(lo: int, hi: int) -> list[int]:
    """The wild extremes -- ONLY used when the model certifies the arg is safe to
    widen (graceful/wild_read out-of-domain). Still bounded by any model domain."""
    cands = [INT_MAX, INT_MAX - 1, INT_MIN, INT_MIN + 1, -1, 0,
             65536, -65536, 1 << 24, 1 << 30, -(1 << 30)]
    return [c for c in cands if lo <= c <= hi]


def _adversarial_prompt(name: str, spec: dict, decompile: str,
                        env: dict[str, tuple[int, int, list[int]]]) -> str:
    scal = _scalar_args(spec)
    int_args = [a for a in scal if a.get("kind") != "buf"]
    arg_desc = ", ".join(f'{a["id"]} ({a.get("kind")})' for a in int_args)
    ids = [a["id"] for a in int_args]
    dom = "; ".join(f'{i}: proven-safe so far in [{env[i][0]}, {env[i][1]}]' for i in ids)
    example = json.dumps({"out_of_domain": "graceful|wild_read|abort|dispatch|unknown",
                          "vectors": [{i: 0 for i in ids}]})
    return (
        "You are an ADVERSARIAL test-vector generator for a reverse-engineering "
        "conformance harness. Below is the Ghidra decompilation of an ORIGINAL "
        "Diablo II function. A separate developer wrote a from-scratch C++ "
        "re-implementation; your job is to produce inputs that would EXPOSE any "
        "behavioral difference. You have NOT seen the re-implementation -- reason "
        "ONLY from the decompile.\n\n"
        "SAFETY IS CRITICAL. The vectors are executed against the LIVE game "
        "process. If an out-of-domain argument makes the original ABORT the "
        "process or perform a COMPUTED JUMP indexed by the argument (jump table / "
        "switch / indirect call through an arg-indexed pointer), that input will "
        "CRASH the game and is forbidden. First CLASSIFY what the original does "
        "for arguments OUTSIDE its valid domain:\n"
        "  - \"abort\": calls an abort/exit/assert path (FORBIDDEN to exceed domain)\n"
        "  - \"dispatch\": jump table / switch / arg-indexed call (FORBIDDEN)\n"
        "  - \"wild_read\": at worst reads out-of-bounds memory, then returns "
        "(recoverable -- you MAY probe just past the domain)\n"
        "  - \"graceful\": bounds-checks and early-returns/clamps (SAFE to probe past)\n"
        "  - \"unknown\": can't tell (treated as FORBIDDEN)\n\n"
        f"Function: {name}\n"
        f"Integer arguments (vectors are JSON objects keyed by these ids): {arg_desc}\n"
        f"Currently proven-safe domain: {dom}\n\n"
        "Then produce vectors. Rules:\n"
        "  * If out_of_domain is abort/dispatch/unknown: EVERY vector must stay "
        "within the proven-safe domain above. Densely cover it and hit every "
        "in-domain branch boundary the decompile tests.\n"
        "  * If wild_read/graceful: you MAY additionally emit boundary probes just "
        "past the domain edge (domain_max+1, a few beyond) and extremes, to test "
        "the out-of-domain handling -- but be judicious.\n\n"
        f"Output ONLY strict JSON, this exact shape: {example}\n"
        "20-60 vectors. No prose, no markdown fences.\n\n"
        "----- DECOMPILE -----\n"
        f"{decompile}\n"
        "----- END DECOMPILE -----"
    )


def _extract_json_object(text: str) -> dict | None:
    """Pull the first balanced top-level JSON object out of a model response
    (tolerates prose or ```json fences)."""
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1] if s.count("```") >= 2 else s.strip("`")
        if s.lstrip().startswith("json"):
            s = s.lstrip()[4:]
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _model_analysis(name: str, spec: dict, decompile: str,
                    env: dict[str, tuple[int, int, list[int]]]
                    ) -> tuple[str, dict[str, list[int]]]:
    """Ask the adversary model to (1) classify out-of-domain behavior and (2)
    propose vectors. Returns (out_of_domain_class, per-arg-id extra values).
    ('unknown', {}) on any failure -- caller then stays strictly in-envelope."""
    try:
        import asyncio
        from claude_agent_sdk import query, ClaudeAgentOptions
    except ImportError:
        print("  [model] claude_agent_sdk unavailable -- staying in-envelope")
        return "unknown", {}

    prompt = _adversarial_prompt(name, spec, decompile, env)
    ids = [a["id"] for a in _scalar_args(spec) if a.get("kind") != "buf"]

    async def run() -> str:
        opts = ClaudeAgentOptions(
            model=V1_MODEL, permission_mode="bypassPermissions", max_turns=1,
            system_prompt=("You output only strict JSON. You classify a decompiled "
                           "function's out-of-domain behavior and propose safe "
                           "adversarial input vectors from the decompile alone."),
        )
        parts: list[str] = []
        async for msg in query(prompt=prompt, options=opts):
            if type(msg).__name__ == "AssistantMessage":
                for blk in getattr(msg, "content", None) or []:
                    if type(blk).__name__ == "TextBlock":
                        parts.append(getattr(blk, "text", ""))
        return "".join(parts)

    try:
        raw = asyncio.run(run())
    except Exception as e:  # noqa: BLE001
        print(f"  [model] call failed ({e}) -- staying in-envelope")
        return "unknown", {}

    obj = _extract_json_object(raw)
    if not isinstance(obj, dict):
        print("  [model] no JSON object parsed -- staying in-envelope")
        return "unknown", {}
    ood = str(obj.get("out_of_domain", "unknown")).strip().lower()
    per_id: dict[str, list[int]] = {i: [] for i in ids}
    for v in obj.get("vectors", []) or []:
        if not isinstance(v, dict):
            continue
        for i in ids:
            if i in v:
                try:
                    per_id[i].append(int(v[i]))
                except (TypeError, ValueError):
                    pass
    kept = sum(len(x) for x in per_id.values())
    print(f"  [model] out_of_domain={ood!r}, {len(obj.get('vectors', []))} vectors, {kept} values")
    return ood, per_id


def build_vectors(name: str, spec: dict, decompile: str | None, use_model: bool
                  ) -> tuple[list[dict], str]:
    """Assemble the adversarial vector list (each a dict keyed by arg id), SAFE by
    construction. Returns (vectors, note). buffer args pinned to 0 (outputs/seeds)."""
    scal = _scalar_args(spec)
    buf_ids = [a["id"] for a in scal if a.get("kind") == "buf"]
    int_args = [a for a in scal if a.get("kind") != "buf"]
    base_buf = {i: 0 for i in buf_ids}
    if not int_args:
        return [dict(base_buf)], "buffer-only"

    env = _spec_envelope(spec, int_args)
    ood, model_extra = ("unknown", {})
    if use_model and decompile:
        ood, model_extra = _model_analysis(name, spec, decompile, env)
    widen = ood in WIDEN_OK

    per_id: dict[str, list[int]] = {}
    for a in int_args:
        i = a["id"]
        lo, hi, obs = env[i]
        vals = set(obs) | set(_densify_in(lo, hi))     # always: in-envelope, safe
        if widen:
            # allow the model's out-of-domain probes + bounded extremes (model
            # certified this arg tolerates them). Cap how far past we go.
            wlo, whi = min(lo, INT_MIN + 1), max(hi, INT_MAX - 1)
            vals |= {v for v in model_extra.get(i, []) if wlo <= v <= whi}
            vals |= set(_extremes_in(wlo, whi))
        else:
            # in-envelope model suggestions only (never widen for abort/dispatch)
            vals |= {v for v in model_extra.get(i, []) if lo <= v <= hi}
        per_id[i] = sorted(vals)

    ids = [a["id"] for a in int_args]
    vectors: list[dict] = []
    if len(ids) == 1:
        i = ids[0]
        for val in per_id[i]:
            vectors.append({**base_buf, i: val})
    else:
        longest = max(len(per_id[x]) for x in ids)
        for k in range(longest):
            vectors.append({**base_buf, **{x: per_id[x][k % len(per_id[x])] for x in ids}})
        import itertools
        for combo in itertools.product(*[per_id[x][:8] for x in ids]):
            vectors.append({**base_buf, **dict(zip(ids, combo))})

    seen, norm = set(), []
    for v in vectors:
        nv = {k: (val & 0xFFFFFFFF) for k, val in v.items()}
        key = tuple(sorted(nv.items()))
        if key in seen:
            continue
        seen.add(key)
        norm.append(nv)
        if len(norm) >= MAX_VECTORS:
            break
    note = f"ood={ood}{'/widened' if widen else '/in-envelope'}"
    return norm, note


# --------------------------------------------------------------------------- #
# Resilient oracle run -- isolate vectors that FAULT the original
# --------------------------------------------------------------------------- #
def _is_fault(res: dict) -> bool:
    """The oracle aborts the whole batch when the ORIGINAL faults on some vector
    (a wild read from an out-of-domain arg -- D2MOO keeps the original's bugs).
    Detect that so we can bisect it out rather than fail the function."""
    return (not res.get("ok")) and "exception" in str(res.get("error", "")).lower()


def run_oracle_resilient(spec: dict, vectors: list[dict], *, _depth: int = 0
                         ) -> tuple[list[dict], list[dict]]:
    """Return (comparable_results, original_fault_vectors). A vector that faults
    the ORIGINAL can't be compared (both sides would fault) -- it's quarantined,
    not counted as a divergence. Bisects to isolate faulting vectors so the rest
    still prove. comparable_results[i] aligns with its input via 'vector' key."""
    if not vectors:
        return [], []
    probe = dict(spec)
    probe["vectors"] = vectors
    res = _oracle_post("/oracle", probe)
    if res.get("ok"):
        out = []
        for i, r in enumerate(res.get("results", [])):
            rr = dict(r)
            rr["vector"] = vectors[i]
            out.append(rr)
        return out, []
    if not _is_fault(res) or _depth > 24:
        # A non-fault error (bad spec, unreachable) -- propagate as empty compare
        # with everything marked unproven by raising to the caller via signal.
        raise RuntimeError(res.get("error", "oracle error"))
    if len(vectors) == 1:
        return [], [vectors[0]]
    mid = len(vectors) // 2
    lc, lf = run_oracle_resilient(spec, vectors[:mid], _depth=_depth + 1)
    rc, rf = run_oracle_resilient(spec, vectors[mid:], _depth=_depth + 1)
    return lc + rc, lf + rf


# --------------------------------------------------------------------------- #
# The V1 pass
# --------------------------------------------------------------------------- #
def reprove(name: str, spec_path: Path, *, use_model: bool, row: dict | None) -> dict:
    spec = json.load(open(spec_path, encoding="utf-8"))
    handle = _handle_args(spec)
    scal = _scalar_args(spec)
    int_args = [a for a in scal if a.get("kind") != "buf"]

    if handle and not int_args:
        return {"name": name, "status": "skipped-shadow-only",
                "reason": "handle-input function: no oracle-sweepable arg (earns evidence via V2 shadow)"}
    if not int_args:
        return {"name": name, "status": "skipped-no-scalar",
                "reason": "no i32/buf integer argument to sweep"}

    offset = spec.get("offset")
    if offset is None and spec.get("addr") is not None:
        offset = spec["addr"] - _D2COMMON_BASE
    addr_hex = f"0x{_D2COMMON_BASE + offset:x}" if offset is not None else None

    decompile = _ghidra_decompile(addr_hex) if (use_model and addr_hex) else None
    if use_model and not decompile:
        print(f"  [ghidra] no decompile for {name} @ {addr_hex} -- algorithmic floor only")

    vectors, gen_note = build_vectors(name, spec, decompile, use_model)
    try:
        results, orig_faults = run_oracle_resilient(spec, vectors)
    except RuntimeError as e:
        return {"name": name, "status": "oracle-error", "reason": str(e)}
    # OracleDied propagates to main() -- a crashed server is fatal for the run.

    compared = len(results)
    mism = [r for r in results if not r.get("match")]
    if compared == 0:
        # Every generated vector faulted the original -- can't prove anything.
        return {"name": name, "status": "all-faulted", "vectors": len(vectors),
                "original_faults": len(orig_faults),
                "reason": "every adversarial input faults the original (undecidable via oracle)"}

    if not mism:
        return {"name": name, "status": "vetted", "vectors": compared,
                "original_faults": len(orig_faults), "used_model": bool(decompile)}

    # Divergence: capture a permanent regression case, exactly like a shadow div.
    fails = [{"vector": r.get("vector"), "ret": r.get("ret"), "bufs": r.get("bufs")}
             for r in mism]
    DIVERGENCE_DIR.mkdir(parents=True, exist_ok=True)
    dpath = DIVERGENCE_DIR / f"{name}.adversarial.json"
    dpath.write_text(json.dumps(
        {"name": name, "spec": str(spec_path.name), "mismatches": len(mism),
         "compared": compared, "original_faults": len(orig_faults),
         "failing": fails[:64]}, indent=2), encoding="utf-8")
    return {"name": name, "status": "DIVERGED", "vectors": compared,
            "mismatches": len(mism), "original_faults": len(orig_faults),
            "regression_case": str(dpath), "used_model": bool(decompile)}


def main() -> int:
    ap = argparse.ArgumentParser(description="V1 adversarial re-proof of CONF_LIVE reimpls.")
    ap.add_argument("--function", help="single function name (registry `name`)")
    ap.add_argument("--all", action="store_true", help="every CONF_LIVE row with a scalar arg")
    ap.add_argument("--no-model", dest="model", action="store_false", default=True,
                    help="algorithmic floor only (no adversary model call)")
    ap.add_argument("--dry-run", action="store_true", help="don't write registry markers")
    args = ap.parse_args()

    st = _oracle_get("/status")
    if not st.get("ok"):
        print(f"[fatal] D2Debugger not reachable at {ORACLE_URL}")
        return 2
    print(f"[status] bridge={st['bridge']} dispatchers={st['dispatchers']} "
          f"provider={st['provider']!r}  model={'on' if args.model else 'off'}")

    specs = _spec_by_name()
    rows = _load_registry()
    by_name = {r["name"]: r for r in rows}

    if args.function:
        targets = [args.function]
    elif args.all:
        targets = [r["name"] for r in rows if r.get("conf") == "CONF_LIVE"]
    else:
        print("[fatal] pass --function NAME or --all")
        return 2

    results = []
    for nm in targets:
        if nm not in specs:
            print(f"[skip] {nm}: no conformance/vectors/*.spec.json declares this name")
            results.append({"name": nm, "status": "no-spec"})
            continue
        print(f"[v1] {nm}")
        try:
            out = reprove(nm, specs[nm], use_model=args.model, row=by_name.get(nm))
        except OracleDied as e:
            print(f"  !! ORACLE DIED while proving {nm}: {e}")
            print(f"  !! A generated vector crashed the oracle server thread. "
                  f"The game may still run but :8790 is down -- restart to restore. "
                  f"Suspect function: {nm}")
            if not args.dry_run:
                _save_registry(rows)
            print(f"\n[aborted] oracle died on {nm}; {len(results)} functions completed first")
            return 3
        results.append(out)
        tag = out["status"]
        if tag == "vetted":
            fault_note = (f", {out['original_faults']} inputs quarantined (fault the original)"
                          if out.get("original_faults") else "")
            print(f"  VETTED: {out['vectors']} adversarial vectors compared, 0 divergence"
                  f"{fault_note}"
                  f"{' (model+algo)' if out.get('used_model') else ' (algo-only)'}")
            r = by_name.get(nm)
            if r is not None and not args.dry_run:
                r["vetted"] = "adversarial"
                r["vetted_date"] = time.strftime("%Y-%m-%d")
                r["vetted_vectors"] = out["vectors"]
                r["vetted_model"] = bool(out.get("used_model"))
                if out.get("original_faults"):
                    r["vetted_quarantined"] = out["original_faults"]
                r.pop("needs_review", None)
        elif tag == "DIVERGED":
            print(f"  !! DIVERGED: {out['mismatches']}/{out['vectors']} mismatch -- "
                  f"REOPENS reimpl. regression case: {out['regression_case']}")
            r = by_name.get(nm)
            if r is not None and not args.dry_run:
                r["vetted"] = "adversarial-FAILED"
                r["needs_review"] = True
                r["vetted_date"] = time.strftime("%Y-%m-%d")
        else:
            print(f"  {tag}: {out.get('reason', '')}")

    if not args.dry_run:
        _save_registry(rows)

    vetted = sum(1 for r in results if r["status"] == "vetted")
    diverged = [r["name"] for r in results if r["status"] == "DIVERGED"]
    skipped = sum(1 for r in results if r["status"].startswith("skipped"))
    print(f"\n[summary] {vetted} vetted, {len(diverged)} DIVERGED, {skipped} shadow-only/skipped, "
          f"{len(results)} total")
    if diverged:
        print(f"[summary] REOPENED (adversarial divergence): {', '.join(diverged)}")
    return 1 if diverged else 0


if __name__ == "__main__":
    raise SystemExit(main())
