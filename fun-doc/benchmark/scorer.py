"""Score a captured worker output against ground truth.

Rubric (locked in Q5):
  * name, plate-per-local-name: multi-level cascade
        exact   -> 1.0
        prefix  -> 0.7   (truth contained in generated or vice versa)
        embed   -> 0.5   (stub — to be replaced by a small embedder)
        llm     -> variable (Haiku judge — stubbed in walking skeleton)
        miss    -> 0.0
  * signature, local types: structural exact match (return type, param
    count, per-param type); partial credit = fraction of correct params.
  * algorithm: structural — does the plate mention the algorithm tag
    (or any configured synonym)? 1.0 or 0.0.

Each dimension emits a dict with `score` plus enough diagnostic detail
(matched_tier, matched_against, mismatch_details) to make the final
diff output readable.

The walking skeleton's LLM judge is a deterministic stub: it returns
a length-weighted character-overlap similarity. Real Haiku-4.5
integration is TODO once the pipeline end-to-end is committed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional


# Haiku judge configuration. Overridable via env so the benchmark
# can test model-routing changes (e.g. switch judge to Sonnet for a
# run, compare vs Haiku).
HAIKU_JUDGE_MODEL = os.environ.get(
    "FUNDOC_BENCHMARK_JUDGE_MODEL", "claude-haiku-4-5"
)
# Set FUNDOC_BENCHMARK_NO_LLM=1 to force-fallback to the Jaccard stub
# even when ANTHROPIC_API_KEY is set — useful for deterministic
# test runs where you don't want network variability.
_LLM_DISABLED = os.environ.get("FUNDOC_BENCHMARK_NO_LLM") == "1"


# ---------- Multi-level rubric primitives ----------


def _normalize_identifier(s: str) -> str:
    """Strip decoration and lowercase for tier-1 comparison.

    MSVC stdcall adds `_` prefix + `@N` suffix; fun-doc usually writes
    names in PascalCase. Normalize both sides so a worker naming
    `CalcCrc16` matches truth `calc_crc16` at the exact-match tier.
    """
    if not s:
        return ""
    s = s.strip()
    # Strip stdcall decoration: leading _ and trailing @N
    s = re.sub(r"^_", "", s)
    s = re.sub(r"@\d+$", "", s)
    # Snake to lowercase-no-underscore, Pascal to lowercase
    return s.replace("_", "").lower()


def _rubric_score_name(
    generated: Optional[str],
    truth_name: str,
    synonyms: list[str],
) -> dict[str, Any]:
    """Score a single name against a truth + synonym list."""
    if not generated:
        return {"score": 0.0, "tier": "miss", "matched_against": None, "generated": None}

    g_norm = _normalize_identifier(generated)
    candidates = [truth_name] + list(synonyms or [])

    # Tier 1 — exact
    for c in candidates:
        if g_norm == _normalize_identifier(c):
            return {
                "score": 1.0,
                "tier": "exact",
                "matched_against": c,
                "generated": generated,
            }

    # Tier 2 — containment / shared prefix (either direction)
    for c in candidates:
        c_norm = _normalize_identifier(c)
        if not c_norm or not g_norm:
            continue
        if g_norm in c_norm or c_norm in g_norm:
            return {
                "score": 0.7,
                "tier": "prefix",
                "matched_against": c,
                "generated": generated,
            }
        # Shared prefix of at least 5 chars counts as a partial match
        common = 0
        for a, b in zip(g_norm, c_norm):
            if a == b:
                common += 1
            else:
                break
        if common >= 5:
            return {
                "score": 0.7,
                "tier": "prefix",
                "matched_against": c,
                "generated": generated,
            }

    # Tier 3 — embedding cosine (stubbed: fall through)
    # Tier 4 — LLM judge (stubbed): apply a naive overlap heuristic so
    # the score isn't always 0 for clearly-related names. This is the
    # TODO: swap with real Haiku judgment.
    best_char_overlap = 0.0
    best_candidate = candidates[0]
    for c in candidates:
        c_norm = _normalize_identifier(c)
        if not c_norm:
            continue
        overlap = len(set(g_norm) & set(c_norm)) / max(len(set(g_norm) | set(c_norm)), 1)
        if overlap > best_char_overlap:
            best_char_overlap = overlap
            best_candidate = c
    if best_char_overlap >= 0.6:
        # Scale to 0.3–0.5 range: this is the "LLM says maybe equivalent" band
        score = 0.3 + 0.2 * best_char_overlap
        return {
            "score": round(score, 3),
            "tier": "llm_stub",
            "matched_against": best_candidate,
            "generated": generated,
            "note": "stub: char-overlap heuristic; swap in Haiku judge",
        }

    return {"score": 0.0, "tier": "miss", "matched_against": None, "generated": generated}


# ---------- Structural scorers ----------


def _normalize_type(t: str) -> str:
    """Canonicalize a C type string for exact-match comparison.

    Ghidra often writes `unsigned short` as `ushort` and `undefined4`
    as the default-undocumented stand-in. We normalize whitespace and
    strip common aliases so equivalent types compare equal.
    """
    if not t:
        return ""
    t = re.sub(r"\s+", " ", t.strip())
    # Normalize common Ghidra/MSVC type aliases
    aliases = {
        "ushort": "unsigned short",
        "uint": "unsigned int",
        "uchar": "unsigned char",
        "byte": "unsigned char",
        "ulong": "unsigned long",
        "unsigned short int": "unsigned short",
        "unsigned int32": "unsigned int",
        "unsigned int16": "unsigned short",
        "unsigned int8": "unsigned char",
    }
    low = t.lower()
    return aliases.get(low, low)


def _types_equivalent(a: str, b: str) -> bool:
    return _normalize_type(a) == _normalize_type(b)


def _score_signature(captured: dict, truth: dict) -> dict[str, Any]:
    """Structural exactness for return type + parameters."""
    truth_ret = truth.get("return_type", "")
    gen_ret = captured.get("return_type", "")
    return_ok = _types_equivalent(truth_ret, gen_ret)

    truth_params = truth.get("parameters") or []
    gen_params = captured.get("parameters") or []
    count_ok = len(truth_params) == len(gen_params)

    per_param = []
    matched = 0
    for i, tp in enumerate(truth_params):
        gp = gen_params[i] if i < len(gen_params) else None
        if gp is None:
            per_param.append(
                {"index": i, "match": False, "truth": tp, "generated": None, "reason": "missing"}
            )
            continue
        type_ok = _types_equivalent(tp.get("type", ""), gp.get("type", ""))
        per_param.append(
            {
                "index": i,
                "match": type_ok,
                "truth": tp,
                "generated": gp,
                "reason": None if type_ok else "type mismatch",
            }
        )
        if type_ok:
            matched += 1

    # Score: return type is half, param types average is half.
    param_score = matched / max(len(truth_params), 1)
    score = 0.5 * (1.0 if return_ok else 0.0) + 0.5 * param_score
    return {
        "score": round(score, 3),
        "return_type_match": return_ok,
        "param_count_match": count_ok,
        "per_param_match": per_param,
    }


def _score_algorithm(captured: dict, truth: dict) -> dict[str, Any]:
    """Structural: does the plate mention the algorithm tag or a synonym?"""
    tag = truth.get("algorithm_tag")
    synonyms = [tag] + list(truth.get("algorithm_synonyms") or [])
    synonyms = [s for s in synonyms if s]
    plate = captured.get("plate") or ""
    plate_low = plate.lower()

    for s in synonyms:
        if s and s.lower() in plate_low:
            return {
                "score": 1.0,
                "mention_found": True,
                "matched_tag": s,
            }
    return {
        "score": 0.0,
        "mention_found": False,
        "matched_tag": None,
    }


def _jaccard_plate_fallback(canon: str, gen: str) -> dict[str, Any]:
    """Pure-Python fallback used when the LLM judge isn't available.

    Tokenizes both plates, drops stop words, computes Jaccard. Coarse
    but monotonic — higher overlap means higher similarity. Gets us
    reasonable mock/offline scoring without a network round-trip.
    """
    words_a = set(re.findall(r"\w+", canon.lower()))
    words_b = set(re.findall(r"\w+", gen.lower()))
    stop = {
        "the", "a", "an", "is", "are", "of", "and", "or", "to", "for", "with",
        "this", "that", "by", "on", "in", "as", "it", "be", "at", "per",
    }
    words_a -= stop
    words_b -= stop
    if not words_a:
        return {"score": 0.0, "tier": "no_canonical", "note": "canonical plate has no scoreable words"}
    jaccard = len(words_a & words_b) / len(words_a | words_b)
    return {
        "score": round(jaccard, 3),
        "tier": "jaccard",
        "note": "LLM judge unavailable; Jaccard word-overlap fallback",
        "jaccard": round(jaccard, 3),
    }


_HAIKU_JUDGE_SYSTEM = (
    "You are a scoring judge for reverse-engineering documentation quality.\n"
    "You will receive a CANONICAL plate comment (ground truth) and a "
    "GENERATED plate comment (produced by an automated doc tool).\n"
    "Score how semantically equivalent the two comments are on a 0.0 - 1.0 "
    "scale where:\n"
    "  1.0 = same algorithm identified, same semantics described, "
    "same input/output contract communicated\n"
    "  0.7 = mostly right, missing a detail or has minor inaccuracies\n"
    "  0.5 = partially right, gets the gist but misses a material piece\n"
    "  0.3 = wrong algorithm / missing the core point but some overlap\n"
    "  0.0 = wrong or generic (no real semantic match)\n"
    "\n"
    "Respond with ONLY the score as a decimal number between 0.0 and 1.0, "
    "nothing else. No explanation, no punctuation, no units.\n"
)


def _haiku_judge_plate(canon: str, gen: str) -> Optional[float]:
    """Call Haiku 4.5 to score plate-comment equivalence. Returns None on failure.

    The prompt is small (~200 tokens system + ~2x the plate length user
    content) and the response is capped at 16 tokens (just the number).
    Expected cost per call: ~$0.00005 on Haiku 4.5. A full fast-tier
    benchmark run invokes this 5 times; core tier 4 times.

    Catches every exception — a Haiku failure must fall through to
    the Jaccard fallback so a network blip doesn't kill the benchmark.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=HAIKU_JUDGE_MODEL,
            max_tokens=16,
            system=_HAIKU_JUDGE_SYSTEM,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"CANONICAL:\n{canon.strip()}\n\n"
                        f"GENERATED:\n{gen.strip()}\n\n"
                        f"Score (0.0 - 1.0):"
                    ),
                }
            ],
        )
        # Response is the score as a decimal. Extract the first float.
        text = ""
        for block in resp.content:
            if getattr(block, "type", None) == "text":
                text += block.text
        # Allow a leading minus so we can clamp negative values to 0.0
        # rather than silently flipping their sign.
        match = re.search(r"-?\d*\.?\d+", text)
        if not match:
            return None
        score = float(match.group(0))
        # Clamp — models sometimes emit >1.0 or <0 on degenerate inputs.
        return max(0.0, min(1.0, score))
    except Exception:
        # Network failure, rate limit, malformed response — fall back.
        return None


def _score_plate(captured: dict, truth: dict) -> dict[str, Any]:
    """Score plate-comment semantic equivalence.

    Preferred path: Haiku 4.5 as a judge via the Anthropic SDK (Q6
    default). Falls back to Jaccard word-overlap when:
      * ANTHROPIC_API_KEY is not set
      * the anthropic SDK isn't installed
      * FUNDOC_BENCHMARK_NO_LLM=1 (force-offline mode for tests)
      * the Haiku call errors (network, rate limit, malformed response)

    The fallback is coarse but monotonic so offline scoring still
    discriminates good plates from bad. The real Haiku judge is what
    you want for actual regression grading.
    """
    canon = truth.get("canonical_plate") or ""
    gen = captured.get("plate") or ""
    if not canon:
        return {"score": 0.0, "tier": "no_canonical", "note": "truth has no canonical_plate"}
    if not gen:
        return {"score": 0.0, "tier": "miss", "note": "worker produced no plate"}

    if not _LLM_DISABLED:
        haiku_score = _haiku_judge_plate(canon, gen)
        if haiku_score is not None:
            return {
                "score": round(haiku_score, 3),
                "tier": "llm_haiku",
                "model": HAIKU_JUDGE_MODEL,
                "note": "Haiku 4.5 semantic equivalence judgment",
            }

    return _jaccard_plate_fallback(canon, gen)


def _score_locals(captured: dict, truth: dict) -> dict[str, Any]:
    """Match each truth local to a captured local by normalized name.

    For each truth local, find the best-match captured local by name
    rubric; score each pair as (name_score + type_match) / 2. Unmatched
    truth locals score 0.
    """
    truth_locals = truth.get("locals") or []
    gen_locals = list(captured.get("locals") or [])
    if not truth_locals:
        return {"score": 1.0, "per_local_match": [], "note": "no truth locals"}

    used_gen = set()
    per = []
    total = 0.0
    for tl in truth_locals:
        t_name = tl.get("name", "")
        t_type = tl.get("type", "")
        best = None
        best_score = 0.0
        for i, gl in enumerate(gen_locals):
            if i in used_gen:
                continue
            name_score = _rubric_score_name(gl.get("name"), t_name, [])
            type_ok = _types_equivalent(t_type, gl.get("type", ""))
            combined = (name_score["score"] + (1.0 if type_ok else 0.0)) / 2
            if combined > best_score:
                best_score = combined
                best = (i, gl, name_score, type_ok)
        if best is not None and best_score > 0.0:
            used_gen.add(best[0])
            per.append(
                {
                    "truth": tl,
                    "generated": best[1],
                    "name_tier": best[2]["tier"],
                    "type_match": best[3],
                    "score": round(best_score, 3),
                }
            )
            total += best_score
        else:
            per.append(
                {
                    "truth": tl,
                    "generated": None,
                    "name_tier": "miss",
                    "type_match": False,
                    "score": 0.0,
                }
            )
    return {
        "score": round(total / len(truth_locals), 3),
        "per_local_match": per,
    }


# ---------- Top-level ----------


def score_function(captured: dict, truth: dict) -> dict[str, Any]:
    """Score one function's captured output against its ground truth.

    `captured` shape (produced by the benchmark runner from Ghidra state):
        {
          "name": str,                  # worker-chosen function name
          "return_type": str,           # e.g. "unsigned short"
          "parameters": [{name,type}],  # worker-set parameter types
          "locals": [{name,type}],      # worker-set local variable names + types
          "plate": str,                 # full plate comment text
        }

    `truth` shape (from ground_truth.json; the extract_truth.py output):
        {
          "name": str,                  # canonical
          "name_synonyms": [str],
          "return_type": str,
          "parameters": [{name,type}],
          "locals": [{name,type}],
          "canonical_plate": str,
          "algorithm_tag": str,
          "algorithm_synonyms": [str],
          "weights": {name, signature, plate, algorithm, locals},
        }
    """
    truth_name = truth.get("name", "")
    synonyms = list(truth.get("name_synonyms") or [])

    dim_name = _rubric_score_name(captured.get("name"), truth_name, synonyms)
    dim_sig = _score_signature(captured, truth)
    dim_plate = _score_plate(captured, truth)
    dim_alg = _score_algorithm(captured, truth)
    dim_locals = _score_locals(captured, truth)

    # Apply weights. Default weights if yaml didn't override.
    weights = truth.get("weights") or {
        "name": 0.25,
        "signature": 0.25,
        "plate": 0.20,
        "algorithm": 0.15,
        "locals": 0.15,
    }
    total_weight = sum(weights.values()) or 1.0
    quality = (
        weights.get("name", 0.0) * dim_name["score"]
        + weights.get("signature", 0.0) * dim_sig["score"]
        + weights.get("plate", 0.0) * dim_plate["score"]
        + weights.get("algorithm", 0.0) * dim_alg["score"]
        + weights.get("locals", 0.0) * dim_locals["score"]
    ) / total_weight

    return {
        "quality": round(quality, 3),
        "dimensions": {
            "name": dim_name,
            "signature": dim_sig,
            "plate": dim_plate,
            "algorithm": dim_alg,
            "locals": dim_locals,
        },
        "weights": weights,
    }


# ---------- Guardrails over tool-call records ----------


def guardrails(tool_calls: list[dict], quality: float) -> dict[str, Any]:
    """Compute the guardrail metrics from a flat list of tool-call records.

    Each record: {"tool": str, "args": dict, "status": "ok"|"failed", ...}
    """
    total = len(tool_calls)
    if total == 0:
        return {
            "tool_calls_total": 0,
            "tool_calls_per_quality_point": None,
            "duplicate_tool_call_ratio": 0.0,
        }

    # Duplicate detection: same (tool, args) encountered more than once
    seen = set()
    duplicates = 0
    for tc in tool_calls:
        key = (tc.get("tool"), _freeze_args(tc.get("args")))
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)

    # Tool calls per quality point — lower is better. 1.0 qp = max quality.
    per_qp = (total / quality) if quality > 0 else None

    return {
        "tool_calls_total": total,
        "tool_calls_per_quality_point": round(per_qp, 2) if per_qp is not None else None,
        "duplicate_tool_call_ratio": round(duplicates / total, 3),
    }


def _freeze_args(args: Any) -> Any:
    """Make args hashable so duplicate detection works on dicts."""
    if isinstance(args, dict):
        return tuple(sorted((k, _freeze_args(v)) for k, v in args.items()))
    if isinstance(args, list):
        return tuple(_freeze_args(v) for v in args)
    return args
