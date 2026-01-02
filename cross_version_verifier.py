#!/usr/bin/env python3
"""
Cross-Version Match Verifier for Ghidra MCP

Verifies function matches by comparing decompiled code and applying names
to confirmed matches.

Usage:
    python cross_version_verifier.py --source "/LoD/1.07/D2Client.dll" --target "/LoD/1.11/D2Client.dll"
"""

import json
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from cross_version_matcher import (
    run_matching, FunctionMatch, MatchResult,
    call_ghidra_json, call_ghidra_text, GHIDRA_MCP_URL
)


@dataclass
class VerificationResult:
    """Result of verifying a function match."""
    match: FunctionMatch
    source_code: str
    target_code: str
    verdict: str  # "APPROVED", "REJECTED", "NEEDS_REVIEW"
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    reason: str
    applied: bool = False


def decompile_function(address: str = None, name: str = None, program: str = None) -> str:
    """Decompile a function by address or name."""
    params = {"program": program} if program else {}
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    else:
        return ""

    result = call_ghidra_json("decompile_function", params)
    if "error" in result:
        return f"[Error: {result['error']}]"
    return result.get("result", "")


def get_function_callees(name: str, program: str) -> List[str]:
    """Get list of functions called by this function."""
    text = call_ghidra_text("get_function_callees", {"name": name, "program": program})
    callees = []
    for line in text.strip().split("\n"):
        if " @ " in line:
            callees.append(line.split(" @ ")[0].strip())
    return callees


def compute_similarity_score(source_code: str, target_code: str,
                             source_callees: List[str], target_callees: List[str]) -> Tuple[float, str]:
    """
    Compute similarity score between two functions.
    Returns (score 0-100, reason string)
    """
    reasons = []
    score = 0

    # Check code length similarity (max 20 points)
    src_lines = len([l for l in source_code.split('\n') if l.strip()])
    tgt_lines = len([l for l in target_code.split('\n') if l.strip()])
    if src_lines > 0 and tgt_lines > 0:
        length_ratio = min(src_lines, tgt_lines) / max(src_lines, tgt_lines)
        length_score = length_ratio * 20
        score += length_score
        if length_ratio > 0.7:
            reasons.append(f"Similar size ({src_lines} vs {tgt_lines} lines)")
        else:
            reasons.append(f"Size mismatch ({src_lines} vs {tgt_lines} lines)")

    # Check callee overlap (max 40 points)
    if source_callees and target_callees:
        # Normalize ordinal names for comparison
        src_callees_norm = set(c for c in source_callees)
        tgt_callees_norm = set(c for c in target_callees)

        # Find common callees (including ordinals)
        common = src_callees_norm & tgt_callees_norm
        total = len(src_callees_norm | tgt_callees_norm)

        if total > 0:
            callee_ratio = len(common) / total
            callee_score = callee_ratio * 40
            score += callee_score
            if common:
                reasons.append(f"Common callees: {', '.join(list(common)[:3])}")

    # Check for common patterns in code (max 40 points)
    pattern_score = 0

    # Registry operations
    if "SetRegistryDword" in source_code and "SetRegistryDword" in target_code:
        pattern_score += 10
        reasons.append("Both use SetRegistryDword")

    # Similar string references
    src_strings = set(s for s in source_code.split('"')[1::2] if len(s) > 3)
    tgt_strings = set(s for s in target_code.split('"')[1::2] if len(s) > 3)
    common_strings = src_strings & tgt_strings
    if common_strings:
        pattern_score += min(len(common_strings) * 5, 15)
        reasons.append(f"Common strings: {', '.join(list(common_strings)[:2])}")

    # Similar control flow
    src_switches = source_code.count("switch(")
    tgt_switches = target_code.count("switch(")
    if src_switches > 0 and tgt_switches > 0:
        pattern_score += 5
        reasons.append("Both have switch statements")

    src_loops = source_code.count("while") + source_code.count("for (")
    tgt_loops = target_code.count("while") + target_code.count("for (")
    if abs(src_loops - tgt_loops) <= 1:
        pattern_score += 5
        reasons.append(f"Similar loop count ({src_loops} vs {tgt_loops})")

    # Return type similarity
    src_return = "void" if source_code.startswith("\nvoid") else "non-void"
    tgt_return = "void" if target_code.startswith("\nvoid") else "non-void"
    if src_return == tgt_return:
        pattern_score += 5
        reasons.append(f"Same return type ({src_return})")

    score += min(pattern_score, 40)

    return score, "; ".join(reasons)


def verify_match(match: FunctionMatch, source_prog: str, target_prog: str) -> VerificationResult:
    """Verify a single function match by comparing decompiled code."""

    # Decompile both functions
    if match.source_addr:
        source_code = decompile_function(address=match.source_addr, program=source_prog)
    else:
        source_code = decompile_function(name=match.source_name, program=source_prog)

    if match.target_addr:
        target_code = decompile_function(address=match.target_addr, program=target_prog)
    else:
        target_code = decompile_function(name=match.target_name, program=target_prog)

    # Get callees for both
    source_callees = get_function_callees(match.source_name, source_prog)
    target_callees = get_function_callees(match.target_name, target_prog)

    # Compute similarity
    score, reason = compute_similarity_score(source_code, target_code, source_callees, target_callees)

    # Determine verdict
    if score >= 60:
        verdict = "APPROVED"
        confidence = "HIGH" if score >= 75 else "MEDIUM"
    elif score >= 40:
        verdict = "NEEDS_REVIEW"
        confidence = "MEDIUM"
    else:
        verdict = "REJECTED"
        confidence = "LOW"

    return VerificationResult(
        match=match,
        source_code=source_code,
        target_code=target_code,
        verdict=verdict,
        confidence=confidence,
        reason=reason
    )


def apply_function_name(target_addr: str, new_name: str, target_prog: str) -> bool:
    """Apply a function name to the target program."""
    result = call_ghidra_json("rename_function_by_address", {
        "function_address": target_addr,
        "new_name": new_name,
        "program": target_prog
    })
    return "error" not in result


def run_verification(source_prog: str, target_prog: str,
                    auto_apply: bool = False,
                    min_confidence: str = "HIGH") -> Dict:
    """
    Run verification on all matches.

    Args:
        source_prog: Source program path
        target_prog: Target program path
        auto_apply: If True, automatically apply approved matches
        min_confidence: Minimum confidence to auto-apply ("HIGH", "MEDIUM", "LOW")

    Returns:
        Dictionary with verification results
    """
    print(f"\n{'='*70}")
    print("CROSS-VERSION MATCH VERIFICATION")
    print(f"{'='*70}")
    print(f"Source: {source_prog}")
    print(f"Target: {target_prog}")
    print(f"Auto-apply: {auto_apply} (min confidence: {min_confidence})")
    print(f"{'='*70}\n")

    # Get matches
    print("Phase 1: Finding matches...")
    match_result = run_matching(source_prog, target_prog)

    # Combine all matches that need sync
    all_matches = []

    # Hash matches that need sync
    for m in match_result.hash_matches:
        if m.source_name != m.target_name and not m.target_name.startswith("FUN_"):
            # Only include if target isn't already a FUN_ (which we want to rename)
            pass
        if m.source_name != m.target_name:
            all_matches.append(m)

    # String and call graph matches (only where target is FUN_)
    for m in match_result.string_matches + match_result.call_graph_matches:
        if m.target_name.startswith("FUN_"):
            all_matches.append(m)

    print(f"\nPhase 2: Verifying {len(all_matches)} matches...\n")

    results = {
        "approved": [],
        "rejected": [],
        "needs_review": [],
        "applied": []
    }

    confidence_levels = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_conf_level = confidence_levels.get(min_confidence, 3)

    for i, match in enumerate(all_matches):
        print(f"[{i+1}/{len(all_matches)}] Verifying: {match.source_name} -> {match.target_name}")

        verification = verify_match(match, source_prog, target_prog)

        # Categorize result
        if verification.verdict == "APPROVED":
            results["approved"].append(verification)
            status = f"✓ {verification.verdict} ({verification.confidence})"

            # Auto-apply if enabled and confidence meets threshold
            if auto_apply:
                conf_level = confidence_levels.get(verification.confidence, 0)
                if conf_level >= min_conf_level and match.target_addr:
                    success = apply_function_name(match.target_addr, match.source_name, target_prog)
                    if success:
                        verification.applied = True
                        results["applied"].append(verification)
                        status += " [APPLIED]"
                    else:
                        status += " [APPLY FAILED]"

        elif verification.verdict == "REJECTED":
            results["rejected"].append(verification)
            status = f"✗ {verification.verdict}"
        else:
            results["needs_review"].append(verification)
            status = f"? {verification.verdict}"

        print(f"    {status}: {verification.reason[:60]}")

    # Summary
    print(f"\n{'='*70}")
    print("VERIFICATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total verified: {len(all_matches)}")
    print(f"  Approved: {len(results['approved'])} ({len(results['applied'])} applied)")
    print(f"  Rejected: {len(results['rejected'])}")
    print(f"  Needs Review: {len(results['needs_review'])}")

    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Cross-version match verifier")
    parser.add_argument("--source", required=True, help="Source program path")
    parser.add_argument("--target", required=True, help="Target program path")
    parser.add_argument("--auto-apply", action="store_true", help="Auto-apply approved matches")
    parser.add_argument("--min-confidence", default="HIGH", choices=["HIGH", "MEDIUM", "LOW"],
                       help="Minimum confidence for auto-apply")
    parser.add_argument("--output", help="Output JSON file for results")
    args = parser.parse_args()

    results = run_verification(
        args.source,
        args.target,
        auto_apply=args.auto_apply,
        min_confidence=args.min_confidence
    )

    if args.output:
        # Convert to serializable format
        output_data = {
            "source": args.source,
            "target": args.target,
            "approved": [
                {
                    "source_name": v.match.source_name,
                    "target_name": v.match.target_name,
                    "target_addr": v.match.target_addr,
                    "confidence": v.confidence,
                    "reason": v.reason,
                    "applied": v.applied
                }
                for v in results["approved"]
            ],
            "rejected": [
                {
                    "source_name": v.match.source_name,
                    "target_name": v.match.target_name,
                    "reason": v.reason
                }
                for v in results["rejected"]
            ],
            "needs_review": [
                {
                    "source_name": v.match.source_name,
                    "target_name": v.match.target_name,
                    "target_addr": v.match.target_addr,
                    "reason": v.reason
                }
                for v in results["needs_review"]
            ]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
