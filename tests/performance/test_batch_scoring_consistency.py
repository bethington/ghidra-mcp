"""
Regression test for batch_analyze_completeness vs analyze_function_completeness
returning the same data.

Background: batch_analyze_completeness was originally a naive for-loop calling
analyze_function_completeness inside a single invokeAndWait, which caused GUI
lockup. It was rewritten to chunk the work into groups of 5 with Thread.sleep
yields. That rewrite must produce the same scores as calling the single
endpoint individually — otherwise fun-doc's scan would drift from manual
inspection.

This test picks N random functions, hits both paths, and asserts key fields
match.
"""
import pytest
import requests


SAMPLE_SIZE = 10


def _safe_get(d, *keys, default=None):
    """Walk nested dict keys safely."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


@pytest.mark.requires_program
@pytest.mark.slow
def test_batch_and_individual_scoring_agree(server_url, server_available):
    """Batch scores must equal individual scores for the same addresses.

    Fails if:
      - batch endpoint produces different effective_score
      - batch endpoint produces different fixable_deductions
      - batch endpoint silently drops entries
      - batch endpoint and individual endpoint return different classifications
    """
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    try:
        meta = requests.get(f"{server_url}/get_metadata", timeout=5).json()
        program = meta.get("program_name") or meta.get("name")
    except (requests.RequestException, ValueError):
        program = None
    if not program:
        pytest.skip("No program loaded")

    # Pick SAMPLE_SIZE addresses that aren't thunks (thunks get different handling)
    r = requests.get(
        f"{server_url}/list_functions_enhanced",
        params={"program": program, "limit": SAMPLE_SIZE * 3},
        timeout=30,
    )
    assert r.status_code == 200
    funcs = r.json().get("functions") or []
    non_thunks = [f for f in funcs if not f.get("isThunk")]
    if len(non_thunks) < SAMPLE_SIZE:
        pytest.skip(f"Only {len(non_thunks)} non-thunk functions available")
    sample = non_thunks[:SAMPLE_SIZE]
    addresses = [f"0x{f['address']}" for f in sample]

    # Batch path
    batch_resp = requests.post(
        f"{server_url}/batch_analyze_completeness",
        params={"program": program},
        json={"addresses": addresses},
        timeout=120,
    )
    assert batch_resp.status_code == 200
    batch_data = batch_resp.json()
    batch_results = batch_data.get("results") or []
    assert len(batch_results) == len(addresses), (
        f"Batch returned {len(batch_results)} results for {len(addresses)} addresses"
    )

    # Individual path — same addresses, one at a time
    individual_results = []
    for addr in addresses:
        single_resp = requests.get(
            f"{server_url}/analyze_function_completeness",
            params={"program": program, "function_address": addr},
            timeout=60,
        )
        assert single_resp.status_code == 200, f"Individual call failed for {addr}"
        individual_results.append(single_resp.json())

    # Compare key fields for each pair
    mismatches = []
    for i, (batch_r, indiv_r) in enumerate(zip(batch_results, individual_results)):
        addr = addresses[i]
        # Effective score must match
        b_score = _safe_get(batch_r, "effective_score")
        i_score = _safe_get(indiv_r, "effective_score")
        if b_score != i_score:
            mismatches.append(f"{addr} effective_score: batch={b_score}, individual={i_score}")
        # Fixable deductions
        b_fix = _safe_get(batch_r, "fixable_deductions")
        i_fix = _safe_get(indiv_r, "fixable_deductions")
        if b_fix != i_fix:
            mismatches.append(f"{addr} fixable_deductions: batch={b_fix}, individual={i_fix}")
        # Classification
        b_cls = _safe_get(batch_r, "classification")
        i_cls = _safe_get(indiv_r, "classification")
        if b_cls != i_cls:
            mismatches.append(f"{addr} classification: batch={b_cls}, individual={i_cls}")
        # Function name (caller behavior sanity)
        b_name = _safe_get(batch_r, "function_name")
        i_name = _safe_get(indiv_r, "function_name")
        if b_name != i_name:
            mismatches.append(f"{addr} function_name: batch={b_name}, individual={i_name}")

    if mismatches:
        msg = "batch_analyze_completeness does not match individual calls:\n" + "\n".join(
            f"  {m}" for m in mismatches[:10]
        )
        pytest.fail(msg)


@pytest.mark.requires_program
def test_batch_analyze_empty_addresses_rejected(server_url, server_available):
    """Empty address list should be rejected cleanly, not return stale data
    from a previous call or crash the EDT."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    r = requests.post(
        f"{server_url}/batch_analyze_completeness",
        json={"addresses": []},
        timeout=30,
    )
    # Accept either 200 with error field or an HTTP error — both are valid
    # "refuse empty input" responses. Main point: it doesn't crash or hang.
    if r.status_code == 200:
        data = r.json()
        assert "error" in data or (data.get("results") == [] and data.get("count") == 0)
    else:
        assert r.status_code in (400, 422)
