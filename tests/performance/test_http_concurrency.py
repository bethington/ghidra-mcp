"""
Regression test for the HTTP server threading contract.

Background: GhidraMCPPlugin.java used to call `server.setExecutor(null)`, which
serialized ALL HTTP requests through a single thread. Symptom: any slow request
(save_program, batch_analyze_completeness) blocked every subsequent request —
even cheap read-only ones like /mcp/schema.

Measured during diagnosis:
    /mcp/schema baseline:     15-36 ms (avg 19.6 ms)
    /mcp/schema under load:   54,076 ms on the first call  (551x slowdown)

Fix: Executors.newFixedThreadPool(8) with a ThreadFactory that names threads
GhidraMCP-HTTP-1..8. Post-fix measurement:
    /mcp/schema baseline:     4-20 ms (avg 10 ms)
    /mcp/schema under load:   15-25 ms (avg 17 ms)  — 1.7x overhead, not 551x

This test fails if anyone removes the thread pool or sets it back to null.
It runs an actual slow request in the background and measures read-only
endpoint latency during the slow call. Any regression is observable as the
thread pool becoming saturated or disappearing entirely.
"""
import threading
import time

import pytest
import requests


# Thresholds chosen well above healthy post-fix measurements (17 ms avg) but
# well below pre-fix measurements (10,829 ms avg) so the test is robust to
# machine variance while still catching a regression.
SCHEMA_UNDER_CONTENTION_MAX_MS = 500
SCHEMA_BASELINE_MAX_MS = 200

# Slow-call payload: needs to be expensive enough that Ghidra is busy for at
# least a couple of seconds. 100 addresses is enough at ~0.5s/address.
SLOW_CALL_ADDRESS_COUNT = 100


def _fetch_non_thunk_addresses(server_url, program, n):
    """Grab the first N non-thunk function addresses via list_functions_enhanced."""
    r = requests.get(
        f"{server_url}/list_functions_enhanced",
        params={"program": program, "offset": 0, "limit": n * 2},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    addrs = [f"0x{f['address']}" for f in data.get("functions", []) if not f.get("isThunk")]
    return addrs[:n]


@pytest.mark.slow
@pytest.mark.requires_program
def test_http_thread_pool_keeps_schema_fast_under_contention(server_url, server_available):
    """/mcp/schema must stay responsive while a slow request is in flight.

    This is the exact symptom that setExecutor(null) produced. If this test
    fails after a future refactor, the HTTP server has regressed to
    single-threaded handling.
    """
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    # Pick an arbitrary program the host has available. Fall back to whatever
    # /list_project_files returns if /get_metadata is busy.
    try:
        meta = requests.get(f"{server_url}/get_metadata", timeout=5).json()
        program = meta.get("program_name") or meta.get("name")
    except (requests.RequestException, ValueError):
        program = None

    if not program:
        pytest.skip("No program loaded — cannot exercise batch_analyze_completeness")

    # Phase 1 — baseline
    baseline_ms = []
    for _ in range(3):
        start = time.perf_counter()
        r = requests.get(f"{server_url}/mcp/schema", timeout=10)
        assert r.status_code == 200
        baseline_ms.append((time.perf_counter() - start) * 1000)

    baseline_avg = sum(baseline_ms) / len(baseline_ms)
    assert baseline_avg < SCHEMA_BASELINE_MAX_MS, (
        f"/mcp/schema baseline ({baseline_avg:.0f} ms avg) is suspiciously slow; "
        f"expected <{SCHEMA_BASELINE_MAX_MS} ms. Something is wrong with the server "
        f"before we even start the concurrency test."
    )

    # Phase 2 — prepare slow call
    try:
        addresses = _fetch_non_thunk_addresses(server_url, program, SLOW_CALL_ADDRESS_COUNT)
    except (requests.RequestException, ValueError) as e:
        pytest.skip(f"Could not fetch addresses for slow call: {e}")

    if len(addresses) < 10:
        pytest.skip(f"Only {len(addresses)} non-thunk addresses available")

    # Phase 3 — fire slow call in background, hit schema during it
    slow_done = threading.Event()
    slow_elapsed = [None]
    slow_error = [None]

    def slow_call():
        start = time.perf_counter()
        try:
            resp = requests.post(
                f"{server_url}/batch_analyze_completeness",
                params={"program": program},
                json={"addresses": addresses},
                timeout=300,
            )
            slow_elapsed[0] = time.perf_counter() - start
        except requests.RequestException as e:
            slow_error[0] = str(e)
        finally:
            slow_done.set()

    bg = threading.Thread(target=slow_call, daemon=True)
    bg.start()

    # Let the slow call actually arrive at the server first
    time.sleep(0.3)

    contended_ms = []
    for _ in range(5):
        start = time.perf_counter()
        r = requests.get(f"{server_url}/mcp/schema", timeout=30)
        assert r.status_code == 200, f"/mcp/schema returned {r.status_code} under contention"
        contended_ms.append((time.perf_counter() - start) * 1000)

    # Wait for the slow call to finish so we don't leak the background thread
    slow_done.wait(timeout=310)

    if slow_error[0]:
        pytest.skip(f"Slow call failed before test could validate: {slow_error[0]}")
    if slow_elapsed[0] is None or slow_elapsed[0] < 1.0:
        pytest.skip(
            f"Slow call was not actually slow ({slow_elapsed[0]}s) — "
            f"test conditions not met"
        )

    # Verify schema latency stayed bounded
    contended_avg = sum(contended_ms) / len(contended_ms)
    contended_max = max(contended_ms)

    assert contended_avg < SCHEMA_UNDER_CONTENTION_MAX_MS, (
        f"/mcp/schema avg latency {contended_avg:.0f} ms under contention exceeds "
        f"{SCHEMA_UNDER_CONTENTION_MAX_MS} ms threshold. "
        f"(baseline {baseline_avg:.0f} ms, slow call {slow_elapsed[0]:.1f}s). "
        f"The HTTP server may have regressed to single-threaded handling — "
        f"check GhidraMCPPlugin.java for setExecutor(null)."
    )

    # No single request should queue behind the slow call entirely
    assert contended_max < (slow_elapsed[0] * 1000 * 0.5), (
        f"/mcp/schema max latency {contended_max:.0f} ms approaches the slow call "
        f"duration ({slow_elapsed[0]*1000:.0f} ms). That's the signature of FIFO "
        f"queuing on a single request thread. Check HTTP server threading."
    )


@pytest.mark.requires_server
def test_schema_endpoint_is_cheap(server_url, server_available):
    """Baseline: /mcp/schema should respond in <200 ms.

    This is a smoke test — the endpoint returns a precomputed JSON string and
    should not touch Ghidra's EDT or program state. If it's slow at baseline,
    something is wrong that the concurrency test above won't catch.
    """
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    # Warm up (first request has cold-start overhead)
    requests.get(f"{server_url}/mcp/schema", timeout=5)

    samples_ms = []
    for _ in range(5):
        start = time.perf_counter()
        r = requests.get(f"{server_url}/mcp/schema", timeout=5)
        assert r.status_code == 200
        samples_ms.append((time.perf_counter() - start) * 1000)

    median = sorted(samples_ms)[len(samples_ms) // 2]
    assert median < SCHEMA_BASELINE_MAX_MS, (
        f"/mcp/schema median latency {median:.0f} ms exceeds {SCHEMA_BASELINE_MAX_MS} ms. "
        f"Samples: {[f'{s:.0f}' for s in samples_ms]}"
    )
