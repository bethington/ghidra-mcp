"""
Tests for the /mcp/health endpoint.

Background: /mcp/health was added alongside the thread pool fix so that both
the dashboard and regression tests can observe HTTP server saturation. If the
endpoint disappears or its shape changes silently, callers break.

This test locks in the contract: the endpoint exists, returns JSON, and
contains the fields the dashboard depends on.
"""
import pytest
import requests


REQUIRED_TOP_LEVEL_FIELDS = {
    "status",
    "uptime_seconds",
    "active_requests",
    "http_pool",
    "memory_mb",
}

REQUIRED_POOL_FIELDS = {
    "configured_size",
    "current_size",
    "largest_size",
    "queue_size",
    "completed_tasks",
}

REQUIRED_MEMORY_FIELDS = {"used", "total", "max"}


@pytest.mark.requires_server
def test_health_endpoint_exists_and_returns_json(server_url, server_available):
    """Smoke test: /mcp/health must return 200 with parseable JSON."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    r = requests.get(f"{server_url}/mcp/health", timeout=5)
    assert r.status_code == 200, f"/mcp/health returned {r.status_code}"
    try:
        data = r.json()
    except ValueError as e:
        pytest.fail(f"/mcp/health returned non-JSON: {e}\nBody: {r.text[:500]}")
    assert isinstance(data, dict)


@pytest.mark.requires_server
def test_health_endpoint_has_required_fields(server_url, server_available):
    """Lock in the contract: dashboard + regression tests depend on these fields
    existing. If the shape changes, update this test deliberately."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    data = requests.get(f"{server_url}/mcp/health", timeout=5).json()

    # Top-level
    missing = REQUIRED_TOP_LEVEL_FIELDS - set(data.keys())
    assert not missing, f"/mcp/health missing fields: {missing}"

    # Pool sub-object
    pool = data["http_pool"]
    assert isinstance(pool, dict)
    missing_pool = REQUIRED_POOL_FIELDS - set(pool.keys())
    assert not missing_pool, f"/mcp/health.http_pool missing fields: {missing_pool}"

    # Memory sub-object
    mem = data["memory_mb"]
    assert isinstance(mem, dict)
    missing_mem = REQUIRED_MEMORY_FIELDS - set(mem.keys())
    assert not missing_mem, f"/mcp/health.memory_mb missing fields: {missing_mem}"


@pytest.mark.requires_server
def test_health_reports_expected_thread_pool_size(server_url, server_available):
    """Pool size = 3 is the current setting: small enough to avoid
    saturating Ghidra's EDT (which caused Swing.runNow deadlocks at pool=8),
    but large enough that a slow write doesn't block all read-only endpoints.

    If this changes, update deliberately — both directions are regressions:
    going back to 1 (single-threaded) blocks reads behind writes; going above
    ~3-4 risks EDT saturation and Ghidra internal task deadlocks."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    data = requests.get(f"{server_url}/mcp/health", timeout=5).json()
    pool = data["http_pool"]

    assert pool["configured_size"] == 3, (
        f"HTTP thread pool size changed from 3 to {pool['configured_size']}. "
        f"Too small (1) brings back single-threaded queuing. "
        f"Too large (8+) causes EDT saturation deadlocks. "
        f"Update this test only if the change is intentional."
    )


@pytest.mark.requires_server
def test_health_reports_sane_uptime(server_url, server_available):
    """uptime_seconds should be a non-negative integer."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    data = requests.get(f"{server_url}/mcp/health", timeout=5).json()
    uptime = data["uptime_seconds"]
    assert isinstance(uptime, int)
    assert uptime >= 0


@pytest.mark.requires_server
def test_health_is_itself_a_fast_endpoint(server_url, server_available):
    """/mcp/health must stay fast — it's going to be polled by the dashboard.
    Any slowdown here means the endpoint is doing too much work or the server
    is struggling."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    import time

    # Warm up
    requests.get(f"{server_url}/mcp/health", timeout=5)

    samples = []
    for _ in range(5):
        start = time.perf_counter()
        r = requests.get(f"{server_url}/mcp/health", timeout=5)
        assert r.status_code == 200
        samples.append((time.perf_counter() - start) * 1000)

    median = sorted(samples)[len(samples) // 2]
    assert median < 100, (
        f"/mcp/health median latency {median:.0f} ms exceeds 100 ms. "
        f"Samples: {samples}"
    )
