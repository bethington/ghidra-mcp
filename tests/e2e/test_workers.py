"""Worker start / stop, driven through the UI the operator actually uses.

The read-only half checks that the pane the page renders describes the
worker the server reports — a pane that says "running" for a worker the
manager has forgotten is how four deadlocked workers went unnoticed for
half an hour.

The destructive half starts a REAL worker via the Start button and stops
it via the pane's stop button. It requires a paused fleet (see
`require_paused_fleet`): a worker started against a paused fleet parks at
the top of its lane loop, before it selects a function and before any
provider call, so the whole lifecycle is exercised for zero tokens and
zero documentation changes.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from conftest import wait_for

pytestmark = pytest.mark.e2e

LIVE_STATES = {"starting", "running", "stopping", "paused", "quota_paused"}


def _panes(page) -> dict[str, str]:
    """Rendered worker panes: {worker_id: pane class}."""
    return page.evaluate(
        """() => Object.fromEntries(
             Array.from(document.querySelectorAll('.worker-pane'))
                  .map(p => [p.id.replace(/^wp-/, ''), p.className]))"""
    )


# ---------------------------------------------------------------------------
# read-only: does the roster on screen match the roster in the manager?
# ---------------------------------------------------------------------------


def test_pane_set_matches_worker_roster(dashboard, api):
    page, _ = dashboard
    page.wait_for_timeout(3000)  # first worker_status push
    workers = api.get("/api/worker/status")["workers"]
    rendered = set(_panes(page))
    expected = {w["id"] for w in workers}
    assert rendered == expected, (
        f"panes on screen {sorted(rendered)} vs manager roster {sorted(expected)}"
    )


def test_worker_hint_counts_running_and_total(dashboard, api):
    page, _ = dashboard
    page.wait_for_timeout(3000)
    workers = api.get("/api/worker/status")["workers"]
    hint = page.locator("#workerHint").inner_text().strip()
    if not workers:
        assert hint == "0 workers", hint
        expect(page.locator(".worker-empty")).to_be_visible()
        return
    running = sum(1 for w in workers if w.get("status") in ("starting", "running", "stopping"))
    parked = sum(1 for w in workers if w.get("status") in ("paused", "quota_paused"))
    expected = (
        f"{running} running / {parked} paused / {len(workers)} total"
        if parked
        else f"{running} running / {len(workers)} total"
    )
    assert hint == expected, f"hint {hint!r} vs {expected!r}"


def test_pane_titles_carry_binary_mode_and_provider(dashboard, api):
    """Six panes across three binaries and three lanes look identical
    without these three facts; picking the wrong one to stop is a real
    and expensive mistake."""
    page, _ = dashboard
    page.wait_for_timeout(3000)
    workers = api.get("/api/worker/status")["workers"]
    if not workers:
        pytest.skip("no workers running")
    labels = {"functions": "Doc", "port": "Prove", "globals": "Globals"}
    for w in workers:
        # the mode chip is CSS-uppercased, so inner_text() yields "PROVE"
        title = page.locator(f"#wp-title-{w['id']}").inner_text().lower()
        if w.get("binary"):
            assert w["binary"].replace("\\", "/").split("/")[-1].lower() in title
        assert labels.get(w.get("mode"), w.get("mode", "")).lower() in title
        assert (w.get("provider") or "worker").lower() in title
        assert f"#{w['id']}".lower() in title


def test_pane_class_reflects_worker_status(dashboard, api):
    page, _ = dashboard
    page.wait_for_timeout(3000)
    workers = {w["id"]: w for w in api.get("/api/worker/status")["workers"]}
    if not workers:
        pytest.skip("no workers running")
    for wid, cls in _panes(page).items():
        status = workers[wid].get("status")
        if status in ("finished", "stopped"):
            assert "finished" in cls
        elif status == "stopping":
            assert "stopping" in cls
        elif status == "quota_paused":
            assert "quota_paused" in cls
        elif status == "paused":
            assert "paused" in cls.split(), f"worker {wid} is paused but pane class is {cls!r}"
        else:
            assert "running" in cls, f"worker {wid} is {status} but pane class is {cls!r}"


def test_pane_progress_line_matches_worker_progress(dashboard, api):
    page, _ = dashboard
    page.wait_for_timeout(3000)
    workers = api.get("/api/worker/status")["workers"]
    live = [w for w in workers if w.get("status") not in ("finished", "stopped")]
    if not live:
        pytest.skip("no live workers")
    for w in live:
        text = page.locator(f"#wp-status-{w['id']}").inner_text()
        pr = w.get("progress") or {}
        assert f"{pr.get('completed', 0)}ok" in text
        assert f"{pr.get('failed', 0)}fail" in text
        # a parked worker's line is prefixed PARKED/QUOTA so it cannot be read
        # as work in flight; strip that before checking the counter itself
        text = re.sub(r"^(PARKED|QUOTA)\s+", "", text)
        if w.get("continuous"):
            assert text.startswith("auto")
        else:
            done = (pr.get("completed", 0)) + (pr.get("skipped", 0)) + (pr.get("failed", 0))
            assert f"{done}/{w.get('count')}" in text


def test_paused_workers_are_not_drawn_as_running(dashboard, api):
    """`paused` had no branch in the pane class map, so it fell through to
    `running`: three parked workers drew the green running border while
    the hint above them read "0 running / 3 total"."""
    page, _ = dashboard
    page.wait_for_timeout(3000)
    paused = [w for w in api.get("/api/worker/status")["workers"] if w.get("status") == "paused"]
    if not paused:
        pytest.skip("no paused workers")
    for w in paused:
        cls = page.locator(f"#wp-{w['id']}").get_attribute("class") or ""
        assert "paused" in cls.split(), (
            f"worker {w['id']} is paused but its pane class is {cls!r}"
        )
        assert "running" not in cls.split()


def test_paused_worker_status_line_says_so(dashboard, api):
    """A parked worker keeps `progress.current` from the function it
    finished last, which reads exactly like work in flight."""
    page, _ = dashboard
    page.wait_for_timeout(3000)
    paused = [w for w in api.get("/api/worker/status")["workers"] if w.get("status") == "paused"]
    if not paused:
        pytest.skip("no paused workers")
    for w in paused:
        text = page.locator(f"#wp-status-{w['id']}").inner_text().upper()
        assert "PARKED" in text, (
            f"worker {w['id']} is parked but its status line reads {text!r}"
        )


def test_hint_counts_paused_workers(dashboard, api):
    page, _ = dashboard
    page.wait_for_timeout(3000)
    workers = api.get("/api/worker/status")["workers"]
    parked = sum(1 for w in workers if w.get("status") in ("paused", "quota_paused"))
    if not parked:
        pytest.skip("no parked workers")
    hint = page.locator("#workerHint").inner_text()
    assert f"{parked} paused" in hint, f"{parked} parked workers but the hint reads {hint!r}"


def test_fleet_pause_bar_is_shown_when_paused(dashboard, api):
    """`/api/health/all` has always carried `paused` + `pause_reason` at
    the top level; nothing on the page read either, so a paused fleet was
    invisible behind five green dots."""
    page, _ = dashboard
    page.wait_for_timeout(3000)
    health = api.get("/api/health/all")
    bar = page.locator("#pauseBar")
    if not health.get("paused"):
        assert "active" not in (bar.get_attribute("class") or "").split()
        return
    assert "active" in (bar.get_attribute("class") or "").split(), (
        "fleet is paused but the pause bar is not shown"
    )
    msg = page.locator("#pauseBarMsg").inner_text()
    assert "paused" in msg.lower()
    if health.get("pause_reason"):
        assert health["pause_reason"] in msg, (
            f"pause bar does not carry the reason: {msg!r}"
        )


def test_stale_worker_is_not_shown_as_healthy(dashboard, api):
    """A worker the manager has flagged stale must not render as a plain
    running pane — a frozen non-terminal status also burns a MAX_WORKERS
    slot, so it has to be visible."""
    page, _ = dashboard
    page.wait_for_timeout(3000)
    stale = [w for w in api.get("/api/worker/status")["workers"] if w.get("is_stale")]
    if not stale:
        pytest.skip("no stale workers")
    for w in stale:
        pane = page.locator(f"#wp-{w['id']}")
        text = pane.inner_text().lower()
        cls = pane.get_attribute("class") or ""
        assert "stale" in text or "stale" in cls or "timeout" in cls, (
            f"worker {w['id']} is stale but its pane looks healthy"
        )


# ---------------------------------------------------------------------------
# destructive: start and stop a real worker through the UI
# ---------------------------------------------------------------------------


@pytest.mark.destructive
def test_start_and_stop_a_worker_through_the_ui(
    dashboard, api, require_paused_fleet, worker_guard, active_program
):
    page, _ = dashboard
    before = worker_guard

    page.locator("#lane").select_option("document")
    page.locator("#provider").select_option("minimax")
    if page.locator("#allFns").is_checked():
        page.locator("#allFns").uncheck()
    page.locator("#count").fill("1")
    page.locator("header button.go[onclick='startLane()']").click()

    # 1. the manager registered a new worker
    new = wait_for(
        lambda: next(
            (
                w
                for w in api.get("/api/worker/status")["workers"]
                if w["id"] not in before and w.get("status") in LIVE_STATES
            ),
            None,
        ),
        timeout=60,
        what="a newly started worker in the roster",
    )
    assert new["mode"] == "functions"
    assert new["provider"] == "minimax"
    assert new["count"] == 1

    # 2. the page grew a pane for it, with a working stop button
    wid = new["id"]
    expect(page.locator(f"#wp-{wid}")).to_be_visible(timeout=30_000)
    expect(page.locator(f"#wp-stop-{wid}")).to_be_visible()
    expect(page.locator(f"#wp-title-{wid}")).to_contain_text("Doc")
    expect(page.locator(f"#wp-title-{wid}")).to_contain_text("minimax")

    # 3. On a PAUSED fleet the worker must park before it selects a function —
    #    that is the property that makes this test free to run. Under
    #    --allow-unpaused there is nothing to park against and the worker
    #    correctly goes to work instead, so only assert this when it applies.
    if require_paused_fleet.get("paused"):
        parked = wait_for(
            lambda: next(
                (w for w in api.get("/api/worker/status")["workers"] if w["id"] == wid),
                {},
            ).get("status")
            == "paused",
            timeout=90,
            what="the new worker to park on the paused fleet",
        )
        assert parked

    # 4. the stop button actually stops it
    page.locator(f"#wp-stop-{wid}").click()
    wait_for(
        lambda: next(
            (w for w in api.get("/api/worker/status")["workers"] if w["id"] == wid),
            {"status": "gone"},
        ).get("status")
        in ("stopped", "finished", "gone"),
        timeout=120,
        what="the worker to reach a terminal status after Stop",
    )

    # 5. and the pane reflects that, with the stop button retired
    page.wait_for_function(
        "(id) => { const p = document.getElementById('wp-' + id);"
        " return !p || p.className.includes('finished'); }",
        arg=wid,
        timeout=60_000,
    )


@pytest.mark.destructive
def test_globals_lane_without_a_binary_is_refused(api, require_paused_fleet, worker_guard):
    """`start_worker` refuses a globals worker with no binary rather than
    launching one that can never pick a target. The HTTP twin must return
    that as a 409 with the reason, not a 500."""
    r = api.post("/api/worker/start", {"mode": "globals", "provider": "minimax", "binary": None})
    assert r.status_code == 409, f"expected a controlled rejection, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("ok") is False
    assert "binary" in (body.get("error") or "").lower()


@pytest.mark.destructive
def test_disabled_provider_is_refused(api, require_paused_fleet, worker_guard):
    """Routing a worker at a provider the operator disabled (gemini has
    been dead since Google retired the individual tier) must fail at the
    launch, not on every function."""
    cfg = api.get("/api/queue/config")
    disabled = (cfg.get("config") or cfg).get("disabled_providers") or []
    if not disabled:
        pytest.skip("no disabled providers configured")
    r = api.post(
        "/api/worker/start",
        {"mode": "functions", "provider": disabled[0], "count": 1},
    )
    assert r.status_code == 409, f"expected 409, got {r.status_code}: {r.text}"
    assert "disabled" in (r.json().get("error") or "").lower()


def test_stop_of_an_unknown_worker_is_a_404_not_a_500(api):
    """Stopping an already-finished worker is a client mistake, not a
    server fault. It returned a 500 with "internal error -- see dashboard
    server log", and nothing in the log."""
    r = api.post("/api/worker/stop", {"worker_id": "definitely-not-a-worker"})
    assert r.status_code == 404, f"unknown worker id produced {r.status_code}: {r.text}"
    assert "unknown worker" in (r.json().get("error") or "").lower()


def test_stop_without_a_worker_id_is_a_400(api):
    r = api.post("/api/worker/stop", {})
    assert r.status_code == 400
    assert r.json().get("ok") is False
