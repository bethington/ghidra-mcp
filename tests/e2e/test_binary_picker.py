"""The binary focus picker.

Everything on this dashboard is per-binary — tags, bands, inventories,
the queue the workers pull from. Focus is therefore the single most
consequential control on the page, and it has a history: switching
context used to route through `save_state()`, which bulk-upserted all
~62K workflow rows and stalled the dashboard for ~50 seconds. Context
switches must stay meta-only, so this file times one.
"""

from __future__ import annotations

import time

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

# Meta-only context write. A regression back to save_state() would put
# this in the tens of seconds; anything past a few seconds means the
# switch is doing more than stamping two meta keys.
CONTEXT_SWITCH_BUDGET_SEC = 8.0


def test_focus_button_shows_the_active_binary(dashboard, active_program):
    page, _ = dashboard
    name = active_program.replace("\\", "/").split("/")[-1]
    expect(page.locator("#fbName")).to_have_text(name)


def test_picker_opens_and_lists_binaries(dashboard):
    page, _ = dashboard
    page.locator("#focusBtn").click()
    expect(page.locator("#picker")).to_have_class("picker open", timeout=15_000)
    page.wait_for_function(
        "() => document.querySelectorAll('#pickerBody .bcard, #pickerBody .worker-empty').length > 0",
        timeout=30_000,
    )
    assert page.locator("#pickerBody").inner_text().strip()
    page.keyboard.press("Escape")
    expect(page.locator("#picker")).not_to_have_class("picker open")


def test_picker_closes_on_click_away(dashboard):
    page, _ = dashboard
    page.locator("#focusBtn").click()
    expect(page.locator("#picker")).to_have_class("picker open")
    page.locator("#intakeN").click()
    expect(page.locator("#picker")).not_to_have_class("picker open")


def test_picker_lists_binaries_the_server_knows_about(dashboard, api):
    page, _ = dashboard
    page.locator("#focusBtn").click()
    page.wait_for_function(
        "() => document.querySelectorAll('#pickerBody .bcard').length > 0", timeout=30_000
    )
    listed = page.locator("#pickerBody").inner_text()
    served = api.get("/api/conformance/binaries")
    names = served if isinstance(served, list) else served.get("binaries", [])
    if not names:
        pytest.skip("no binaries reported")
    shown = [
        n
        for n in (
            (b if isinstance(b, str) else b.get("name") or b.get("path", "")) for b in names
        )
        if n
    ]
    hits = sum(1 for n in shown if n.replace("\\", "/").split("/")[-1] in listed)
    assert hits > 0, "the picker listed none of the binaries the server reports"
    page.keyboard.press("Escape")


def test_context_endpoint_reports_a_binary_and_folder(api):
    ctx = api.get("/api/context")
    assert ctx.get("active_binary"), "no active_binary in /api/context"
    assert ctx.get("project_folder"), "no project_folder in /api/context"
    assert ctx.get("available_binaries"), "no available_binaries in /api/context"


@pytest.mark.destructive
def test_context_switch_is_meta_only_and_fast(api):
    """Set the active binary to what it already is and time it. Even the
    identity write goes down the same path, so a regression to a bulk
    upsert shows up here without changing any state."""
    ctx = api.get("/api/context")
    active = ctx["active_binary"]
    start = time.time()
    r = api.post("/api/context/binary", {"binary": active})
    elapsed = time.time() - start
    assert r.status_code < 400, f"{r.status_code}: {r.text}"
    assert elapsed < CONTEXT_SWITCH_BUDGET_SEC, (
        f"a context switch took {elapsed:.1f}s (budget {CONTEXT_SWITCH_BUDGET_SEC}s) — "
        "context switches must stay meta-only, not route through save_state()"
    )
    assert api.get("/api/context")["active_binary"] == active


@pytest.mark.destructive
def test_switching_binary_repoints_every_panel(dashboard, api, active_program):
    """Switching focus must move the bars AND both inventories. A panel
    that keeps the old binary's numbers next to the new binary's name is
    the worst possible outcome: it looks correct."""
    page, _ = dashboard
    original_context = api.get("/api/context")["active_binary"]
    listed = api.get("/api/conformance/binaries")["binaries"]
    candidates = [b["path"] for b in listed if b["path"] != active_program]
    if not candidates:
        pytest.skip("only one binary available")

    # pick one that actually has functions, else the assertion is vacuous
    target = None
    for path in candidates:
        try:
            if api.get("/api/conformance/inventory", program=path, limit=1)["total"] > 0:
                target = path
                break
        except Exception:  # noqa: BLE001, PERF203
            continue
    if not target:
        pytest.skip("no alternative binary with functions")

    before_inv = page.locator("#invHint").inner_text()
    try:
        page.locator("#focusBtn").click()
        page.wait_for_function(
            "() => document.querySelectorAll('#pickerBody .bcard').length > 0", timeout=30_000
        )
        page.evaluate("(p) => pickBinary(p)", target)
        page.wait_for_function(
            "(n) => (document.getElementById('fbName').textContent || '').includes(n)",
            arg=target.split("/")[-1],
            timeout=30_000,
        )
        page.wait_for_function(
            "(before) => document.getElementById('invHint').textContent !== before",
            arg=before_inv,
            timeout=60_000,
        )
        assert api.get("/api/context")["active_binary"] == target

        served = api.get("/api/conformance/inventory", program=target, q="", limit=6000)
        assert page.locator("#invHint").inner_text().strip() == (
            f"{served['shown']} of {served['total']}"
        )
    finally:
        api.post("/api/context/binary", {"binary": original_context})
