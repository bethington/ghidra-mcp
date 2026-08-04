"""The function and globals inventories, and the function drawer.

Both inventories are read through `conformance_dashboard`, which reads
7.0.0 envelopes from `/list_functions`, `/list_globals` and
`/list_segments`. When that module was blanket-exempted from the
response-contract guard, BOTH inventories silently returned zero rows for
days while the whole suite stayed green — the operator saw an empty table
and the tests saw nothing at all. That is the specific failure these
tests exist to make impossible, so "renders a non-zero number of rows
that agrees with the API" is the headline assertion, not a detail.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _rows(page, tbody: str) -> int:
    return page.locator(f"#{tbody} tr").count()


def _wait_rows(page, tbody: str, timeout: int = 45_000):
    page.wait_for_function(
        "(id) => document.querySelectorAll('#' + id + ' tr').length > 0",
        arg=tbody,
        timeout=timeout,
    )


def _assert_hint_matches(hint: str, served: dict, label: str):
    """Both halves of an inventory hint: the counts, and the hidden-library tail.

    The hint reads ``"147 of 147 · 322 library hidden"``. It used to be asserted
    as exact equality against ``"{shown} of {total}"``, which broke the moment
    the library toggle shipped -- these tests and that feature were developed on
    two branches in parallel and first met when both merged into `dev`.

    Rather than loosen the check to a prefix and lose coverage, assert both
    parts. The tail is the more interesting one: CLAUDE.md requires
    ``library_total`` be reported *whether the toggle is on or off*, because a
    count that silently shrinks when library code is hidden reads as "this
    binary is smaller than I thought". Nothing pinned that until now.

    The separator is U+00B7 and is deliberately not asserted on -- it is
    styling, and matching it invites an encoding failure that says nothing
    about correctness.
    """
    head = f"{served['shown']} of {served['total']}"
    assert hint.startswith(head), (
        f"{label} hint {hint!r} does not start with {head!r} "
        f"(API shown={served['shown']} total={served['total']})"
    )

    library_total = served.get("library_total")
    tail = hint[len(head):].strip().lstrip("·").strip()

    if library_total:
        assert str(library_total) in tail and "librar" in tail.lower(), (
            f"{label} hint {hint!r} omits the hidden-library count; the API "
            f"reports library_total={library_total}. A hint that shows only "
            f"the in-scope total makes excluded library code invisible, which "
            f"is what `library_total` exists to prevent."
        )
    else:
        assert not tail, (
            f"{label} hint {hint!r} carries the trailing text {tail!r} while "
            f"the API reports library_total={library_total!r}. The hint is "
            f"claiming a hidden population the server does not report."
        )


# ---------------------------------------------------------------------------
# function inventory
# ---------------------------------------------------------------------------


def test_function_inventory_renders_rows(dashboard, api):
    page, _ = dashboard
    total = api.get("/api/conformance/inventory", limit=1)["total"]
    if not total:
        pytest.skip("no functions in scope for the focused binary")
    _wait_rows(page, "invBody")
    assert _rows(page, "invBody") > 0, (
        "the function inventory rendered zero rows while the API reports "
        f"{total} — this is the envelope-unwrap regression"
    )


def test_function_inventory_hint_matches_api(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "invBody")
    hint = page.locator("#invHint").inner_text().strip()
    served = api.get("/api/conformance/inventory", q="", limit=6000)
    _assert_hint_matches(hint, served, "inventory")
    assert _rows(page, "invBody") == served["shown"]


def test_function_inventory_row_content_matches_api(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "invBody")
    served = api.get("/api/conformance/inventory", q="", limit=6000)
    if not served["rows"]:
        pytest.skip("empty inventory")
    first = served["rows"][0]
    row = page.locator("#invBody tr").first
    assert first["name"] in row.inner_text()
    assert first["address"] in row.inner_text()


def test_function_inventory_search_filters(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "invBody")
    served = api.get("/api/conformance/inventory", q="", limit=6000)
    if not served["rows"]:
        pytest.skip("empty inventory")
    needle = served["rows"][0]["name"][:6]
    before = _rows(page, "invBody")

    page.locator("#invSearch").fill(needle)
    page.wait_for_timeout(2000)  # debouncedInv()
    filtered = api.get("/api/conformance/inventory", q=needle, limit=6000)
    page.wait_for_function(
        "(n) => document.querySelectorAll('#invBody tr').length === n",
        arg=filtered["shown"],
        timeout=30_000,
    )
    assert _rows(page, "invBody") <= before

    page.locator("#invSearch").fill("")
    page.wait_for_timeout(2000)


def test_function_inventory_search_with_no_matches_is_empty_not_stale(dashboard):
    """A search that matches nothing must clear the table. Leaving the
    previous result set on screen reads as "these matched"."""
    page, _ = dashboard
    _wait_rows(page, "invBody")
    try:
        page.locator("#invSearch").fill("zzz_no_such_function_zzz")
        page.wait_for_function(
            "() => document.querySelectorAll('#invBody tr').length === 0", timeout=30_000
        )
        assert page.locator("#invHint").inner_text().strip().startswith("0 of")
    finally:
        page.locator("#invSearch").fill("")
        page.wait_for_timeout(2000)


def test_function_drawer_opens_and_closes(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "invBody")
    served = api.get("/api/conformance/inventory", q="", limit=1)
    if not served["rows"]:
        pytest.skip("empty inventory")
    expected = served["rows"][0]

    page.locator("#invBody tr").first.click()
    expect(page.locator("#drawer")).to_have_class("drawer open", timeout=30_000)
    expect(page.locator("#drAddr")).to_have_text(expected["address"])
    assert page.locator("#drName").inner_text().strip()
    assert page.locator("#drBadges").inner_text().strip()

    page.keyboard.press("Escape")
    expect(page.locator("#drawer")).not_to_have_class("drawer open")


# ---------------------------------------------------------------------------
# globals inventory
# ---------------------------------------------------------------------------


def test_globals_inventory_renders_rows(dashboard, api):
    page, _ = dashboard
    total = api.get("/api/conformance/globals", limit=1)["total"]
    if not total:
        pytest.skip("no globals in scope for the focused binary")
    _wait_rows(page, "globBody")
    assert _rows(page, "globBody") > 0, (
        f"the globals inventory rendered zero rows while the API reports {total}"
    )


def test_globals_inventory_hint_matches_api(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "globBody")
    hint = page.locator("#globHint").inner_text().strip()
    served = api.get("/api/conformance/globals", q="", limit=200)
    _assert_hint_matches(hint, served, "globals inventory")
    assert _rows(page, "globBody") == served["shown"]


def test_globals_untyped_rows_are_marked(dashboard, api):
    """An untyped global is hard-capped below COMPLETE_80 — the type cell
    carries the `untyped` class so the operator can see the backlog
    without reading every band badge."""
    page, _ = dashboard
    _wait_rows(page, "globBody")
    served = api.get("/api/conformance/globals", q="", limit=200)
    untyped_api = sum(1 for r in served["rows"] if not r.get("typed"))
    untyped_dom = page.locator("#globBody td.gtype.untyped").count()
    assert untyped_dom == untyped_api, (
        f"{untyped_dom} rows marked untyped in the DOM vs {untyped_api} from the API"
    )


def test_globals_reviewed_flag_matches_api(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "globBody")
    served = api.get("/api/conformance/globals", q="", limit=200)
    reviewed_api = sum(1 for r in served["rows"] if r.get("reviewed"))
    reviewed_dom = page.locator("#globBody button.pin-btn.pinned").count()
    assert reviewed_dom == reviewed_api


def test_globals_search_filters(dashboard, api):
    page, _ = dashboard
    _wait_rows(page, "globBody")
    served = api.get("/api/conformance/globals", q="", limit=200)
    if not served["rows"]:
        pytest.skip("empty globals inventory")
    needle = served["rows"][0]["name"][:5]
    try:
        page.locator("#globSearch").fill(needle)
        page.wait_for_timeout(2000)
        filtered = api.get("/api/conformance/globals", q=needle, limit=200)
        page.wait_for_function(
            "(n) => document.querySelectorAll('#globBody tr').length === n",
            arg=filtered["shown"],
            timeout=30_000,
        )
    finally:
        page.locator("#globSearch").fill("")
        page.wait_for_timeout(2000)


def test_globals_summary_agrees_with_the_bar(api):
    """`/globals` carries its own summary block; the bar reads
    `/glob_bands`. Two sources for one number is two chances to be wrong,
    so they must at least agree."""
    inv = api.get("/api/conformance/globals", limit=1)["summary"]
    bands = api.get("/api/conformance/glob_bands")
    assert inv["bands"] == bands["bands"]
    assert inv["reviewed"] == bands["reviewed"]
    assert inv["scope"] == bands["in_scope"]
