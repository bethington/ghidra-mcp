"""The four segmented completion bars.

Every bar is `count / denominator`, and every bar bug this project has
had was a DENOMINATOR bug that the API never saw: `in_scope || 1` turned
3,267 tagged functions into "326700%", and the same class produced
"228600%" on the globals bar. Both were found by eye, in production.

So the invariants under test are structural, not cosmetic:

  1. legend counts == the API's counts (the bar isn't inventing numbers)
  2. drawn segment widths sum to ~100% (the bar fits its track)
  3. the headline percentage is arithmetically consistent with the legend
  4. the numerator's population is the same population as the denominator

(4) is the one that catches a scope mismatch: if the counts come from a
wider set than the denominator counts, the bar reads over 100% and the
leading "untagged/none" segment silently collapses to zero.
"""

from __future__ import annotations

import pytest

from conftest import pct_from_label, read_legend, read_segments

pytestmark = pytest.mark.e2e

# A bar is drawn from integer counts over an integer denominator, so the
# only slack needed is float/rounding noise in the CSS percentages.
WIDTH_TOLERANCE = 0.75
PCT_TOLERANCE = 0.15


BARS = {
    "documentation": ("docBar", "docLegend", "docPct"),
    "function_completeness": ("bandBar", "bandLegend", "bandPct"),
    "conformance": ("confBar", "confLegend", "confPct"),
    "globals": ("globBandBar", "globBandLegend", "globBandPct"),
}


@pytest.fixture
def matrix(api):
    """Function-scoped on purpose: `api` re-points at whatever binary the
    dashboard is focused on right now, and focus is server state that other
    tests change. A module-scoped cache here would pin one binary's matrix
    across a focus switch."""
    return api.get("/api/conformance/matrix")


def _col(matrix: dict, col: str) -> int:
    return sum(matrix["cell"].get(r, {}).get(col, 0) for r in matrix["rows"])


def _row(matrix: dict, row: str) -> int:
    return sum(matrix["cell"].get(row, {}).get(c, 0) for c in matrix["cols"])


# ---------------------------------------------------------------------------
# structural invariants — apply to every bar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(BARS))
def test_bar_is_drawn(dashboard, name):
    page, _ = dashboard
    bar_id, legend_id, _ = BARS[name]
    page.wait_for_function(
        "(id) => document.querySelectorAll('#' + id + ' .lg').length > 0",
        arg=legend_id,
        timeout=30_000,
    )
    assert read_legend(page, legend_id), f"{name} legend is empty"
    assert read_segments(page, bar_id), f"{name} bar drew no segments"


@pytest.mark.parametrize("name", list(BARS))
def test_segments_fit_the_track(dashboard, name):
    """Widths summing past 100% mean the bar has overflowed its own track:
    the visual is wrong AND the numbers behind it are being divided by a
    denominator that does not cover them."""
    page, _ = dashboard
    bar_id, _, _ = BARS[name]
    segments = read_segments(page, bar_id)
    total = sum(w for _, w in segments)
    assert total <= 100 + WIDTH_TOLERANCE, (
        f"{name} bar segments sum to {total:.2f}% — the bar overflows its track. "
        f"Segments: {segments}"
    )
    assert total >= 100 - WIDTH_TOLERANCE, (
        f"{name} bar segments sum to only {total:.2f}% — part of the population "
        f"is unaccounted for. Segments: {segments}"
    )


@pytest.mark.parametrize("name", list(BARS))
def test_headline_percentage_is_in_range(dashboard, name):
    page, _ = dashboard
    _, _, pct_id = BARS[name]
    label = page.locator(f"#{pct_id}").inner_text()
    pct = pct_from_label(label)
    if pct is None:
        assert "—" in label or "-" in label, f"{name} shows neither a % nor an em-dash: {label!r}"
        return
    assert 0.0 <= pct <= 100.0, f"{name} headline reads {pct}% ({label!r})"


@pytest.mark.parametrize("name", list(BARS))
def test_legend_and_segments_agree(dashboard, name):
    """Every drawn segment must correspond to a legend entry with the same
    count — the legend is the only place the operator can read an actual
    number, so a legend that disagrees with the bar is worse than no bar."""
    page, _ = dashboard
    bar_id, legend_id, _ = BARS[name]
    legend = read_legend(page, legend_id)
    for title, _width in read_segments(page, bar_id):
        seg_label, _, seg_n = title.rpartition(" ")
        assert seg_label in legend, f"{name}: segment {seg_label!r} has no legend entry"
        assert legend[seg_label] == int(seg_n), (
            f"{name}: segment {seg_label!r} says {seg_n} but the legend says {legend[seg_label]}"
        )


@pytest.mark.parametrize("name", list(BARS))
def test_segment_widths_match_their_share(dashboard, name):
    """A width must be the segment's share of the total the legend sums to.
    This is what catches a bar whose numbers are right but whose geometry
    is computed against a different denominator."""
    page, _ = dashboard
    bar_id, legend_id, _ = BARS[name]
    legend = read_legend(page, legend_id)
    total = sum(legend.values())
    if total <= 0:
        pytest.skip(f"{name} has an empty population")
    for title, width in read_segments(page, bar_id):
        label, _, n = title.rpartition(" ")
        expected = 100.0 * int(n) / total
        assert abs(width - expected) <= WIDTH_TOLERANCE, (
            f"{name}: segment {label!r} is drawn {width:.2f}% wide but is "
            f"{n}/{total} = {expected:.2f}% of the bar"
        )


# ---------------------------------------------------------------------------
# per-bar: does the page agree with the server?
# ---------------------------------------------------------------------------


def test_documentation_bar_matches_matrix(dashboard, matrix):
    page, _ = dashboard
    legend = read_legend(page, "docLegend")
    in_scope = matrix["in_scope"]
    dd, dr, dv = (_col(matrix, c) for c in ("DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED"))

    assert legend["DRAFT"] == dd
    assert legend["REVIEWED"] == dr
    assert legend["VERIFIED"] == dv
    assert legend["untagged"] == max(0, in_scope - (dd + dr + dv))

    pct = pct_from_label(page.locator("#docPct").inner_text())
    if pct is not None:
        assert abs(pct - 100.0 * dv / in_scope) <= PCT_TOLERANCE


def test_documentation_population_fits_its_denominator(matrix):
    """The doc bar divides matrix tag counts by `in_scope`. `matrix()` does
    not subtract EXCLUDE_TAGS (library/stub) the way `bands()` does, so its
    counts can cover a WIDER population than the denominator — at which
    point the "% any" reading exceeds 100 and the `untagged` segment is
    clamped to zero, hiding the inconsistency. Server-side check, no
    browser needed: the bug is in the data contract, not the rendering."""
    tagged = sum(_col(matrix, c) for c in ("DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED"))
    assert tagged <= matrix["in_scope"], (
        f"{tagged} DOC-tagged functions vs in_scope={matrix['in_scope']} "
        f"(evaluated={matrix.get('evaluated')}, excluded_lib={matrix.get('excluded_lib')}): "
        "matrix() counts library-excluded functions that in_scope does not, so the "
        "documentation bar reads over 100%."
    )


def test_conformance_bar_matches_matrix(dashboard, matrix):
    page, _ = dashboard
    legend = read_legend(page, "confLegend")
    in_scope = matrix["in_scope"]
    rungs = {
        "DRAFT": "CONF_DRAFT",
        "VECTORS": "CONF_VECTORS",
        "LIVE": "CONF_LIVE",
        "BATTLETESTED": "CONF_BATTLETESTED",
        "REGRESSION": "CONF_REGRESSION",
    }
    proven = 0
    for label, rung in rungs.items():
        n = _row(matrix, rung)
        assert legend[label] == n, f"conformance {label}: page {legend[label]} vs API {n}"
        proven += n
    assert legend["none"] == max(0, in_scope - proven)

    pct = pct_from_label(page.locator("#confPct").inner_text())
    if pct is not None:
        assert abs(pct - 100.0 * proven / in_scope) <= PCT_TOLERANCE


def test_conformance_none_segment_agrees_with_the_matrix_cell(matrix):
    """The bar computes `none` as in_scope - proven; the matrix reports its
    own `none` row. They are the same quantity and must not diverge."""
    proven = sum(
        _row(matrix, r)
        for r in ("CONF_DRAFT", "CONF_VECTORS", "CONF_LIVE", "CONF_BATTLETESTED", "CONF_REGRESSION")
    )
    rendered_none = max(0, matrix["in_scope"] - proven)
    matrix_none = _row(matrix, "none")
    assert rendered_none == matrix_none, (
        f"conformance bar draws none={rendered_none} while the matrix row says "
        f"{matrix_none} — the bar and the matrix are counting different populations"
    )


def test_function_completeness_bar_matches_bands(dashboard, api):
    page, _ = dashboard
    b = api.get("/api/conformance/bands")
    legend = read_legend(page, "bandLegend")
    bands = b["bands"]
    in_scope = b["in_scope"]

    assert legend["80+"] == bands.get("COMPLETE_80", 0)
    assert legend["90+"] == bands.get("COMPLETE_90", 0)
    assert legend["95+"] == bands.get("COMPLETE_95", 0)
    assert legend["100"] == bands.get("COMPLETE_100", 0)
    tagged = sum(bands.get(f"COMPLETE_{t}", 0) for t in (80, 90, 95, 100))
    assert legend["<80"] == max(0, in_scope - tagged)


def test_function_completeness_target_follows_config(dashboard, api):
    """The "at target" reading must follow `good_enough_score`, not a
    hardcoded 90 — the Target picker is how an operator changes what
    "done" means, and a frozen headline makes that setting a lie."""
    page, _ = dashboard
    cfg = api.get("/api/queue/config")
    target = int((cfg.get("config") or cfg).get("good_enough_score") or 90)
    label = page.locator("#bandPct").inner_text()
    assert f"({target}+)" in label, f"band headline {label!r} does not reflect target {target}"

    b = api.get("/api/conformance/bands")
    bands, in_scope = b["bands"], b["in_scope"]
    at_level = {
        80: sum(bands.get(f"COMPLETE_{t}", 0) for t in (80, 90, 95, 100)),
        90: sum(bands.get(f"COMPLETE_{t}", 0) for t in (90, 95, 100)),
        95: sum(bands.get(f"COMPLETE_{t}", 0) for t in (95, 100)),
        100: bands.get("COMPLETE_100", 0),
    }
    pct = pct_from_label(label)
    if pct is not None and in_scope:
        assert abs(pct - 100.0 * at_level[target] / in_scope) <= PCT_TOLERANCE


def test_globals_bar_matches_glob_bands(dashboard, api):
    page, _ = dashboard
    b = api.get("/api/conformance/glob_bands")
    legend = read_legend(page, "globBandLegend")
    bands, in_scope = b["bands"], b["in_scope"]

    assert legend["80+"] == bands.get("COMPLETE_80", 0)
    assert legend["90+"] == bands.get("COMPLETE_90", 0)
    assert legend["95+"] == bands.get("COMPLETE_95", 0)
    assert legend["100"] == bands.get("COMPLETE_100", 0)
    tagged = sum(bands.get(f"COMPLETE_{t}", 0) for t in (80, 90, 95, 100))
    assert legend["<80"] == max(0, in_scope - tagged)


def test_globals_reviewed_chip_is_not_folded_into_the_bar(dashboard, api):
    """`reviewed` is a trust bit, orthogonal to completeness — it rides as
    a chip in the label and must never become a band segment (that
    conflation is exactly why the DOC rung ladder was retired)."""
    page, _ = dashboard
    reviewed = api.get("/api/conformance/glob_bands").get("reviewed", 0)
    label = page.locator("#globBandPct").inner_text()
    assert "reviewed" in label
    assert f"{reviewed:,}" in label or str(reviewed) in label
    assert "reviewed" not in read_legend(page, "globBandLegend")


def test_bars_survive_a_refresh(dashboard):
    """The refresh button re-runs the same render path; a bar that only
    renders on first paint leaves stale numbers on screen indefinitely."""
    page, _ = dashboard
    before = read_legend(page, "docLegend")
    page.locator("header button[title='Refresh']").click()
    page.wait_for_timeout(4000)
    page.wait_for_function(
        """() => ['docLegend','bandLegend','confLegend','globBandLegend']
                  .every(id => document.querySelectorAll('#' + id + ' .lg').length > 0)""",
        timeout=45_000,
    )
    assert read_legend(page, "docLegend") == before
