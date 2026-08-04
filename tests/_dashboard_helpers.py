"""DOM- and API-shaped helpers shared by every fun-doc dashboard test tier.

Three tiers read the dashboard and they have different prerequisites, which
is the only thing that should separate them:

``tests/dashboard``      hermetic. Flask test client, sandboxed state, a fake
                         Ghidra. No browser, no server, no Ghidra, no
                         providers. Runs in CI.
``tests/e2e``            live. Real Chromium against a real dashboard backed
                         by a real Ghidra. Skips entirely without one.
``tests/benchmark_e2e``  the undocumented -> documented pass against a
                         dedicated headless Ghidra holding Benchmark.dll.

The parsing below is identical across all three, so it lives here rather
than in any one conftest. Keeping one copy is not tidiness: ``read_legend``
encodes a real parsing trap (labels contain digits), and a second copy that
drifts from this one produces a tier that passes for the wrong reason.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

# --------------------------------------------------------------------------
# legend / segmented-bar parsing
# --------------------------------------------------------------------------

# Legend entries render as ``<swatch>LABEL N``. The label may itself contain
# digits (``80+``, ``<80``, ``100``), so anchor on the LAST whitespace-
# separated integer rather than splitting greedily on the first.
_LEGEND_RE = re.compile(r"^(?P<label>.*?)\s+(?P<n>[\d,]+)$")


def parse_legend_entry(text: str) -> tuple[str, int]:
    """``"DOC_VERIFIED 1,204"`` -> ``("DOC_VERIFIED", 1204)``.

    Raises AssertionError on an unparseable entry rather than returning a
    sentinel: a legend row that does not match this shape means the renderer
    changed, and silently dropping it would shrink every total that is
    compared against the API.
    """
    m = _LEGEND_RE.match(text.strip())
    assert m, f"unparseable legend entry {text!r}"
    return m.group("label").strip(), int(m.group("n").replace(",", ""))


def read_legend(page, legend_id: str) -> dict[str, int]:
    """Parse a ``.seg-legend`` into ``{label: count}``."""
    out: dict[str, int] = {}
    for text in page.locator(f"#{legend_id} .lg").all_inner_texts():
        label, n = parse_legend_entry(text)
        out[label] = n
    return out


def read_segments(page, bar_id: str) -> list[tuple[str, float]]:
    """Return ``[(title, width_pct)]`` for a segmented bar's drawn spans.

    Only segments with n > 0 are drawn, so this is the bar as the operator
    actually SEES it -- which is where a width-overflow bug shows up.
    """
    return page.evaluate(
        """(id) => Array.from(document.querySelectorAll('#' + id + ' > span'))
              .map(s => [s.title, parseFloat(s.style.width) || 0])""",
        bar_id,
    )


def pct_from_label(text: str) -> float | None:
    """Extract the leading percentage from a bar's ``.p`` label.

    Returns None for the em-dash the renderers print when the denominator is
    unknown -- a legitimate, deliberate state, not a parse error.
    """
    m = re.search(r"(-?[\d.]+)\s*%", text)
    return float(m.group(1)) if m else None


# --------------------------------------------------------------------------
# bar invariants -- shared because they are contract, not presentation
# --------------------------------------------------------------------------


def assert_segments_fit(segments: list[tuple[str, float]], *, what: str, tol: float = 0.5) -> None:
    """No segmented bar may draw more than 100% of its own track.

    This is the ``326700%`` family of bugs (``in_scope || 1`` as a
    denominator). It is asserted identically whether the widths came from a
    real browser or from a computed payload, so it lives here.
    """
    total = sum(w for _, w in segments)
    assert total <= 100.0 + tol, (
        f"{what}: segments sum to {total:.2f}% of the track "
        f"(> 100%); segments={segments!r}"
    )
    for title, w in segments:
        assert w >= 0, f"{what}: segment {title!r} has negative width {w}"


def assert_percentage_sane(pct: float | None, *, what: str) -> None:
    """A rendered percentage is either absent (unknown denominator) or 0-100."""
    if pct is None:
        return
    assert 0.0 <= pct <= 100.0, f"{what}: rendered {pct}%, outside 0-100"


# --------------------------------------------------------------------------
# server-side polling
# --------------------------------------------------------------------------


def wait_for(
    predicate: Callable[[], Any],
    timeout: float = 30.0,
    interval: float = 0.5,
    what: str = "condition",
) -> Any:
    """Poll a *server-side* predicate until truthy.

    Playwright's ``expect()`` retries only against the DOM; anything that
    settles in the server (a worker reaching ``running``, a queue draining)
    needs this instead.
    """
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what} (last={last!r})")
