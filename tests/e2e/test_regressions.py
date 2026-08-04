"""Named guards for dashboard bugs that actually shipped.

Each test here corresponds to a specific failure that reached the
operator's screen. They are separated from the feature tests on purpose:
when one of these goes red it is not "a test broke", it is "a bug we have
already paid for is back".
"""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.e2e

# `326700%` on the completeness bar, `228600%` on the globals bar — both
# from `in_scope || 1` folding a legitimate zero into a denominator of 1.
IMPLAUSIBLE_PCT = 100.5

_PCT_RE = re.compile(r"(-?\d[\d,]*\.?\d*)\s*%")


def test_no_percentage_on_the_page_exceeds_100(dashboard):
    """The `|| 1` denominator class of bug, caught wherever it surfaces."""
    page, _ = dashboard
    page.wait_for_timeout(4000)
    offenders = []
    for pct_id in ("docPct", "bandPct", "confPct", "globBandPct"):
        text = page.locator(f"#{pct_id}").inner_text()
        for raw in _PCT_RE.findall(text):
            value = float(raw.replace(",", ""))
            if value > IMPLAUSIBLE_PCT or value < 0:
                offenders.append(f"#{pct_id}: {value}% (in {text!r})")
    assert not offenders, "implausible percentages rendered:\n  " + "\n  ".join(offenders)


def test_health_payload_carries_no_store_credentials(api):
    """`_health_store` must report `config.backend`, never `config.url` —
    a Postgres URL carries credentials and this payload renders in a
    browser and lands in anyone's devtools."""
    store = api.get("/api/health/all")["subsystems"]["store"]
    blob = " ".join(str(v) for v in store.values() if v is not None).lower()
    for leak in ("://", "password", "postgresql:", "@localhost", "user="):
        assert leak not in blob, f"store health detail looks like a connection string: {store}"


def test_both_inventories_are_non_zero(api):
    """`conformance_dashboard` reads 7.0.0 envelopes; when its unwrap
    broke, both inventories returned 0 rows for days behind a green
    suite. Zero from a binary with functions is the tell."""
    summary = api.get("/api/conformance/summary")
    if not summary.get("local_defined"):
        pytest.skip("focused binary has no defined functions")
    assert api.get("/api/conformance/inventory", limit=1)["total"] > 0, (
        "function inventory returned 0 rows for a binary with defined functions"
    )
    assert api.get("/api/conformance/globals", limit=1)["total"] > 0, (
        "globals inventory returned 0 rows for a binary with defined functions"
    )


def test_worker_roster_is_offered_not_auto_restored(api):
    """Auto-restore is retired at the call site on purpose: a restart used
    to silently relaunch a fleet the operator had deliberately stopped.
    The roster may be OFFERED, never applied."""
    roster = api.get("/api/worker/roster")
    assert "offer" in roster, f"roster payload has no offer field: {roster}"
    offer = roster.get("offer")
    if not offer:
        return
    running = {w["id"] for w in api.get("/api/worker/status")["workers"]}
    offered = {w.get("id") for w in offer.get("workers", [])}
    assert not (offered & running), (
        "workers from the persisted roster are already running — "
        f"auto-restore appears to have fired: {offered & running}"
    )


def test_pause_state_reports_worker_count_and_reason(api):
    """A paused fleet must say WHY and HOW MANY. `paused: true` with no
    reason is indistinguishable from a bug that stopped the fleet."""
    state = api.get("/api/worker/pause_state")
    assert "paused" in state
    if state.get("paused"):
        assert state.get("reason"), "fleet is paused with no reason recorded"
        assert isinstance(state.get("workers"), int)


def test_matrix_and_summary_count_the_same_population(api):
    """`summary()` filters library-excluded functions; `matrix()` does
    not. When the two disagree, every bar built from the matrix is
    divided by the summary's denominator and reads high."""
    m = api.get("/api/conformance/matrix")
    s = api.get("/api/conformance/summary")
    # `summary.in_scope` comes from a stored Ghidra option that only the sync
    # tool writes, so it is absent for any binary that never went through
    # conformance intake; matrix() then computes defined-minus-library itself.
    # Only compare when the authoritative value actually exists.
    if s.get("in_scope") is not None:
        assert m["in_scope"] == s["in_scope"], (
            f"matrix in_scope={m['in_scope']} but summary in_scope={s['in_scope']}"
        )
    assert m["evaluated"] <= m["in_scope"], (
        f"matrix evaluated={m['evaluated']} exceeds in_scope={m['in_scope']} "
        f"(excluded_lib={m.get('excluded_lib')}) — the matrix is counting functions "
        "the denominator excludes, so the doc/conformance bars read high"
    )


def test_summary_declares_how_stale_it_is(dashboard, api):
    """`summary` is a SNAPSHOT; `matrix` is LIVE.

    The conformance bar takes its denominator from the stored summary option
    (written only by `sync_conformance_to_ghidra.py`) and its numerators from
    a live Ghidra read, so the two legitimately disagree — measured
    CONF_LIVE 162 live vs 149 in a snapshot three weeks old. That is by
    design and cannot be asserted away.

    What CAN go wrong is an operator reading a stale percentage without
    knowing it is stale, so the guard is that `last_sync` exists AND is on
    the page. (It used to be rendered into `#workerHint`, the Active Workers
    header, where it clobbered the worker count and told you nothing about
    the bars it actually qualifies.)
    """
    page, _ = dashboard
    s = api.get("/api/conformance/summary")
    if not s.get("last_sync"):
        pytest.skip("focused binary has never been synced")
    shown = page.locator("#lastSync").inner_text()
    assert s["last_sync"] in shown, (
        f"summary is a {s['last_sync']} snapshot but the page shows {shown!r}"
    )
    assert "last sync" not in page.locator("#workerHint").inner_text().lower(), (
        "the sync date is being written into the Active Workers header again"
    )


@pytest.mark.slow
def test_no_binary_in_the_project_overflows_its_denominator(api):
    """Sweep every binary, not just the focused one.

    The per-binary guards above only fire for whatever is in focus, and
    the overflow is corpus-shaped: when this was found, 32 of 34 binaries
    were fine and D2Common (105.3%) and PD2_EXT (172.6%) were not. A
    guard that only checks the focused binary would have been green on
    31 of 34 workdays.
    """
    listed = api.get("/api/conformance/binaries")["binaries"]
    offenders = []
    for b in listed:
        try:
            m = api.get("/api/conformance/matrix", program=b["path"])
        except Exception as exc:  # noqa: BLE001, PERF203
            offenders.append(f"{b['name']}: matrix failed ({exc})")
            continue
        in_scope = m.get("in_scope") or 0
        if not in_scope:
            continue
        tagged = sum(
            sum(m["cell"].get(r, {}).get(c, 0) for r in m["rows"])
            for c in ("DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED")
        )
        if tagged > in_scope:
            offenders.append(
                f"{b['name']}: {tagged} DOC-tagged / {in_scope} in scope "
                f"= {100.0 * tagged / in_scope:.1f}%"
            )
        elif m.get("evaluated", 0) > in_scope:
            offenders.append(
                f"{b['name']}: evaluated={m['evaluated']} > in_scope={in_scope}"
            )
    assert not offenders, "binaries whose bars divide by too small a denominator:\n  " + "\n  ".join(
        offenders
    )


def test_bands_never_exceed_in_scope(api):
    """`bands()` DOES subtract EXCLUDE_TAGS. This is the control that
    proves the matrix failure above is a real asymmetry and not just how
    the corpus is shaped."""
    for endpoint in ("/api/conformance/bands", "/api/conformance/glob_bands"):
        b = api.get(endpoint)
        tagged = sum(b["bands"].values())
        assert tagged <= b["in_scope"], (
            f"{endpoint}: {tagged} band-tagged vs in_scope={b['in_scope']}"
        )


def test_page_focus_and_server_context_agree(api):
    """The binary the header names must be the binary the fleet works.

    `loadBinaries()` seeds `PROGRAM` from
    `/api/conformance/binaries/progress`, whose route deliberately
    overrides `conformance_dashboard.PROGRAM` (a module constant from
    `FUNDOC_GHIDRA_PROGRAM`) with the persisted `active_binary` meta —
    the value `pickBinary -> syncServerContext` writes. Drop that
    override and focus silently reverts to the default binary on every
    reload while the workers keep running against the chosen one.

    Note `/api/conformance/binaries` (no `/progress`) still reports the
    unpatched constant; it is not what the page reads.
    """
    page_focus = api.get("/api/conformance/binaries/progress").get("active")
    server_context = api.get("/api/context").get("active_binary")
    assert page_focus == server_context, (
        f"the dashboard header focuses {page_focus} but the server context "
        f"(globals worker / queue refresh / worker default) is {server_context}"
    )


@pytest.mark.destructive
def test_binary_focus_survives_a_reload(dashboard, api):
    """Picking a binary writes the server context but the boot path never
    reads it back, so focus silently resets on every refresh."""
    page, _ = dashboard
    listed = api.get("/api/conformance/binaries")
    original = listed.get("active")
    candidates = [b["path"] for b in listed["binaries"] if b["path"] != original]
    if not candidates:
        pytest.skip("only one binary available")
    target = candidates[0]
    try:
        page.evaluate("(p) => pickBinary(p)", target)
        page.wait_for_function(
            "(n) => (document.getElementById('fbName').textContent || '') === n",
            arg=target.split("/")[-1],
            timeout=30_000,
        )
        page.reload(wait_until="domcontentloaded")
        page.wait_for_function(
            "() => (document.getElementById('fbName').textContent || '') !== 'binary'",
            timeout=45_000,
        )
        assert page.locator("#fbName").inner_text().strip() == target.split("/")[-1], (
            "binary focus reset on reload — the picked binary was written to the "
            "server context but the boot path re-reads the hardcoded default"
        )
    finally:
        if original:
            api.post("/api/context/binary", {"binary": original})


def test_dashboard_does_not_error_when_a_panel_endpoint_is_slow(dashboard):
    """Panels fetch independently; one slow endpoint must degrade that
    panel, not throw and abort the rest of the render pass."""
    page, errors = dashboard
    page.wait_for_timeout(5000)
    fatal = [e for e in errors.pageerrors if "TypeError" in e or "undefined" in e]
    assert not fatal, "unhandled render errors:\n  " + "\n  ".join(fatal)
