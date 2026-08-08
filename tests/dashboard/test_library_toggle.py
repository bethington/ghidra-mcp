"""The "show library code" toggle, end to end through the real Flask app.

Hermetic: FakeGhidra supplies both exclusion populations already -- LIB_CRT
function tags and `Scope` property entries on globals -- so these exercise the
route, the query-string flag and the read layer together rather than the read
layer alone.

The invariant under test is not "the toggle works". It is that the two states
stay RECONCILABLE: whatever the toggle is doing, the operator can always tell
how many rows are hidden and why. A count that silently shrinks reads as "this
binary is smaller than I thought", which is the failure this feature exists to
prevent -- the same shape as the types bar counting a destroyed global as
perfectly typed.
"""

from __future__ import annotations

import fake_ghidra as fg


def _inv(harness, **q):
    r = harness.client.get("/api/conformance/inventory", query_string=q or None)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    return r.get_json()


def _glob(harness, **q):
    r = harness.client.get("/api/conformance/globals", query_string=q or None)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    return r.get_json()


# --------------------------------------------------------------------------
# function inventory
# --------------------------------------------------------------------------

class TestFunctionInventoryToggle:
    def test_library_functions_are_excluded_by_default(self, harness):
        out = _inv(harness)
        assert out["total"] == fg.N_IN_SCOPE
        assert all(not r.get("library") for r in out["rows"])

    def test_hidden_count_is_reported_even_when_hidden(self, harness):
        """The operator must never have to guess how much is missing."""
        out = _inv(harness)
        assert out["library_total"] == len(fg.FakeGhidra().tags["LIB_CRT"])
        assert out["include_library"] is False

    def test_toggle_adds_them_back_labelled(self, harness):
        out = _inv(harness, lib="1")
        assert out["include_library"] is True
        assert out["total"] == (fg.N_IN_SCOPE + out["library_total"]
                                + out["scope_excluded_total"])
        lib_rows = [r for r in out["rows"] if r.get("library")]
        assert lib_rows, "toggle on but no library rows returned"
        assert {r["library"] for r in lib_rows} == {"LIB_CRT", "SCOPE_EXCLUDED"}

    def test_the_two_states_reconcile(self, harness):
        """off.total + everything hidden == on.total. If these ever disagree, one
        of the two views is lying about the size of the binary."""
        off, on = _inv(harness), _inv(harness, lib="1")
        assert (off["total"] + off["library_total"]
                + off["scope_excluded_total"]) == on["total"]


class TestProofAndInferenceAreCountedApart:
    """`library_total` means a lane MATCHED an artifact; `scope_excluded_total`
    means scope_graph only INFERRED it from the reference graph -- which is also
    true, by construction, of every mod entry point the CRT calls. Summing them
    renders a guess as a proof on the panel an operator uses to decide what is
    worth documenting."""

    def test_both_counts_are_reported_separately(self, harness):
        out = _inv(harness)
        assert out["library_total"] == fg.N_LIBRARY
        assert out["scope_excluded_total"] == fg.N_SCOPE_EXCLUDED

    def test_neither_count_absorbs_the_other(self, harness):
        out = _inv(harness)
        assert out["library_total"] != out["library_total"] + out["scope_excluded_total"]
        assert out["scope_excluded_total"] > 0, \
            "the fake corpus lost its inferred population -- this test proves nothing"

    def test_inferred_rows_are_labelled_with_their_own_tag(self, harness):
        """The per-row chip is the auditable part: an operator can see WHY a
        function is out of scope, and that an inference is an inference."""
        rows = [r for r in _inv(harness, lib="1")["rows"]
                if r.get("library") == "SCOPE_EXCLUDED"]
        assert len(rows) == fg.N_SCOPE_EXCLUDED
        # Game-styled names: the population a name-based classifier cannot catch.
        assert any(r["name"].startswith(("UNIT_", "MEMMGR_", "STRING_"))
                   for r in rows)

    def test_inferred_functions_are_out_of_the_default_view(self, harness):
        names = {r["name"] for r in _inv(harness)["rows"]}
        assert "UNIT_GetUnitFlags2" not in names

    def test_they_are_excluded_from_the_in_scope_denominator(self, harness):
        """Panels divide tagged counts by in_scope. A numerator computed over a
        wider population is how the bars read 105.3% and 172.6%."""
        r = harness.client.get("/api/conformance/bands")
        assert r.status_code == 200
        assert r.get_json()["in_scope"] == fg.N_IN_SCOPE

    def test_library_rows_sort_last(self, harness):
        """The toggle is for inspection. Burying the actual work under CRT rows
        would defeat the inventory it is attached to."""
        rows = _inv(harness, lib="1")["rows"]
        first_lib = next(i for i, r in enumerate(rows) if r.get("library"))
        assert all(not r.get("library") for r in rows[:first_lib])
        assert all(r.get("library") for r in rows[first_lib:])

    def test_search_still_applies_with_the_toggle_on(self, harness):
        name = next(r["name"] for r in _inv(harness, lib="1")["rows"])
        out = _inv(harness, lib="1", q=name)
        assert out["total"] >= 1
        assert all(name.lower() in r["name"].lower() for r in out["rows"])

    def test_flag_forms_all_mean_the_same(self, harness):
        """A checkbox sends `on`; a hand-typed URL sends 1 or true."""
        base = _inv(harness, lib="1")["total"]
        for form in ("true", "on", "yes", "1"):
            assert _inv(harness, lib=form)["total"] == base

    def test_absent_or_falsey_flag_excludes(self, harness):
        off = _inv(harness)["total"]
        for form in ("", "0", "false", "off", "no", "banana"):
            assert _inv(harness, lib=form)["total"] == off


# --------------------------------------------------------------------------
# globals inventory
# --------------------------------------------------------------------------

class TestGlobalsInventoryToggle:
    def test_scope_excluded_globals_hidden_by_default(self, harness):
        out = _glob(harness)
        assert out["library_total"] == fg.N_GLOBALS_EXCLUDED
        assert all(not r.get("library") for r in out["rows"])

    def test_toggle_adds_them_back_labelled(self, harness):
        out = _glob(harness, lib="1", limit=500)
        lib_rows = [r for r in out["rows"] if r.get("library")]
        assert len(lib_rows) == fg.N_GLOBALS_EXCLUDED
        assert all(r["library"] == "LIB" for r in lib_rows)

    def test_the_two_states_reconcile(self, harness):
        off = _glob(harness, limit=500)
        on = _glob(harness, lib="1", limit=500)
        assert off["total"] + fg.N_GLOBALS_EXCLUDED == on["total"]

    def test_summary_scope_grows_with_the_toggle(self, harness):
        """`summary` feeds the Globals bar. It must describe the same population
        the rows do, or the bar and the list disagree about the denominator."""
        off = _glob(harness, limit=500)["summary"]
        on = _glob(harness, lib="1", limit=500)["summary"]
        assert on["scope"] == off["scope"] + fg.N_GLOBALS_EXCLUDED

    def test_library_globals_sort_last(self, harness):
        rows = _glob(harness, lib="1", limit=500)["rows"]
        first_lib = next(i for i, r in enumerate(rows) if r.get("library"))
        assert all(r.get("library") for r in rows[first_lib:])


# --------------------------------------------------------------------------
# the two halves must not disagree
# --------------------------------------------------------------------------

class TestBothHalvesAgree:
    def test_both_inventories_expose_the_same_contract(self, harness):
        """Two views of "what is in scope in this binary" with different flag
        names or different report keys is how the last globals bug hid."""
        for payload in (_inv(harness), _glob(harness, limit=500)):
            assert "library_total" in payload
            assert "include_library" in payload

    def test_neither_half_500s_on_the_flag(self, harness):
        for path in ("/api/conformance/inventory", "/api/conformance/globals"):
            for form in ("1", "0", "", "garbage"):
                r = harness.client.get(path, query_string={"lib": form})
                assert r.status_code == 200, f"{path}?lib={form} -> {r.status_code}"
