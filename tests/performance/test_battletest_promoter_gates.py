"""Tests for battletest_promoter's promotion and refutation gates.

Three defects this pins, all found while extending the promoter for D2Client:

  * the module carried its OWN four-item CONF_TAGS list, written before
    CONF_VETTED/SHIPPED/BLOCKED/REFUTED existed -- so a promotion would leave
    any of those standing next to CONF_BATTLETESTED, breaking the mutual
    exclusivity the taxonomy depends on;
  * the image base was hardcoded to D2Common, so a D2Client dispatcher offset
    resolved into D2Common -- the wrong-binary failure class again;
  * a divergence only incremented a counter. The disproved rung kept standing
    forever, which under shadow-first (where divergences are the PRIMARY
    signal) is the single most important thing to get right.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

bp = pytest.importorskip("battletest_promoter")
import conf_ladder  # noqa: E402

ADDR_COMMON = 0x6FD50000
ADDR_CLIENT = 0x6FAB0000


@pytest.fixture
def rig(monkeypatch, tmp_path):
    """Fake the dispatcher feed, the registry file, and Ghidra writes."""
    state = {"dispatchers": [], "rows": [], "writes": []}

    monkeypatch.setattr(bp, "PROVEN_REGISTRY", tmp_path / "proven.jsonl")
    monkeypatch.setattr(bp, "_load_registry", lambda: state["rows"])
    monkeypatch.setattr(bp, "_save_registry", lambda rows: None)
    monkeypatch.setattr(bp, "_http_get_json",
                        lambda *a, **k: {"ok": True, "dispatchers": state["dispatchers"]})

    def fake_post(path, data):
        state["writes"].append((path, data))
        return {"status": "success"}

    monkeypatch.setattr(bp, "_ghidra_post", fake_post)
    monkeypatch.setattr(bp, "_WARNED_NO_DISTINCT", set())
    monkeypatch.setattr(bp, "_WARNED_DOMAIN", set())

    # Ghidra is the source of truth for the held rung, so the promoter queries
    # it. Serve it from the fake registry rows here -- without this the tests
    # would silently depend on a live Ghidra (and on whatever tags the real
    # D2Common happens to carry at those addresses).
    def fake_rung(address_hex, program):
        if "ghidra_rung" in state:
            return state["ghidra_rung"]
        key = str(address_hex).lower().lstrip("0x").rjust(8, "0")
        for r in state["rows"]:
            if str(r["address"]).lower().lstrip("0x").rjust(8, "0") == key:
                return r.get("conf")
        return None

    monkeypatch.setattr(bp, "_ghidra_rung", fake_rung)

    # Saturation watermarks live in their own durable store; isolate it per test
    # so nothing touches the real conformance/shadow_watermarks.json.
    state["marks"] = {}
    monkeypatch.setattr(bp, "_load_watermarks", lambda: state["marks"])
    monkeypatch.setattr(bp, "_save_watermarks", lambda w: state.update(marks=w))
    return state


def _added(state):
    return [d for p, d in state["writes"] if p == "/add_function_tag"]


def _disp(name, offset, **kw):
    base = {"name": name, "offset": offset, "modeName": "shadow",
            "hits": 5000, "divergences": 0, "distinct_inputs": 50, "arg_count": 2}
    base.update(kw)
    return base


def _row(name, addr, conf="CONF_LIVE"):
    return {"name": name, "address": addr, "conf": conf, "program": "D2Common.dll"}


# --- promotion requires volume AND diversity --------------------------------

def test_promotes_when_both_bars_are_met(rig):
    rig["dispatchers"] = [_disp("F", 0x1000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert out["ok"] and len(out["promoted"]) == 1
    assert out["promoted"][0]["rung"] == "CONF_BATTLETESTED"


def test_high_volume_low_diversity_does_not_promote(rig):
    """'1M calls with 3 inputs is not coverage'."""
    rig["dispatchers"] = [_disp("F", 0x1000, hits=1_000_000, distinct_inputs=3)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert out["promoted"] == []


def test_missing_sampler_fails_closed(rig, capsys):
    """No distinct_inputs field = older D2Debugger without the sampler. Must NOT
    promote on volume alone, and must say so."""
    d = _disp("F", 0x1000)
    del d["distinct_inputs"]
    rig["dispatchers"] = [d]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert out["promoted"] == []
    assert "no input-diversity data" in capsys.readouterr().out


def test_below_volume_bar_does_not_promote(rig):
    rig["dispatchers"] = [_disp("F", 0x1000, hits=999)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert bp.poll_and_promote()["promoted"] == []


# --- divergence refutes -----------------------------------------------------

def test_divergence_refutes_the_held_rung(rig):
    rig["dispatchers"] = [_disp("F", 0x1000, divergences=4)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000), conf="CONF_BATTLETESTED")]
    out = bp.poll_and_promote()
    assert len(out["refuted"]) == 1
    assert out["refuted"][0]["from"] == "CONF_BATTLETESTED"
    assert any(d["tags"] == conf_ladder.CONF_REFUTED for d in _added(rig))


def test_diverging_function_is_never_also_promoted(rig):
    """Plenty of hits and diversity, but it diverged -- refute, never promote."""
    rig["dispatchers"] = [_disp("F", 0x1000, hits=100_000, divergences=1)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert out["promoted"] == [] and len(out["refuted"]) == 1


def test_divergence_records_the_counterexample(rig):
    rig["dispatchers"] = [_disp("F", 0x1000, divergences=7)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    bp.poll_and_promote()
    props = [d for p, d in rig["writes"] if p == "/set_property"]
    assert props and '"divergences":7' in props[0]["value"]


# --- mutual exclusivity + program targeting ---------------------------------

def test_promotion_clears_every_other_rung(rig):
    """The stale local CONF_TAGS list would have left CONF_VETTED/BLOCKED/
    REFUTED standing alongside the new rung."""
    rig["dispatchers"] = [_disp("F", 0x1000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    bp.poll_and_promote()
    removed = [d for p, d in rig["writes"] if p == "/remove_function_tag"][0]
    cleared = set(removed["tags"].split(","))
    for t in conf_ladder.ALL_CONF_TAGS:
        if t != "CONF_BATTLETESTED":
            assert t in cleared, t


def test_d2client_offsets_resolve_against_the_d2client_base(rig):
    rig["dispatchers"] = [_disp("G", 0xB150)]
    rig["rows"] = [_row("G", hex(ADDR_CLIENT + 0xB150))]
    out = bp.poll_and_promote(program="D2Client.dll")
    assert len(out["promoted"]) == 1
    assert _added(rig)[0]["program"] == "D2Client.dll"
    assert _added(rig)[0]["function"] == hex(ADDR_CLIENT + 0xB150)


def test_unknown_program_is_refused_not_guessed(rig):
    out = bp.poll_and_promote(program="Fog.dll")
    assert out["ok"] is False and "image base" in out["error"]


# --- CONF_SHIPPED is opt-in -------------------------------------------------

def test_shipped_requires_opt_in(rig):
    rig["dispatchers"] = [_disp("F", 0x1000, hits=50_000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert bp.poll_and_promote()["promoted"][0]["rung"] == "CONF_BATTLETESTED"


def test_shipped_needs_the_higher_volume_bar(rig):
    rig["dispatchers"] = [_disp("F", 0x1000, hits=5_000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote(allow_ship=True)
    assert out["promoted"][0]["rung"] == "CONF_BATTLETESTED"


def test_shipped_granted_at_the_higher_bar_when_opted_in(rig):
    rig["dispatchers"] = [_disp("F", 0x1000, hits=50_000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote(allow_ship=True)
    assert out["promoted"][0]["rung"] == "CONF_SHIPPED"


def test_never_demotes_by_promotion(rig):
    """An already-shipped function must not be knocked back to battletested."""
    rig["dispatchers"] = [_disp("F", 0x1000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000), conf="CONF_SHIPPED")]
    assert bp.poll_and_promote()["promoted"] == []


# --- arg_count semantics (added with the D2Debugger sampler) ----------------

def test_zero_arg_function_skips_the_diversity_floor(rig):
    """A 0-arg function has exactly ONE possible input, so a >=20 distinct floor
    is unsatisfiable by construction and would block it forever."""
    rig["dispatchers"] = [_disp("F", 0x1000, arg_count=0, distinct_inputs=1)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert len(bp.poll_and_promote()["promoted"]) == 1


def test_coord_family_reports_no_diversity_data(rig, capsys):
    """The coord family predates the sampler: it reports distinct_inputs=0 with
    arg_count=-1, meaning UNKNOWN -- not 'one input'. Must fail closed."""
    rig["dispatchers"] = [_disp("F", 0x1000, arg_count=-1, distinct_inputs=0)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert bp.poll_and_promote()["promoted"] == []
    assert "no input-diversity data" in capsys.readouterr().out


def test_missing_arg_count_fails_closed(rig):
    d = _disp("F", 0x1000)
    del d["arg_count"]
    rig["dispatchers"] = [d]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert bp.poll_and_promote()["promoted"] == []


# --- the ITEMS_GetItemDataByte45 case (live, 2026-07-29) --------------------

def test_refutes_a_function_with_no_registry_row(rig):
    """Found live: ITEMS_GetItemDataByte45 diverged 2,620 times while holding
    CONF_LIVE in Ghidra, but had NO registry row -- the loop `continue`d before
    refutation, so a falsified rung survived. Ghidra is the source of truth, so
    a missing mirror row must not protect a broken reimpl."""
    rig["dispatchers"] = [_disp("ITEMS_GetItemDataByte45", 0x237c0,
                                hits=8857, divergences=2620, distinct_inputs=128)]
    rig["rows"] = []                      # no mirror row at all
    rig["ghidra_rung"] = "CONF_LIVE"      # ...but Ghidra holds a rung
    out = bp.poll_and_promote()
    assert len(out["refuted"]) == 1
    assert out["refuted"][0]["from"] == "CONF_LIVE"
    assert any(d["tags"] == conf_ladder.CONF_REFUTED for d in _added(rig))


def test_registry_lookup_survives_a_ghidra_rename(rig):
    """The mirror stores the name at proof time; Ghidra renames drift from it.
    Keying by (name, address) silently missed -- key by ADDRESS only."""
    rig["dispatchers"] = [_disp("ITEMS_GetItemDataByte45", 0x1000)]
    rig["rows"] = [_row("ITEMS_GetItemDataInvPage", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert len(out["promoted"]) == 1, "address-keyed lookup should still match"


def test_ghidra_rung_wins_over_a_stale_mirror(rig):
    """Registry says CONF_LIVE, Ghidra says CONF_BATTLETESTED -- the refutation
    must record what was actually falsified."""
    rig["dispatchers"] = [_disp("F", 0x1000, divergences=3)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000), conf="CONF_LIVE")]
    rig["ghidra_rung"] = "CONF_BATTLETESTED"
    out = bp.poll_and_promote()
    assert out["refuted"][0]["from"] == "CONF_BATTLETESTED"


# --- multi-bridge: per-dispatcher module attribution -----------------------

def test_module_field_selects_the_image_base(rig):
    """D2Debugger's multi-bridge tags each dispatcher with its patch module.
    Applying one base to a mixed list would resolve D2Client offsets inside
    D2Common -- the wrong-binary class again."""
    rig["dispatchers"] = [
        _disp("Common1", 0x1000, module="D2Common.dll"),
        _disp("Client1", 0xB150, module="D2Client.dll"),
    ]
    rig["rows"] = [_row("Common1", hex(ADDR_COMMON + 0x1000)),
                   _row("Client1", hex(ADDR_CLIENT + 0xB150))]
    out = bp.poll_and_promote()
    assert len(out["promoted"]) == 2
    progs = {d["program"]: d["function"] for d in _added(rig)}
    assert progs["D2Common.dll"] == hex(ADDR_COMMON + 0x1000)
    assert progs["D2Client.dll"] == hex(ADDR_CLIENT + 0xB150)


def test_unknown_module_is_skipped_not_misresolved(rig, capsys):
    rig["dispatchers"] = [_disp("X", 0x1000, module="Fog.dll")]
    rig["rows"] = [_row("X", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert out["ok"] is True and out["promoted"] == []
    assert "no known image base" in capsys.readouterr().out


def test_missing_module_falls_back_to_the_program_arg(rig):
    """An older oracle emits a flat list with no attribution."""
    d = _disp("F", 0x1000)
    assert "module" not in d
    rig["dispatchers"] = [d]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert len(bp.poll_and_promote(program="D2Common.dll")["promoted"]) == 1


# --- saturation-based promotion (2026-07-29) --------------------------------

def _seed_mark(state, addr, distinct, at_hits, module="D2Common.dll",
               sessions=99, last_hits=0, counted=True):
    """Pre-record a watermark, as if earlier polls had seen `distinct` at
    `at_hits`. The promoter RESETS the watermark whenever distinct changes, so a
    store with no prior entry looks like a first observation and correctly
    restarts the saturation clock. `sessions` defaults high so tests that are
    not about the multi-session gate aren't blocked by it."""
    state["marks"][f"{module}:{addr}"] = {
        "distinct": distinct, "at_hits": at_hits,
        "saturated_sessions": sessions, "last_hits": last_hits,
        "counted_this_session": counted}


def _sat_row(name, addr, conf="CONF_LIVE", **kw):
    return _row(name, addr, conf)


def test_saturated_small_domain_promotes(rig):
    """GetItemQualityStringId's real case: 3 distinct, plateaued. Fresh calls
    across the whole Necro skill tree added no new input, so 3 IS full
    reachable coverage."""
    import conf_ladder
    hits = 5000
    addr = hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("QualityMapper", 0x1000, hits=hits,
                                distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("QualityMapper", addr)]
    _seed_mark(rig, addr, 3, hits - conf_ladder.SATURATION_HITS)
    assert len(bp.poll_and_promote()["promoted"]) == 1


def test_not_yet_saturated_does_not_promote(rig):
    """Still finding new inputs recently -> flat floor still applies."""
    import conf_ladder
    hits = 5000
    addr = hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("QualityMapper", 0x1000, hits=hits,
                                distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("QualityMapper", addr)]
    _seed_mark(rig, addr, 3, hits - (conf_ladder.SATURATION_HITS - 1))
    assert bp.poll_and_promote()["promoted"] == []


def test_saturation_records_its_basis_in_the_conf_record(rig):
    """The rung must be auditable: it promoted on exhausted-input evidence, not
    on meeting the flat floor."""
    import conf_ladder
    hits = 5000
    addr = hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("QualityMapper", 0x1000, hits=hits,
                                distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("QualityMapper", addr)]
    _seed_mark(rig, addr, 3, hits - conf_ladder.SATURATION_HITS)
    bp.poll_and_promote()
    props = [d for p, d in rig["writes"] if p == "/set_property"]
    assert props and "saturated@3" in props[0]["value"]
    assert "sessions" in props[0]["value"]


def test_watermark_resets_when_a_new_input_appears(rig):
    """The saturation clock must RESET on a new distinct input."""
    addr = hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("F", 0x1000, hits=4000, distinct_inputs=5, arg_count=1)]
    rig["rows"] = [_sat_row("F", addr)]
    _seed_mark(rig, addr, 4, 100)          # previously saw 4 inputs
    bp.poll_and_promote()
    m = rig["marks"][f"D2Common.dll:{addr}"]
    assert m["distinct"] == 5 and m["at_hits"] == 4000


def test_saturation_does_not_bypass_volume(rig):
    addr = hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("QualityMapper", 0x1000, hits=999,
                                distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("QualityMapper", addr)]
    _seed_mark(rig, addr, 3, 0)
    assert bp.poll_and_promote()["promoted"] == []


def test_promotion_creates_a_missing_mirror_row(rig):
    """The registry MIRRORS Ghidra. A function that reached its rung via the
    static oracle has no record_proof row; blocking promotion on that would
    permanently strand it (live case: GetItemQualityStringId, CONF_VECTORS in
    Ghidra, zero registry rows)."""
    import conf_ladder
    hits = 5000
    rig["dispatchers"] = [_disp("Orphan", 0x1000, hits=hits,
                                distinct_inputs=30, arg_count=1)]
    rig["rows"] = []                       # no mirror row at all
    rig["ghidra_rung"] = "CONF_VECTORS"    # ...but Ghidra holds a real rung
    out = bp.poll_and_promote()
    assert len(out["promoted"]) == 1
    assert any(r["name"] == "Orphan" and r["conf"] == "CONF_BATTLETESTED"
               for r in rig["rows"]), "mirror row should have been created"


def test_promotion_respects_ghidra_rung_over_absent_mirror(rig):
    """Already CONF_SHIPPED in Ghidra with no mirror row -> must not 'promote'
    backwards to CONF_BATTLETESTED."""
    rig["dispatchers"] = [_disp("Orphan", 0x1000, hits=5000,
                                distinct_inputs=30, arg_count=1)]
    rig["rows"] = []
    rig["ghidra_rung"] = "CONF_SHIPPED"
    assert bp.poll_and_promote()["promoted"] == []


# --- multi-session saturation (2026-07-29) ----------------------------------

def test_single_session_saturation_does_not_promote(rig, capsys):
    """ITEMS_GetUltraOrBaseCode promoted on 3.46M calls / 4 distinct from ONE
    session. Saturation there proves the paths THAT session exercised were
    exhausted -- not that another act/class/difficulty passes the same set."""
    import conf_ladder
    hits, addr = 5000, hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("Q", 0x1000, hits=hits, distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("Q", addr)]
    _seed_mark(rig, addr, 3, hits - conf_ladder.SATURATION_HITS,
               sessions=1, last_hits=hits)
    assert bp.poll_and_promote()["promoted"] == []
    assert "1/2 session" in capsys.readouterr().out


def test_two_session_saturation_promotes(rig):
    import conf_ladder
    hits, addr = 5000, hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("Q", 0x1000, hits=hits, distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("Q", addr)]
    _seed_mark(rig, addr, 3, hits - conf_ladder.SATURATION_HITS,
               sessions=2, last_hits=hits)
    assert len(bp.poll_and_promote()["promoted"]) == 1


def test_hit_count_dropping_marks_a_new_session(rig):
    """Counters are process-static and restart at 0 on relaunch, so a hit count
    that went DOWN is the only reliable new-session signal."""
    addr = hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("Q", 0x1000, hits=50, distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("Q", addr)]
    _seed_mark(rig, addr, 3, 4000, sessions=1, last_hits=9000, counted=True)
    bp.poll_and_promote()
    m = rig["marks"][f"D2Common.dll:{addr}"]
    assert m["counted_this_session"] is False, "new session must be re-countable"
    assert m["at_hits"] == 50, "watermark restarts from the new session's counter"


def test_each_session_counts_at_most_once(rig):
    """Polling repeatedly inside one session must not inflate the count."""
    import conf_ladder
    hits, addr = 5000, hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("Q", 0x1000, hits=hits, distinct_inputs=3, arg_count=1)]
    rig["rows"] = [_sat_row("Q", addr)]
    _seed_mark(rig, addr, 3, hits - conf_ladder.SATURATION_HITS,
               sessions=0, last_hits=hits, counted=False)
    for _ in range(5):
        bp.poll_and_promote()
    assert rig["marks"][f"D2Common.dll:{addr}"]["saturated_sessions"] == 1


def test_a_new_input_breaks_saturation_for_this_session(rig):
    """A fresh distinct value means the space was NOT exhausted after all."""
    import conf_ladder
    hits, addr = 5000, hex(ADDR_COMMON + 0x1000)
    rig["dispatchers"] = [_disp("Q", 0x1000, hits=hits, distinct_inputs=4, arg_count=1)]
    rig["rows"] = [_sat_row("Q", addr)]
    _seed_mark(rig, addr, 3, hits - conf_ladder.SATURATION_HITS,
               sessions=1, last_hits=hits, counted=True)
    bp.poll_and_promote()
    m = rig["marks"][f"D2Common.dll:{addr}"]
    assert m["counted_this_session"] is False
    assert m["at_hits"] == hits, "saturation clock restarts from the new input"


# --- module name is not a program name --------------------------------------
# A dispatcher reports the LIVE module name; every Ghidra write passes that as
# `program`. For D2's DLLs the two coincide, and five call sites open-coded that
# assumption. It stops holding for SGD2FreeRes-GDI: the stale 2023 upstream build
# already owns the program name `SGD2FreeRes.dll`, and `switch_program` matches
# by name -- so an unmapped write lands on the wrong binary.

ADDR_SGD2FR = 0x10000000


def _programs_written(state):
    return {d.get("program") for _, d in state["writes"]}


def test_module_name_maps_to_the_ghidra_program_name():
    assert bp.ghidra_program_for("SGD2FreeRes.dll") == "SGD2FreeRes-GDI.dll"


def test_unmapped_modules_resolve_to_themselves():
    """Identity is the right default -- D2's DLLs import under their own names."""
    for m in ("D2Common.dll", "D2Client.dll", "Fog.dll"):
        assert bp.ghidra_program_for(m) == m


def test_sgd2freeres_promotion_targets_the_lab_program_not_the_stale_import(rig):
    """The whole point: the GDI fork's rung must not be tagged onto the 2023 build."""
    addr = hex(ADDR_SGD2FR + 0x1000)
    rig["dispatchers"] = [_disp("PatchApply", 0x1000, module="SGD2FreeRes.dll")]
    rig["rows"] = [{"name": "PatchApply", "address": addr, "conf": "CONF_LIVE",
                    "program": "SGD2FreeRes-GDI.dll"}]
    bp.poll_and_promote(program="SGD2FreeRes.dll")

    written = _programs_written(rig)
    assert "SGD2FreeRes-GDI.dll" in written
    assert "SGD2FreeRes.dll" not in written, (
        "wrote to the stale 2023 upstream program -- the wrong-binary failure class")


def test_sgd2freeres_refutation_also_targets_the_lab_program(rig):
    """Refutation is the more dangerous direction: it TAKES A TAG AWAY."""
    addr = hex(ADDR_SGD2FR + 0x2000)
    rig["dispatchers"] = [_disp("PatchApply", 0x2000, module="SGD2FreeRes.dll",
                                divergences=7)]
    rig["rows"] = [{"name": "PatchApply", "address": addr, "conf": "CONF_BATTLETESTED",
                    "program": "SGD2FreeRes-GDI.dll"}]
    bp.poll_and_promote(program="SGD2FreeRes.dll")

    written = _programs_written(rig)
    assert written, "a divergence must produce a write"
    assert "SGD2FreeRes.dll" not in written, (
        "removed a tag from the stale 2023 program instead of the lab program")


def test_sgd2freeres_offsets_resolve_against_its_own_base(rig):
    """Its Ghidra base is the PE preferred base, not the live 0x6cfb0000."""
    assert bp.IMAGE_BASES["SGD2FreeRes.dll"] == 0x10000000
    rig["dispatchers"] = [_disp("PatchApply", 0x1234, module="SGD2FreeRes.dll")]
    rig["rows"] = [{"name": "PatchApply", "address": hex(ADDR_SGD2FR + 0x1234),
                    "conf": "CONF_LIVE", "program": "SGD2FreeRes-GDI.dll"}]
    bp.poll_and_promote(program="SGD2FreeRes.dll")
    assert any(int(str(d["function"]), 16) == ADDR_SGD2FR + 0x1234
               for _, d in rig["writes"] if "function" in d)


# --- low-frequency evidence -------------------------------------------------
# MEASURED 2026-08-05. CLIENT_SetWorldView (SGD2FreeRes) fires exactly twice
# during process startup and never again -- identical across 3 launches, and
# unchanged by a full world load and 46,000 rendered frames. It agrees with its
# reimplementation on every call it will ever make, and it can never reach the
# 1,000-call volume bar.
#
# conf_ladder has carried is_low_frequency/low_frequency_status/
# effective_volume_floor since that bar was first questioned, with a comment
# stating the evidence "now accumulates in the logs instead of being invisible".
# It did not: all three were called from NOWHERE, nothing recorded per-session
# hit counts, and a below-bar function fell through the gate in total silence.
# An exemption that can never be calibrated is a dead branch, not a deferred
# decision.

def test_below_bar_function_reports_low_frequency(rig, capsys):
    rig["dispatchers"] = [_disp("StartupOnly", 0x1000, hits=2, distinct_inputs=1)]
    rig["rows"] = [_row("StartupOnly", hex(ADDR_COMMON + 0x1000))]
    for _ in range(conf_ladder.LOW_FREQUENCY_MIN_SESSIONS_TO_CLASSIFY):
        bp.poll_and_promote()
        rig["dispatchers"][0]["hits"] = 0        # relaunch: counters reset
        bp.poll_and_promote()
        rig["dispatchers"][0]["hits"] = 2
    assert "LOW-FREQUENCY" in capsys.readouterr().out


def test_reporting_is_not_a_promotion_path(rig):
    """The whole point of the report is that it grants nothing today."""
    rig["dispatchers"] = [_disp("StartupOnly", 0x1000, hits=2, distinct_inputs=1)]
    rig["rows"] = [_row("StartupOnly", hex(ADDR_COMMON + 0x1000))]
    for _ in range(6):
        out = bp.poll_and_promote()
        rig["dispatchers"][0]["hits"] = 0
        bp.poll_and_promote()
        rig["dispatchers"][0]["hits"] = 2
    assert out["promoted"] == []
    assert _added(rig) == []


def test_sessions_and_peak_hits_are_recorded(rig):
    """The two numbers the exemption needs, neither of which existed before."""
    rig["dispatchers"] = [_disp("StartupOnly", 0x1000, hits=2, distinct_inputs=1)]
    rig["rows"] = [_row("StartupOnly", hex(ADDR_COMMON + 0x1000))]
    bp.poll_and_promote()
    rig["dispatchers"][0]["hits"] = 0          # session 2
    bp.poll_and_promote()
    rig["dispatchers"][0]["hits"] = 2
    bp.poll_and_promote()
    m = [v for k, v in rig["marks"].items() if k.endswith("1000")]
    assert m, rig["marks"].keys()
    assert m[0]["sessions_observed"] == 2
    assert m[0]["max_hits_session"] == 2


def test_peak_is_the_largest_session_not_the_latest(rig):
    """A quiet session must not erase evidence that the function CAN go higher --
    the exemption turns on the ceiling, not on the most recent playthrough."""
    rig["dispatchers"] = [_disp("Occasional", 0x1000, hits=40, distinct_inputs=3)]
    rig["rows"] = [_row("Occasional", hex(ADDR_COMMON + 0x1000))]
    bp.poll_and_promote()
    rig["dispatchers"][0]["hits"] = 1          # relaunch, barely exercised
    bp.poll_and_promote()
    m = [v for k, v in rig["marks"].items() if k.endswith("1000")][0]
    assert m["max_hits_session"] == 40


def test_one_quiet_session_is_not_enough_to_classify(rig, capsys):
    """One session says more about the playthrough than about the function."""
    rig["dispatchers"] = [_disp("Unknown", 0x1000, hits=2, distinct_inputs=1)]
    rig["rows"] = [_row("Unknown", hex(ADDR_COMMON + 0x1000))]
    bp.poll_and_promote()
    assert "LOW-FREQUENCY" not in capsys.readouterr().out


def test_a_diverging_function_is_never_called_low_frequency(rig, capsys):
    """Rarity is not evidence of correctness; a refuted function must not be
    dressed up as a promotion candidate waiting on a bar."""
    rig["dispatchers"] = [_disp("Bad", 0x1000, hits=2, distinct_inputs=1, divergences=3)]
    rig["rows"] = [_row("Bad", hex(ADDR_COMMON + 0x1000))]
    for _ in range(4):
        bp.poll_and_promote()
        rig["dispatchers"][0]["hits"] = 0
        bp.poll_and_promote()
        rig["dispatchers"][0]["hits"] = 2
    assert "LOW-FREQUENCY" not in capsys.readouterr().out


# --- the canonical gate actually gates --------------------------------------
# Found by value_ledger 2026-08-06: `conf_ladder.meets_promotion_bar` -- the one
# function that says whether anything may reach CONF_BATTLETESTED -- had 19 test
# references and ZERO production references. This module re-implemented the
# volume half inline, so the low-frequency exemption could never fire however it
# was calibrated: the code that promotes never asked. Two implementations of one
# rule is the documented cause of several bugs in this codebase.

def test_promotion_consults_the_canonical_gate(rig, monkeypatch):
    """If meets_promotion_bar says no, nothing promotes -- even when the raw
    numbers would have passed the old inline check."""
    monkeypatch.setattr(conf_ladder, "meets_promotion_bar",
                        lambda *a, **k: False)
    rig["dispatchers"] = [_disp("F", 0x1000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert out["promoted"] == []


def test_the_canonical_gate_is_what_lets_it_through(rig, monkeypatch):
    seen = {}

    def spy(rung, calls, distinct_inputs, **kw):
        seen["called"] = True
        return True

    monkeypatch.setattr(conf_ladder, "meets_promotion_bar", spy)
    rig["dispatchers"] = [_disp("F", 0x1000)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote()
    assert seen.get("called") and len(out["promoted"]) == 1


def test_an_explicit_override_relaxes_but_the_default_path_does_not(rig):
    """An operator lowering --min-distinct must still work. Folding that floor
    into the canonical call would let the canonical gate overrule a deliberate
    override and kill it without a word."""
    rig["dispatchers"] = [_disp("F", 0x1000, distinct_inputs=3)]
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    assert bp.poll_and_promote()["promoted"] == []          # default bar refuses
    rig["rows"] = [_row("F", hex(ADDR_COMMON + 0x1000))]
    out = bp.poll_and_promote(min_distinct=2)               # operator relaxes it
    assert len(out["promoted"]) == 1
