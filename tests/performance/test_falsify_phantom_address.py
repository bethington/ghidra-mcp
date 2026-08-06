"""F8: a plate citing an absolute address the function never touches.

MEASURED ORIGIN, 2026-08-05. D2Client's HandleSaveAndExitDialogConfirm carries an
AI-written plate naming `g_pSaveExitDialog (0x6fbcc994)` and
`g_dwGameModeState (0x6fbcd5ac)`. Its disassembly writes `0x6fbc77e8` and
`0x6fbcc2cc`. Both cited addresses are fabricated -- and D2Debugger had copied
one into a hardcoded constant, disabling a guard its own comment describes as
protecting against refcount corruption.

Every existing falsify check is structural in a different dimension (convention,
arity, return width, parameter counts, verb agreement), so none of them could
see it. This one is equally mechanical: an address a plate names either appears
among the addresses the instructions reference, or it does not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

falsify = pytest.importorskip("falsify")

# The real disassembly of HandleSaveAndExitDialogConfirm, trimmed.
REAL_DISASM = """
6fb0999b | MOV EAX,0x3
6fb099a0 | MOV [0x6fbcc2cc],EAX
6fb099b4 | MOV dword ptr [0x6fbc77e8],0x0
6fb099d1 | CALL 0x6fac43e0
"""

# The real plate, with both fabricated addresses.
REAL_PLATE = """Handles the "Save and Exit" dialog confirmation button callback.

Related Globals:
  - g_dwGameModeState (0x6fbcd5ac): Game state machine, set to 3 on exit
  - g_pSaveExitDialog (0x6fbcc994): Dialog window pointer, cleared on confirm
"""


# D2Client's real non-executable segments (from /list_segments):
#   .rdata 6fb7e000-6fb8afff,  .data 6fb8b000-6fbd4adb
# .text (6fab1000-6fb7dfff) is deliberately absent: a cited CODE address is a
# routine reference, not a false global claim.
DATA_RANGES = ((0x6fb7e000, 0x6fb8afff), (0x6fb8b000, 0x6fbd4adb))


def bundle(plate, disasm=REAL_DISASM, address="6fb09980", data_ranges=DATA_RANGES):
    return {"name": "HandleSaveAndExitDialogConfirm", "address": address,
            "program": "/Mods/PD2-S12/D2Client.dll", "plate": plate,
            "disasm_text": disasm, "data_ranges": data_ranges}


def run(b):
    return falsify.check_phantom_address(b)


# --- the measured case -------------------------------------------------------

def test_catches_the_two_fabricated_addresses():
    f = run(bundle(REAL_PLATE))
    assert len(f) == 1
    got = set(f[0].detail["phantom_addresses"])
    assert got == {"6fbcd5ac", "6fbcc994"}


def test_the_real_addresses_are_not_flagged():
    plate = """Sets the game mode state.

Related Globals:
  - g_dwGameModeState (0x6fbcc2cc): set to 3 on exit
  - g_pSaveExitDialog (0x6fbc77e8): cleared on confirm
"""
    assert run(bundle(plate)) == []


def test_it_is_tier_2_not_tier_1():
    """Sound but unmeasured at corpus scale; tier 1 has to be earned."""
    f = run(bundle(REAL_PLATE))
    assert f[0].tier == falsify.TIER_REVIEW


def test_the_check_is_enabled_after_three_calibration_rounds():
    """29 -> 12 -> 4 findings on the same 400-function slice, with 3 of 3 round-3
    survivors verified genuine against the disassembly."""
    assert "phantom_address" in falsify.ALL_CHECKS
    assert "phantom_address" not in falsify.DEFAULT_DISABLED


# --- false-positive guards ---------------------------------------------------

def test_struct_offsets_are_never_matched():
    """`+0x14` and `0x5c` are layout, not addresses."""
    plate = """Initialises two rectangles.

Structure Layout:
  +0x00  | 4  | dwFlags  | bit 0 = initialised
  +0x04  | 16 | rcPanel  | panel rectangle
  +0x14  | 16 | rcWorld  | world rectangle
  Sets dialog type at offset +0x5c to 1.
"""
    assert run(bundle(plate)) == []


def test_small_constants_and_string_ids_are_not_matched():
    plate = 'Adds title text (string ID 0xFCA) and a button (string ID 0xD49).'
    assert run(bundle(plate)) == []


def test_caller_sections_are_exempt():
    """A function never references the things that CALL it."""
    plate = """Does a thing.

Called By:
  - FUN_6fac2430: dialog creation function that adds this as a handler
"""
    assert run(bundle(plate)) == []


def test_an_address_present_as_an_immediate_passes():
    """A documented constant that appears anywhere in the disassembly is fine."""
    plate = "Compares against the sentinel 0x6fac43e0."
    assert run(bundle(plate)) == []


def test_the_functions_own_address_is_citable():
    plate = "HandleSaveAndExitDialogConfirm @ 0x6fb09980 -- the confirm callback."
    assert run(bundle(plate, address="6fb09980")) == []


# --- abstains rather than guessing -------------------------------------------

def test_no_disassembly_means_no_finding():
    assert run({"name": "F", "plate": REAL_PLATE, "disasm_text": "",
                "data_ranges": DATA_RANGES}) == []


def test_without_segment_ranges_it_abstains_entirely():
    """Cannot tell a data global from another module's address or a code label,
    so it reports nothing rather than falling back to a looser rule."""
    assert run(bundle(REAL_PLATE, data_ranges=())) == []


def test_no_plate_means_no_finding():
    assert run(bundle("")) == []


def test_a_plate_with_no_addresses_is_silent():
    assert run(bundle("Initialises the viewport rectangles and sets a flag.")) == []


# --- calibration (measured against the 400-function D2Client sweep) -----------
# That sweep produced 29 findings; a 6-sample review found at least 4 false.
# Both exclusions below kill a MEASURED false class rather than a supposed one.

def test_mask_shaped_constants_are_excluded():
    """0xffffffff / 0x0fffffff / 0x100001 have 6-8 hex digits and are not addresses.
    A real global sits near the code that touches it."""
    for mask in ("0xffffffff", "0x0fffffff", "0x100001", "0x7fffffff"):
        plate = f"Clamps the value against {mask}."
        assert run(bundle(plate)) == [], mask


def test_a_nearby_global_is_still_caught():
    """The exclusion must not swallow the real case: 0x6fbcc994 is ~0xC3000
    from the function at 0x6fb09980 -- well inside the same module."""
    f = run(bundle("Clears g_pSaveExitDialog (0x6fbcc994) on confirm."))
    assert len(f) == 1 and f[0].detail["phantom_addresses"] == ["6fbcc994"]


def test_addresses_of_other_functions_are_excluded_when_known():
    """A plate naming a related ROUTINE is documentation, not a false claim."""
    b = bundle("Mirrors the logic at 0x6fab12b0.", address="6fab1300")
    b["function_addresses"] = {"6fab12b0", "6fab1300"}
    assert run(b) == []


def test_the_segment_rule_supersedes_the_function_list():
    """Round 2 needed the function list to exclude a routine address, and was
    noisier without it. Round 3's data-segment rule excludes it either way,
    because 0x6fab12b0 is in .text -- so the finding no longer depends on the
    caller supplying a list at all."""
    b = bundle("Mirrors the logic at 0x6fab12b0.", address="6fab1300")
    assert run(b) == []                       # no function list supplied
    b["function_addresses"] = {"6fab12b0"}
    assert run(b) == []                       # and with one


def test_the_function_list_does_not_hide_a_real_data_global():
    b = bundle("Clears g_pSaveExitDialog (0x6fbcc994) on confirm.")
    b["function_addresses"] = {"6fab12b0", "6fb09980"}
    assert run(b)[0].detail["phantom_addresses"] == ["6fbcc994"]


# --- round 3: data-segment containment (the principled calibration) ----------
# Measured survivors of round 2 that this eliminates, all from the same slice.

def test_another_modules_address_is_excluded():
    """0x6fc36ad4 is D2Game, 0x6ff7e33f is Fog -- outside every D2Client segment."""
    for foreign in ("0x6fc36ad4", "0x6ff7e33f", "0x6fbfe368"):
        assert run(bundle(f"Related: g_thing ({foreign}).")) == [], foreign


def test_a_code_address_is_excluded():
    """__sopen at 0x6faba467 cites 0x6faba473 -- twelve bytes on, inside .text.
    A mid-function label is not a global, and the function list cannot see it."""
    for code in ("0x6faba473", "0x6fb7ddb5", "0x6fab12b0"):
        assert run(bundle(f"Mirrors the logic at {code}.")) == [], code


def test_a_data_address_the_code_never_touches_is_still_caught():
    """The measured defect: both fabricated globals live in .data."""
    f = run(bundle(REAL_PLATE))
    assert set(f[0].detail["phantom_addresses"]) == {"6fbcd5ac", "6fbcc994"}


def test_an_rdata_address_counts_as_data():
    f = run(bundle("Reads the table at 0x6fb7f2b8."))
    assert f and f[0].detail["phantom_addresses"] == ["6fb7f2b8"]
