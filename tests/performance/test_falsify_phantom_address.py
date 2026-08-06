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


def bundle(plate, disasm=REAL_DISASM, address="6fb09980"):
    return {"name": "HandleSaveAndExitDialogConfirm", "address": address,
            "program": "/Mods/PD2-S12/D2Client.dll", "plate": plate,
            "disasm_text": disasm}


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


def test_the_check_is_registered_but_disabled_pending_calibration():
    """Two measured rounds against the same 400-function slice: 29 findings then
    12, with the survivors still dominated by cross-module addresses and nearby
    code labels. Registered and available via --enable; not run by default until
    it has the module range and a code-vs-data test."""
    assert "phantom_address" in falsify.ALL_CHECKS
    assert "phantom_address" in falsify.DEFAULT_DISABLED


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
    assert run({"name": "F", "plate": REAL_PLATE, "disasm_text": ""}) == []


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


def test_without_the_function_list_it_does_not_guess():
    """No list supplied -> the routine-address exclusion cannot apply. Noisier,
    but never wrong in the consequential direction."""
    b = bundle("Mirrors the logic at 0x6fab12b0.", address="6fab1300")
    assert len(run(b)) == 1


def test_the_function_list_does_not_hide_a_real_data_global():
    b = bundle("Clears g_pSaveExitDialog (0x6fbcc994) on confirm.")
    b["function_addresses"] = {"6fab12b0", "6fb09980"}
    assert run(b)[0].detail["phantom_addresses"] == ["6fbcc994"]
