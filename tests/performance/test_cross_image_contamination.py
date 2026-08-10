"""Tests for the cross-image plate contamination detector.

Every abstention asserted here kills a class that was OBSERVED in the 2026-08-09
census of /Vanilla/1.00/D2Game.dll (745 plated functions, ~44 contaminated).
They are calibration outputs, not stylistic choices -- a test that fails after
someone "simplifies" an abstention is telling you a measured false-positive class
has come back.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

cic = pytest.importorskip("scripts.cross_image_contamination")


# A 0x10000000-based program, like D2Game v1.00.
RANGES = [(0x10000000, 0x100A5FFF)]


def test_fires_on_unattributed_foreign_address():
    """The measured defect: a 0x6F address presented as this function's own."""
    plate = ("Retrieves game server configuration values.\n"
             "Stores g_dwData_1c20 at 0x6fcd1c20 and returns the max game count.")
    hit = cic.check_program_function(plate, RANGES, name="GetGameServerConfig")
    assert hit is not None
    assert "6fcd1c20" in hit["foreign_addresses"]
    assert hit["tier"] == 2
    # Repair must move the name too -- the measured half-fix.
    assert hit["name_derivation_risk"] is True


def test_abstains_on_address_inside_this_program():
    """An in-program address is falsify F8's business, not ours. The two checks
    are complements; overlapping them would double-accuse."""
    plate = "Writes the result to g_dwState at 0x10041c20."
    assert cic.check_program_function(plate, RANGES) is None


def test_abstains_when_a_module_is_named():
    """Measured benign class: BinkBufferGetError thunks in 1.13c D2Game cite
    0x100..... while naming binkw32.dll, which genuinely bases there. An
    ATTRIBUTED foreign address is a legitimate cross-module reference."""
    plate = "Thunk to binkw32.dll's BinkBufferGetError at 0x10004512."
    assert cic.check_program_function(plate, RANGES) is None
    assert cic.check_program_function(
        "Calls Fog.dll ordinal 10021 at 0x6ff7e33f to log.", RANGES) is None


def test_abstains_on_a_repair_note():
    """9 of 47 address-citing plates in the census cite a foreign address only to
    REFUTE it. Counting those re-flags exactly the functions someone already
    fixed, and makes the rate look WORSE after a repair pass than before it."""
    plate = ("Dispatches an MCP message.\n"
             "CORRECTION: the previous plate cited 0x6fcd1c20, which belongs to a "
             "different image base (1.13c) and does not match this code.")
    assert cic.check_program_function(plate, RANGES) is None


def test_abstains_on_thunks():
    plate = "Jumps to the real implementation at 0x6fcd1000."
    assert cic.check_program_function(plate, RANGES, is_thunk=True) is None


def test_abstains_when_ranges_unknown():
    """'Cannot tell' must never become 'passed' -- the CONF_BLOCKED rule."""
    plate = "Stores something at 0x6fcd1c20."
    assert cic.check_program_function(plate, []) is None
    assert cic.check_program_function("", RANGES) is None


def test_ignores_offsets_and_small_constants():
    """Struct offsets and string ids must never be read as addresses, or every
    plate documenting a field layout becomes a finding."""
    plate = "Reads +0x14, masks with 0x5c, and checks string id 0xFCA."
    assert cic.check_program_function(plate, RANGES) is None


def test_caller_sections_are_exempt():
    """A function does not reference the things that call it, so addresses in a
    caller listing are not its claim to get wrong."""
    plate = ("Does the thing.\n"
             "Called By:\n"
             "  0x6fcd2000 SomeCallerInAnotherBuild\n")
    assert cic.check_program_function(plate, RANGES) is None


@pytest.mark.parametrize("plate", [
    "Returns 0xffffffff on failure.",
    "Terminator is 0xdddddddd (TSExplicitList sentinel).",
    "Fills the buffer with 0xcccccccc.",
    "Masks the handle with 0xffff0000.",
    "Compares against 0x7fffffff.",
    "Debug fill 0xbaadf00d indicates uninitialised memory.",
])
def test_abstains_on_masks_and_sentinels(plate):
    """MEASURED: the FIRST live run returned 6 findings and all 6 were this class
    -- 0xffffffff sentinels and 0xdddddddd (Blizzard's TSExplicitList terminator;
    the RTTI reads TSExplicitList<SGAMEDATA, -0x22222223> = 0xDDDDDDDD).
    A mask is outside every segment by definition, so any detector keying on
    'outside every segment' inherits this class and must exclude it."""
    assert cic.check_program_function(plate, RANGES) is None


@pytest.mark.parametrize("v,why", [
    (0xFFFFFFFD, "small negative (-3) as unsigned"),
    (0xFFFFFFE1, "small negative (-31)"),
    (0x19930520, "MSVC EH magic"),
    (0xE06D7363, "MSVC C++ exception code 'msc'"),
    (0x7EFEFEFF, "strlen byte-scan constant"),
    (0x51EB851F, "reciprocal-multiply divisor"),
    (0x20326671, "four printable ASCII bytes -- text, not an address"),
    (0x00100000, "1 MB, below any plausible image base"),
])
def test_round2_constant_families(v, why):
    """ROUND 2 calibration: the full-binary run returned 50 findings and these
    four families accounted for most of them. All are compiler output."""
    assert cic.looks_like_mask(v), why


def test_looks_like_mask_families():
    assert cic.looks_like_mask(0xFFFFFFFF)      # all bytes identical
    assert cic.looks_like_mask(0xDDDDDDDD)
    assert cic.looks_like_mask(0x7FFFFFFF)      # all-ones low run
    assert cic.looks_like_mask(0xFFFF0000)      # all-ones high run
    assert cic.looks_like_mask(0xBAADF00D)      # famous fill
    # Real image-base-shaped addresses must NOT be swallowed.
    assert not cic.looks_like_mask(0x6FCD1C20)
    assert not cic.looks_like_mask(0x10041C20)
    assert not cic.looks_like_mask(0x6FF7E33F)


def test_foreign_addresses_dedupes_and_sorts():
    plate = "0x6fcd1c20 then 0x6fcd1c20 and 0x6fb90000"
    assert cic.foreign_addresses(plate, RANGES) == ["6fb90000", "6fcd1c20"]


def test_summarize_reports_rate_and_base_histogram():
    """The census found contamination clustered by base (6ff2/6ff3/6fdd/6fb9/6f9e),
    which is what showed it came from SEVERAL modules, not just 1.13c D2Game."""
    findings = [
        {"foreign_bases": ["6ff2"]},
        {"foreign_bases": ["6ff2", "6fdd"]},
    ]
    s = cic.summarize(findings, plated_total=100)
    # Deliberately NOT "findings": scan_program merges this dict into a report
    # that already holds the finding LIST under that key, and the first live run
    # clobbered the list with this count. Two writers of one key.
    assert s["findings_count"] == 2
    assert "findings" not in s
    assert s["rate"] == 0.02
    assert s["by_foreign_base"]["6ff2"] == 2
    assert s["by_foreign_base"]["6fdd"] == 1


def test_summarize_handles_zero_plates_without_dividing_by_zero():
    assert cic.summarize([], plated_total=0)["rate"] == 0.0


# --- ROUND 3: corpus containment ------------------------------------------

SIBLING = [(0x6FAB0000, 0x6FF80000)]     # the D2 module band


def test_sibling_containment_keeps_a_real_foreign_address():
    plate = "Stores the flag at 0x6fcd1c20 before returning."
    assert cic.check_program_function(plate, RANGES, sibling_ranges=SIBLING) is not None


def test_sibling_containment_drops_float_and_mask_constants():
    """ROUND 3, the discriminator that ends the constant whack-a-mole. Rounds 1-2
    kept finding new species of compiler constant because 'outside every segment
    of THIS program' lets in every number. Requiring the value to land inside
    ANOTHER BINARY IN THE CORPUS excludes them by construction.
    Measured: round 2 left 18 findings on D2Game v1.00, 4 of them CRT float/mask
    words (0x40000000, 0x7fff8000, 0xff0000, 0xfffffd66); containment removes
    exactly those and keeps all 14 genuine 0x6f... hits."""
    for plate in ("Compares against 0x40000000.",
                  "Masks with 0x7fff8000.",
                  "Uses 0x00ff0000 as a byte mask."):
        assert cic.check_program_function(
            plate, RANGES, sibling_ranges=SIBLING) is None


def test_without_siblings_the_check_is_deliberately_looser():
    """Documented behaviour, not an oversight: with no corpus supplied the check
    still fires so it is usable standalone, but the CLI warns and refuses when
    --corpus-folders resolves to nothing."""
    plate = "Compares against 0x40000000."
    assert cic.check_program_function(plate, RANGES) is not None


@pytest.mark.parametrize("v,why", [
    (0x67452301, "SHA-1/MD5 H0"),
    (0x10325476, "SHA-1/MD5 H2 -- measured FP on Fog.dll ComputeSha1Hash"),
    (0xC3D2E1F0, "SHA-1 H4"),
    (0x5A827999, "SHA-1 round constant K1"),
])
def test_round4_crypto_constants(v, why):
    """ROUND 4: crypto IVs land INSIDE a sibling image range (several PD2-S12
    modules are based at 0x10000000), so corpus containment does not exclude
    them. Containment narrows the constant problem; it does not end it."""
    assert cic.looks_like_mask(v), why
