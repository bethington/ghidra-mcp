"""BSim identification: same source, different build.

Byte-exact matching (`crt_identify.py`) identifies library code with zero false
positives and is exhausted at 5,475 of 70,558 corpus functions (7.8%). What it
cannot reach is one class: a function compiled from identical source by a
different compiler, at a different optimisation level, or linked into a
different layout. Call displacements move when layout moves, and masking cannot
repair that. BSim matches normalised p-code features instead of bytes.

    Ghidra (BSim query)  ->  JSONL dump  ->  THIS MODULE (decide + write)

`scripts/bsim/Analyze_BSimIdentifyDump.java` does the querying and makes no
decisions; it dumps every candidate above a deliberately low floor. Every
threshold and the whole write path live here, in Python, where they are
testable without a live Ghidra and re-tunable without an 8-minute re-query.

CALIBRATION (Phase 0, 2026-08-03) -- these numbers are measured, not chosen
=========================================================================

OpenSSL 1.1.1j built with VS2022 17.14 was queried against the shipped PD2
`libcrypto-1_1.dll` built with VS2017 15.9 -- same source, 7 years of toolchain
drift, and BOTH sides carry ground-truth names from authoritative PDBs, so every
verdict could be scored. 8,088 named functions scored writer-centrically.

    sim >= 0.95, signif >= 30, tie => abstain   ->  precision 1.0000, recall 21.8%
                                                    (1,764 writes, 0 wrong)

Three findings that the thresholds encode, each of which cost precision when
violated in the calibration run:

1.  ABSTAIN IS MANDATORY, NOT A REFINEMENT. Applying the best-similarity
    candidate without the tie rule peaks at ~86% precision no matter how the
    floors are set. Similarity-1.0 ties carrying DIFFERENT names are everywhere
    (OpenSSL's `*_it` accessors; D2Common's `_aulldiv` / `_aulldvrm`). This is
    the same lesson `crt_identify` paid for when 141 OpenSSL functions all
    "matched" `__ld12tod`.

2.  SIGNIFICANCE IS THE DISCRIMINATOR, NOT SIMILARITY. Naive precision FALLS as
    the similarity floor rises, because tiny degenerate bodies match at sim 1.0
    while carrying almost no information. Significance scales with how much
    function there is to be similar about.

3.  THE FLOOR CAME FROM A NEGATIVE CONTROL, NOT FROM TASTE -- exactly as
    `STRONG_INFORMATIVE_BYTES = 20` did. Querying D2Common.dll (Blizzard code,
    no relationship to OpenSSL whatsoever) against the OpenSSL index produced
    two false writes at significance 20.7, and Benchmark.dll one at 23.8.
    SIGNIF_FLOOR = 30 clears the observed false-positive ceiling with margin.
    At that floor D2Common's only surviving write is `__allmul` -> `_allmul`,
    which is CORRECT (a hand-written CRT helper genuinely shared between them).

Re-run the calibration whenever a new reference corpus is added; a corpus built
from a much closer toolchain (binkw32's VC6 SP5 vs our SP6) should sit higher on
the curve, and one built from a much more distant one may need higher floors.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

GHIDRA_URL = os.environ.get("GHIDRA_URL", "http://127.0.0.1:8089").rstrip("/")

# --------------------------------------------------------------------------
# Calibrated thresholds -- see the module docstring for how each was measured
# --------------------------------------------------------------------------

#: Cosine-ish similarity of the LSH vectors. Necessary but NOT sufficient: on
#: its own it is the WEAKER of the two signals (see finding 2 above).
SIM_FLOOR = 0.95

#: BSim significance. The real discriminator. 30 clears the highest
#: false-positive significance observed across both negative controls (23.8)
#: with margin. Do not lower it without re-running the controls.
SIGNIF_FLOOR = 30.0

#: Body bytes required before a NAME is written. Measured, not guessed: a
#: 16-byte floor costs 1 of 1,764 correct writes (0.1%) on the calibration set,
#: so it is nearly free insurance against the degenerate-tiny-body failure mode
#: that produced both negative-control false positives. Same value as
#: `crt_identify.MIN_CONFIDENT_LEN`, for the same reason.
MIN_CONFIDENT_LEN = 16

#: Similarities are floats from a distance computation; compare with slack.
SIM_EPS = 1e-6

BOOKMARK_CATEGORY = "BSim Identify"

#: Fallback tag when the caller supplies no reference-exe -> tag mapping.
#: Deliberately generic: a `LIB_*` tag makes the fun-doc selector skip a
#: function PERMANENTLY, so it must never imply more provenance than we have.
DEFAULT_TAG = "LIB_BSIM"

#: Ghidra's own placeholder names -- the only ones safe to overwrite, and the
#: only ones that must never be COPIED out of the reference index.
DEFAULT_NAME = re.compile(r"^(FUN_|SUB_|LAB_|thunk_FUN_|Ordinal_|entry$|switch)")

#: Compiler/linker-local labels. `crt_identify` learned this the expensive way:
#: 25 of a claimed "+29" FID win were `$L#####` labels that would have been
#: written as function names.
LINKER_LOCAL = re.compile(r"^[$?][A-Za-z]*\d+$")


def is_default_name(name: str) -> bool:
    """True for Ghidra placeholders -- safe to overwrite, never worth copying."""
    return bool(DEFAULT_NAME.match(name or ""))


def _canon(name: str) -> str:
    """Normalise decoration so `_foo`, `foo` and `_foo@12` compare equal.

    Leading-underscore and `@N` stdcall decoration differ between builds of the
    same source; treating them as different names would manufacture ties.
    """
    return re.sub(r"@\d+$", "", (name or "").lstrip("_@")).lower()


# --------------------------------------------------------------------------
# The verdict
# --------------------------------------------------------------------------

@dataclass
class BSimMatch:
    """One query function's verdict. `writable` is the only gate that matters."""

    address: str
    current_name: str
    match_name: Optional[str]          # None when ambiguous -- nothing is written
    similarity: float
    significance: float
    body_size: int
    source_exe: str
    program: str = ""
    tag: str = DEFAULT_TAG
    ambiguous: bool = False
    candidates: List[str] = field(default_factory=list)
    #: Set when the top similarity tier contained an UNNAMED reference function.
    #: Reported separately from a name tie because it means something different:
    #: the closest thing in the index has no name to give.
    unnamed_top: bool = False

    @property
    def weak(self) -> bool:
        """Below either calibrated floor."""
        return self.similarity < SIM_FLOOR or self.significance < SIGNIF_FLOOR

    @property
    def writable(self) -> bool:
        """May ANYTHING be written to Ghidra for this match?

        Ambiguity and weakness both mean the evidence does not identify a
        function, and an unidentified function must not be tagged: a `LIB_*`
        tag makes the fun-doc selector skip it forever. Reported, never written
        -- the JSON report is the review surface.
        """
        return not self.ambiguous and not self.unnamed_top and not self.weak

    @property
    def confident_name(self) -> bool:
        """May this match's NAME be written into Ghidra?"""
        return bool(self.writable
                    and self.match_name
                    and self.body_size >= MIN_CONFIDENT_LEN
                    and not is_default_name(self.match_name)
                    and not LINKER_LOCAL.match(self.match_name))

    @property
    def bucket(self) -> str:
        """Which report bucket this falls in -- drives both report and writes."""
        # unnamed_top is reported FIRST because it is the more specific
        # diagnosis and the more actionable one: it says the reference index
        # lacks a name for the closest match (fix the corpus), where
        # `ambiguous` says the function genuinely has look-alikes (fix nothing).
        # An unnamed top tier also sets `ambiguous`, since no name survives the
        # named-candidate filter -- so this order is load-bearing, not cosmetic.
        if self.unnamed_top:
            return "unnamed_top_match"
        if self.ambiguous:
            return "ambiguous"
        if self.weak:
            return "below_threshold"
        if not self.confident_name:
            return "too_short" if self.body_size < MIN_CONFIDENT_LEN else "unusable_name"
        if _canon(self.current_name) == _canon(self.match_name or ""):
            return "already_correct"
        if not is_default_name(self.current_name):
            return "documented_preserved"
        return "writable"


# --------------------------------------------------------------------------
# The decision -- pure, so it is testable without Ghidra or a BSim database
# --------------------------------------------------------------------------

def decide(row: dict, program: str = "", tags: Optional[Dict[str, str]] = None,
           sim_floor: float = SIM_FLOOR,
           signif_floor: float = SIGNIF_FLOOR) -> Optional[BSimMatch]:
    """Turn one dump row into a verdict, or None when nothing cleared the floor.

    The order here is load-bearing:

      1. Apply BOTH floors first. Everything below them is noise and must not
         influence the tie test -- otherwise a junk candidate manufactures an
         abstention and suppresses a good write.
      2. Look at the top similarity tier of ALL surviving candidates, named or
         not. An unnamed candidate sitting at the top means the closest thing in
         the index carries no name; a named candidate below it may well be a
         different function. That is ambiguity, so abstain.
      3. Among named candidates in that tier, require exactly ONE distinct
         canonical name. More than one and the evidence does not single out an
         answer -- this is the rule that moves precision from ~86% to 1.0000.
      4. Break the remaining tie (same name, several reference addresses) by
         significance, which is the stronger signal.
    """
    tags = tags or {}
    matches = row.get("matches") or []
    elig = [m for m in matches
            if float(m.get("sim", 0.0)) >= sim_floor
            and float(m.get("signif", 0.0)) >= signif_floor]
    if not elig:
        return None

    best_all = max(float(m["sim"]) for m in elig)
    tier = [m for m in elig if float(m["sim"]) >= best_all - SIM_EPS]
    unnamed_top = any(is_default_name(m.get("name", "")) for m in tier)

    named = [m for m in tier if not is_default_name(m.get("name", ""))]
    distinct = {_canon(m["name"]) for m in named}

    # Report the strongest named candidate even when abstaining, so the review
    # surface shows WHAT was rejected rather than just that something was.
    winner = max(named or tier, key=lambda m: (float(m.get("signif", 0.0)),
                                               float(m.get("sim", 0.0))))
    ambiguous = len(distinct) != 1

    return BSimMatch(
        address=str(row.get("query_address", "")).replace("0x", ""),
        current_name=row.get("query_function", "") or "",
        match_name=None if ambiguous else winner.get("name"),
        similarity=float(winner.get("sim", 0.0)),
        significance=float(winner.get("signif", 0.0)),
        body_size=int(row.get("body_size", 0)),
        source_exe=winner.get("exe", "") or "",
        program=program,
        tag=tags.get(winner.get("exe", ""), DEFAULT_TAG),
        ambiguous=ambiguous,
        candidates=sorted({m.get("name", "") for m in tier}),
        unnamed_top=unnamed_top,
    )


def load_dump(path: str) -> Iterable[dict]:
    """Stream the JSONL dump. Corpus dumps run to tens of MB; do not slurp."""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def identify_from_dump(path: str, program: str,
                       tags: Optional[Dict[str, str]] = None,
                       sim_floor: float = SIM_FLOOR,
                       signif_floor: float = SIGNIF_FLOOR) -> List[BSimMatch]:
    """Every verdict in a dump that cleared the floors (writable or not)."""
    out: List[BSimMatch] = []
    for row in load_dump(path):
        verdict = decide(row, program=program, tags=tags,
                         sim_floor=sim_floor, signif_floor=signif_floor)
        if verdict is not None:
            out.append(verdict)
    return out


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _get(path: str, **params) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=180) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _post(path: str, program: str, body: dict) -> dict:
    # `program` MUST ride as a query parameter, never in the JSON body: a POST
    # without a resolvable `program` query param falls through to the ACTIVE
    # program, which is how a dry run once wrote to the wrong binary.
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode({"program": program})
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _ok(response: dict) -> bool:
    return bool(response.get("success")
                or str(response.get("status", "")).lower() == "success")


# --------------------------------------------------------------------------
# The single writer
# --------------------------------------------------------------------------

def sync_to_ghidra(match: BSimMatch, apply_name: bool = True,
                   rename_documented: bool = False) -> dict:
    """Write one verdict to Ghidra. THE single writer for this module.

    Every lane -- sweep, triage, dashboard -- goes through here, for the same
    reason `crt_identify.sync_to_ghidra` and `falsify.sync_to_ghidra` exist:
    when a second writer grows somewhere else, a fix to one silently misses the
    other. That lesson is already paid for; do not let this module grow a
    second write path.

    Always (for a writable match): the tag plus a durable bookmark. The bookmark
    is the point -- like FID's, it SURVIVES a later rename, so a documentation
    pass that overwrites the name leaves the evidence recoverable rather than
    merely detectable.

    The name is applied only when the match is confident AND the function still
    carries a Ghidra default. Overwriting real documentation is gated behind
    `rename_documented`, because that bucket deserves review, not a sweep.
    """
    result = {"address": match.address, "bucket": match.bucket, "tagged": False,
              "bookmarked": False, "renamed": None, "skipped": None}

    if not match.writable:
        result["skipped"] = match.bucket
        return result

    program = match.program
    result["tagged"] = _ok(_post("/add_function_tag", program,
                                 {"function": match.address, "tags": match.tag}))

    result["bookmarked"] = _ok(_post("/set_bookmark", program, {
        "address": match.address,
        "category": BOOKMARK_CATEGORY,
        "comment": (f"BSim match - {match.match_name} from {match.source_exe} "
                    f"[sim {match.similarity:.4f}, signif {match.significance:.1f}, "
                    f"{match.body_size}b]")}))

    if not apply_name or not match.confident_name:
        result["skipped"] = ("name-not-requested" if not apply_name
                             else match.bucket)
        return result

    if _canon(match.current_name) == _canon(match.match_name or ""):
        result["skipped"] = "already_correct"
        return result

    if not is_default_name(match.current_name) and not rename_documented:
        result["skipped"] = "documented_preserved"
        return result

    # strict_mode=false on purpose. NamingConventions is right for code WE
    # author, but these are upstream symbols and are not ours to restyle -- it
    # rejected 66 real OpenSSL names (`X448`, `CMAC_Final`, `OPENSSL_Uplink`)
    # for `missing_specifier` during the PDB recovery pass.
    body = {"old_name": match.address, "new_name": match.match_name,
            "strict_mode": False}
    response = _post("/rename_function", program, body)
    ok = _ok(response)

    if not ok and "already exists at this address" in str(response):
        # Not a real conflict: an analyzer left its own label on the address as
        # a non-primary symbol, so the rename is blocked by the very evidence
        # being applied. Drop the duplicate label, then take the name.
        _post("/delete_label", program,
              {"address": match.address, "name": match.match_name})
        response = _post("/rename_function", program, body)
        ok = _ok(response)

    result["renamed"] = match.match_name if ok else None
    if not ok:
        # Loud, never silent. A best-effort write-back that fails quietly is how
        # the wrong-binary CONF_ bug survived weeks.
        result["error"] = str(response)[:200]
    return result


def sync_all(matches: Sequence[BSimMatch], apply_name: bool = True,
             rename_documented: bool = False) -> List[dict]:
    """Convenience fan-out. Still one writer -- this only loops."""
    return [sync_to_ghidra(m, apply_name=apply_name,
                           rename_documented=rename_documented)
            for m in matches]
