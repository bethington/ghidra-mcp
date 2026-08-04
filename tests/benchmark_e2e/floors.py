"""Pass/fail rules for an undocumented -> documented run over Benchmark.dll.

The assertions are split by DETERMINISM, because conflating the two halves
is what makes a quality gate untrustworthy.

MECHANICAL floors are absolutes. A correct fun-doc produces them on every
run regardless of which model answered or how well: a name was applied, it
follows the naming convention, the plate carries its required sections, the
parameters are typed, no run ended in a timeout, and no hand-authored
function was claimed as library code. If any of these fails, fun-doc is
broken -- not unlucky. They are asserted as hard equalities.

SEMANTIC quality is statistical. `scorer.score_function` compares generated
documentation against `ground_truth.json` and the result moves with model
temperature, provider load and prompt phrasing. Gating it on an absolute bar
means either a bar so low it never fires or a suite that cries wolf; gating
it on a DELTA against the committed `runs/latest.json` catches a real
regression while tolerating noise. Both a mean-drop and a worst-single-
function-drop are checked, because a mean can absorb one function
collapsing.

Why the LIB_CRT control is a mechanical floor and not a nice-to-have
-------------------------------------------------------------------
`LIB_CRT` makes the selector skip a function PERMANENTLY. A false positive
does not degrade a score -- it removes the function from the corpus
silently, forever. `Benchmark.dll` is the only binary in the project with
ground truth about which functions are hand-authored, so it is the only
place this can be measured rather than believed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# --------------------------------------------------------------------------
# tolerances
# --------------------------------------------------------------------------

#: How far the mean quality may fall below the committed baseline before the
#: run is called a regression. `runs/latest.json` records quality on a 0-1
#: scale, so 0.03 is three points on the 0-100 scale the CLAUDE.md guidance
#: is written in.
MEAN_DROP_TOLERANCE = 0.03

#: A single function may move more than the mean -- one function is a small
#: sample -- but a collapse is a regression even when the mean absorbs it.
PER_FUNCTION_DROP_TOLERANCE = 0.10

#: Plate sections `batch_set_comments` warns about when missing.
REQUIRED_PLATE_SECTIONS = ("Algorithm", "Parameters", "Returns")

#: Terminal provider outcomes. A run ending in any of these means the
#: pipeline failed, which is never acceptable on a 9-function binary that
#: fits comfortably inside every tier budget.
FATAL_RESULT_CODES = ("failed", "blocked", "stopped")

#: Ghidra's default naming. A function still carrying one of these was not
#: documented, whatever else the run reported.
_DEFAULT_NAME_RE = re.compile(r"^(FUN_|SUB_|thunk_FUN_|Ordinal_|entry$)", re.I)

#: An UPPERCASE_ module prefix (`DATATBLS_`, `D2COMMON_`), which
#: `NamingConventions` accepts and validates separately from the body.
_MODULE_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9]*_")

#: Capital-initiated segments of a PascalCase body.
_SEGMENT_RE = re.compile(r"[A-Z][a-z0-9]*")

#: `NamingConventions` warns on short names; below this a name carries no
#: verb and no object, which is the thing the rule is actually about.
_MIN_NAME_LEN = 6

#: A type Ghidra never resolved. `set_variable_type` rejects undefined ->
#: undefined for the same reason.
_UNDEFINED_TYPE_RE = re.compile(r"\bundefined\d*\b", re.I)


@dataclass
class Violation:
    """One failed floor, named so the failure message is actionable."""

    floor: str
    function: str
    detail: str

    def __str__(self) -> str:  # pragma: no cover - formatting only
        return f"[{self.floor}] {self.function}: {self.detail}"


@dataclass
class FloorReport:
    mechanical: list[Violation] = field(default_factory=list)
    semantic: list[Violation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mechanical and not self.semantic

    def format(self) -> str:
        lines = []
        if self.mechanical:
            lines.append("MECHANICAL floors failed (fun-doc is broken, not unlucky):")
            lines += [f"  {v}" for v in self.mechanical]
        if self.semantic:
            lines.append("SEMANTIC quality regressed against runs/latest.json:")
            lines += [f"  {v}" for v in self.semantic]
        return "\n".join(lines) or "all floors passed"


# --------------------------------------------------------------------------
# mechanical floors
# --------------------------------------------------------------------------


def check_name_applied(fn_name: str, captured: dict) -> list[Violation]:
    name = (captured.get("name") or "").strip()
    if not name:
        return [Violation("name-applied", fn_name, "no name in the captured state")]
    if _DEFAULT_NAME_RE.match(name):
        return [
            Violation(
                "name-applied",
                fn_name,
                f"still carries the Ghidra default name {name!r} -- the run "
                f"reported success but nothing was written",
            )
        ]
    return []


def check_name_convention(fn_name: str, captured: dict) -> list[Violation]:
    """PascalCase with a verb, per `NamingConventions.java`.

    Checked here rather than trusted from the tool layer on purpose: the
    point of this run is to prove the tool layer is still enforcing it.
    """
    name = (captured.get("name") or "").strip()
    if not name or _DEFAULT_NAME_RE.match(name):
        return []  # already reported by check_name_applied

    body = _MODULE_PREFIX_RE.sub("", name, count=1)

    def _fail(why: str) -> list[Violation]:
        return [
            Violation(
                "name-convention",
                fn_name,
                f"{name!r} {why}. NamingConventions should have warned and the "
                f"worker should have corrected it.",
            )
        ]

    if not body or not body[0].isupper():
        return _fail("does not start with a capital (PascalCase, optionally "
                     "behind an UPPERCASE_ module prefix)")
    if not body.isalnum():
        return _fail("contains a separator; PascalCase carries no spaces or "
                     "underscores outside the module prefix")
    # An all-caps body ("CRC", "ABC") satisfies a naive PascalCase regex
    # because `[A-Z][a-z0-9]*` happily matches a bare capital. Requiring a
    # lowercase letter somewhere is what actually distinguishes PascalCase
    # from an acronym, while still admitting embedded acronyms like
    # `ParseHTTPHeader`.
    if not any(c.islower() for c in body):
        return _fail("is all caps, not PascalCase")
    if len(body) < _MIN_NAME_LEN:
        return _fail(f"is shorter than {_MIN_NAME_LEN} characters, so it "
                     f"cannot carry both a verb and an object")
    if len(_SEGMENT_RE.findall(body)) < 2:
        return _fail("is a single word; the convention is Verb + Object")
    return []


def check_plate_sections(fn_name: str, captured: dict) -> list[Violation]:
    plate = captured.get("plate") or ""
    if not plate.strip():
        return [Violation("plate-present", fn_name, "no plate comment was written")]
    missing = [s for s in REQUIRED_PLATE_SECTIONS if s.lower() not in plate.lower()]
    if missing:
        return [
            Violation(
                "plate-sections",
                fn_name,
                f"plate is missing {', '.join(missing)} -- "
                f"batch_set_comments warns on exactly this",
            )
        ]
    return []


def check_parameters_typed(fn_name: str, captured: dict) -> list[Violation]:
    out = []
    for param in captured.get("parameters") or []:
        ptype = str(param.get("type") or "")
        if _UNDEFINED_TYPE_RE.search(ptype):
            out.append(
                Violation(
                    "params-typed",
                    fn_name,
                    f"parameter {param.get('name')!r} left as {ptype!r}; "
                    f"an undefined type means the type work was skipped",
                )
            )
    return out


def check_result_code(fn_name: str, result: str | None) -> list[Violation]:
    if result in FATAL_RESULT_CODES:
        return [
            Violation(
                "run-completed",
                fn_name,
                f"the run ended {result!r}. On a 9-function binary well "
                f"inside every tier budget this is a pipeline failure, not a "
                f"hard function.",
            )
        ]
    return []


def check_no_authored_function_claimed_as_library(
    authored: Iterable[str], library_claims: Iterable[str]
) -> list[Violation]:
    """The positive control.

    `LIB_CRT` makes the selector skip a function permanently, so a false
    positive deletes hand-written code from the corpus with no score signal
    and no error. Zero of Benchmark.dll's authored functions may ever be
    claimed.
    """
    claimed = sorted(set(authored) & set(library_claims))
    return [
        Violation(
            "library-control",
            name,
            "claimed as library code. LIB_CRT makes the selector skip a "
            "function PERMANENTLY -- a false positive silently removes "
            "hand-written code from the corpus.",
        )
        for name in claimed
    ]


# --------------------------------------------------------------------------
# semantic delta
# --------------------------------------------------------------------------


def _quality(entry: dict) -> float | None:
    """Pull the quality out of a run JSON's per-function entry.

    The shape is ``{function: {provider: {quality: float, ...}}}``; when
    several providers ran, the best is the one being compared, because that
    is what the operator would ship.
    """
    if not isinstance(entry, dict):
        return None
    scores = [
        v["quality"]
        for v in entry.values()
        if isinstance(v, dict) and isinstance(v.get("quality"), (int, float))
    ]
    return max(scores) if scores else None


def check_semantic_delta(
    run: dict[str, Any],
    baseline: dict[str, Any] | None,
    *,
    mean_tolerance: float = MEAN_DROP_TOLERANCE,
    per_function_tolerance: float = PER_FUNCTION_DROP_TOLERANCE,
) -> list[Violation]:
    """Compare a run's quality against the committed baseline.

    Returns no violations when there is no baseline: the FIRST run on a new
    machine has nothing to regress against, and inventing an absolute bar
    there would just be the pure-thresholds option under another name.
    """
    if not baseline:
        return []

    out: list[Violation] = []

    run_mean = (run.get("aggregate") or {}).get("quality_mean")
    base_mean = (baseline.get("aggregate") or {}).get("quality_mean")
    if isinstance(run_mean, (int, float)) and isinstance(base_mean, (int, float)):
        if run_mean < base_mean - mean_tolerance:
            out.append(
                Violation(
                    "semantic-mean",
                    "<aggregate>",
                    f"mean quality {run_mean:.3f} is below the baseline "
                    f"{base_mean:.3f} by more than {mean_tolerance:.3f}",
                )
            )

    base_fns = baseline.get("functions") or {}
    run_fns = run.get("functions") or {}
    for name, base_entry in base_fns.items():
        base_q = _quality(base_entry)
        run_q = _quality(run_fns.get(name, {}))
        if base_q is None:
            continue
        if run_q is None:
            out.append(
                Violation(
                    "semantic-missing",
                    name,
                    "scored in the baseline but absent from this run -- the "
                    "function was dropped, not merely documented worse",
                )
            )
            continue
        if run_q < base_q - per_function_tolerance:
            out.append(
                Violation(
                    "semantic-function",
                    name,
                    f"quality {run_q:.3f} vs baseline {base_q:.3f} "
                    f"(drop > {per_function_tolerance:.3f})",
                )
            )
    return out


# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------


#: Per-function mechanical checks, by name, so a caller can select a subset.
PER_FUNCTION_CHECKS = {
    "name-applied": check_name_applied,
    "name-convention": check_name_convention,
    "plate-sections": check_plate_sections,
    "params-typed": check_parameters_typed,
}

#: Checks that assert *fun-doc's own conventions* on its output, and are
#: therefore meaningless against the mock fixtures.
#:
#: The `--mock` captures under `benchmark/fixtures/` are HAND-AUTHORED
#: artifacts, not fun-doc output -- their plates are prose paragraphs with no
#: Algorithm/Parameters/Returns headings at all. Asserting the convention
#: against them would test the fixture author, not the pipeline, and the only
#: way to make it pass would be to rewrite the very files `--compare` uses as
#: its baseline. The mock tier therefore proves the PLUMBING (capture ->
#: scorer -> aggregate -> floors); the real tier proves the CONVENTIONS.
CONVENTION_CHECKS = frozenset({"name-convention", "plate-sections", "params-typed"})


def evaluate(
    run: dict[str, Any],
    baseline: dict[str, Any] | None = None,
    *,
    authored: Iterable[str] = (),
    library_claims: Iterable[str] = (),
    result_codes: dict[str, str] | None = None,
    skip_checks: Iterable[str] = (),
) -> FloorReport:
    """Apply every floor to a completed run and return the whole picture.

    Deliberately collects ALL violations rather than failing on the first:
    when a change breaks documentation, knowing it broke six functions the
    same way is the diagnosis, and stopping at the first hides it.

    ``skip_checks`` names per-function checks to omit -- pass
    ``CONVENTION_CHECKS`` on the mock tier, for the reason documented above.
    """
    report = FloorReport()
    result_codes = result_codes or {}
    skip = set(skip_checks)
    active = {n: fn for n, fn in PER_FUNCTION_CHECKS.items() if n not in skip}

    for fn_name, entry in (run.get("functions") or {}).items():
        for provider_result in (entry or {}).values():
            if not isinstance(provider_result, dict):
                continue
            captured = provider_result.get("captured") or {}
            if not captured:
                continue
            for check in active.values():
                report.mechanical += check(fn_name, captured)
        report.mechanical += check_result_code(fn_name, result_codes.get(fn_name))

    report.mechanical += check_no_authored_function_claimed_as_library(
        authored, library_claims
    )
    report.semantic += check_semantic_delta(run, baseline)
    return report
