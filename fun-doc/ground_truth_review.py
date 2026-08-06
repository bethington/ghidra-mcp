"""Review a documented function against the ORIGINAL SOURCE it was built from.

WHY THIS EXISTS. Every other quality signal in this project is internal.
`analyze_function_completeness` measures whether documentation is PRESENT --
it is computed FROM the documentation, so no observation about the binary can
lower it. `falsify.py` measures mechanical CONTRADICTION between doc claims and
disassembly facts. Both are real, and both are structurally blind to a
documented function that is coherent, complete, self-consistent, survives every
check -- and describes the wrong thing.

MEASURED, 2026-08-05. The first function taken end-to-end through the vertical
slice was documented as `CLIENT_SetWorldView`, scored well, passed falsify,
passed a live shadow comparison byte-for-byte, and was on its way to
BATTLETESTED. Its real name is `Sgd2fr_D2Client_SetTileCullingBound`: it sets
the draw-window rect and then the tile-culling window, with perspective-mode
compensation. Nothing we had could see that, because nothing we had was
looking at the answer.

SGD2FreeRes-GDI is the subject binary precisely BECAUSE we build it ourselves
and therefore know the code that produced it. Its PDB attributes 661 functions
to our own compilands, with real names and real source on disk. That makes it
the only large ground-truth corpus this project has -- Benchmark.dll has 9
functions. The rule that keeps it valuable: the truth is a MEASURING STICK and
is never written into Ghidra, so the documentation pipeline stays blind and its
output stays scorable.

WHAT THIS SCORES, AND WHAT IT DELIBERATELY DOES NOT

Names are compared SEMANTICALLY, never by string equality. Ground truth here is
`Sgd2fr_D2Client_SetTileCullingBound`, which this project's own
NamingConventions rejects (underscores, no leading verb) -- scoring on the
literal string would penalise the pipeline for obeying the conventions we
require of it. What matters is whether the name identifies the right OPERATION
on the right OBJECT.

Structure is compared exactly, because there the compiler is the authority:
argument count, return width and the size of an out-parameter buffer are facts,
and the reimplementation's ABI depends on them.

Report-only. This writes nothing to Ghidra and nothing to SQL. Its output is
evidence for changing the workflow, which is a human decision.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# --- token-level semantic comparison ----------------------------------------

# Splitting an identifier into concept tokens. Both sides use different casing
# conventions, so casing carries no signal and is discarded.
_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Words that appear in names as scaffolding rather than meaning. A match on
# these is not evidence the pipeline understood anything: every D2 function
# could carry them. Module prefixes are stripped for the same reason -- ours
# are a house convention (CLIENT_), theirs are a vendor one (Sgd2fr_).
_NOISE = {
    "sgd2fr", "sgd2", "client", "d2client", "d2common", "d2game", "d2",
    "fn", "func", "function", "sub", "the", "a", "an", "of", "for", "to",
}

# Verbs that mean the same operation. A pipeline that says "Set" where truth
# says "Update" understood the function; scoring that as a miss would push the
# workflow toward copying vocabulary rather than reading code.
_VERB_SYNONYMS = [
    {"set", "assign", "store", "write", "update", "put"},
    {"get", "read", "fetch", "retrieve", "query", "load"},
    {"init", "initialize", "initialise", "setup", "create", "construct"},
    {"free", "release", "destroy", "delete", "unload", "cleanup", "dispose"},
    {"calc", "calculate", "compute", "derive"},
    {"check", "test", "validate", "verify", "is", "has"},
    {"find", "search", "locate", "lookup"},
    {"draw", "render", "blit", "paint"},
    {"handle", "process", "dispatch"},
]


def tokens(name: str) -> list[str]:
    """Concept tokens of an identifier, with scaffolding removed."""
    raw = [t.lower() for t in _SPLIT.split(name or "") if t]
    return [t for t in raw if t and t not in _NOISE and not t.isdigit()]


def _synonym_class(tok: str):
    for group in _VERB_SYNONYMS:
        if tok in group:
            return frozenset(group)
    return None


def tokens_agree(a: str, b: str) -> bool:
    if a == b:
        return True
    ca, cb = _synonym_class(a), _synonym_class(b)
    if ca is not None and ca == cb:
        return True
    # Substring only when the shorter is a real prefix/suffix of the longer,
    # which catches cull/culling and rect/rectangle without matching on a
    # single shared letter.
    lo, hi = sorted((a, b), key=len)
    return len(lo) >= 4 and lo in hi


@dataclass
class NameVerdict:
    truth: str
    documented: str
    truth_tokens: list[str]
    doc_tokens: list[str]
    matched: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    invented: list[str] = field(default_factory=list)
    context_tokens: list[str] = field(default_factory=list)
    context_matched: list[str] = field(default_factory=list)

    @property
    def context_recall(self) -> float:
        """How much of the namespace/class the name carries. Reported, never
        folded into `recall` -- a stripped binary does not contain it."""
        return (len(self.context_matched) / len(self.context_tokens)
                if self.context_tokens else 0.0)

    @property
    def recall(self) -> float:
        """Share of the truth's concepts the documented name carries."""
        return len(self.matched) / len(self.truth_tokens) if self.truth_tokens else 0.0

    @property
    def verdict(self) -> str:
        if not self.truth_tokens:
            return "unscorable"
        if self.recall >= 0.99 and not self.invented:
            return "correct"
        if self.recall >= 0.5:
            return "partial"
        return "wrong"


# C++ spells a constructor `Class::Class` and a destructor `Class::~Class`, so
# the class name appears TWICE in the truth and the operation has no verb of its
# own. A documented name that says `Class_ctor` is not inventing a concept -- it
# is naming the same thing with the conventional suffix, and it is arguably
# clearer than the truth.
#
# MEASURED 2026-08-06: `GetGlobalBeltRecordPatch_1_09D_ctor` against truth
# `...::GetGlobalBeltRecordPatch_1_09D::GetGlobalBeltRecordPatch_1_09D` scored
# `partial` at recall 1.0, penalised solely for the suffix. A correctly
# identified constructor must not read as a partial miss.
_STRUCTOR_SUFFIXES = {"ctor", "constructor", "dtor", "destructor"}

# A constructor also has no VERB of its own -- `Class::Class` names the class
# twice and nothing else -- so a documented `InitializeFooPatch` is penalised
# for saying what the function does. MEASURED 2026-08-06: five constructors in
# the blind sample scored `partial`, four of them with missed=[] (FULL recall),
# solely for the words below. Constructing and initializing are the same act,
# and these already sit in one _VERB_SYNONYMS group; the constructor simply has
# no token for them to match against.
#
# Scoped to constructors and destructors only. The fifth row genuinely dropped
# "Get" from GetGlobalEquipmentSlotLayoutPatch and correctly stays partial --
# the rule credits the missing verb, not a missing concept.
_STRUCTOR_VERBS = {"initialize", "initialise", "init", "construct", "create",
                   "build", "setup", "make",
                   "destroy", "free", "release", "cleanup", "dispose"}


def _is_structor(truth: str) -> bool:
    """Does the truth name a C++ constructor or destructor?

    Detected from the SHAPE -- a trailing `A::A` or `A::~A` -- rather than from
    a name list, because the class name is arbitrary.
    """
    parts = [p for p in str(truth or "").split("::") if p]
    if len(parts) < 2:
        return False
    last, prev = parts[-1], parts[-2]
    return last == prev or last == "~" + prev


def split_truth(truth: str):
    """(context_tokens, operation_tokens) for a qualified C++ name.

    The final `::` component is the OPERATION -- the verb and object a reader of
    the machine code can actually recover. Everything before it is CONTEXT: the
    namespace and class, which a stripped binary does not carry.

    MEASURED 2026-08-06. Scoring both together penalised the pipeline for
    information nobody could recover: `d2::CelFile_Api::GetCel` demands the
    tokens cel/file/api before a single one about what the function DOES, so a
    perfect reading of the code still scores partial. Reported separately, the
    operation figure says how well the code was read and the context figure says
    how much structure was inferred -- two different abilities that a single
    number conflates.

    For a constructor the last component IS the class name, which is correct:
    naming the class is the operation.
    """
    parts = [p for p in str(truth or "").split("::") if p]
    if not parts:
        return [], []
    return tokens("::".join(parts[:-1])), tokens(parts[-1])


def compare_names(documented: str, truth: str) -> NameVerdict:
    """Semantic comparison. See the module docstring for why not string equality."""
    ctx_tokens, tt = split_truth(truth)
    dt = tokens(documented)
    matched, missed = [], []
    for t in tt:
        if any(tokens_agree(t, d) for d in dt):
            matched.append(t)
        else:
            missed.append(t)
    # Context is scored, but SEPARATELY -- a doc name that also carries the
    # class is better, and one that does not is not wrong about the code.
    ctx_matched = [c for c in ctx_tokens if any(tokens_agree(c, d) for d in dt)]
    # Invention is judged against BOTH: a token echoing the class is not
    # invented, it is just context the operation name did not need.
    all_truth = tt + ctx_tokens
    invented = [d for d in dt if not any(tokens_agree(d, x) for x in all_truth)]
    if _is_structor(truth):
        # The suffix IS the operation the truth expresses by repeating the class
        # name; crediting it is reading the same fact, not relaxing the bar.
        allowed = _STRUCTOR_SUFFIXES | _STRUCTOR_VERBS
        invented = [d for d in invented if d not in allowed]
    return NameVerdict(truth=truth, documented=documented, truth_tokens=tt,
                       doc_tokens=dt, matched=matched, missed=missed,
                       invented=invented, context_tokens=ctx_tokens,
                       context_matched=ctx_matched)


# --- structural comparison ---------------------------------------------------

@dataclass
class StructVerdict:
    field_name: str
    documented: object
    truth: object

    @property
    def agrees(self) -> bool:
        if self.documented is None or self.truth is None:
            return True            # unknown is not a disagreement
        return self.documented == self.truth

    @property
    def scorable(self) -> bool:
        return self.documented is not None and self.truth is not None


def compare_structure(documented: dict, truth: dict) -> list[StructVerdict]:
    """Arg count, return width and out-buffer size are compiler facts.

    Unlike the name, these are compared EXACTLY: the reimplementation's ABI
    depends on them, and a wrong arg count on a callee-cleans convention skews
    ESP and access-violates the game.
    """
    return [StructVerdict(f, documented.get(f), truth.get(f))
            for f in ("arg_count", "ret_bits", "outbuf_bytes", "callconv")]


# --- the review --------------------------------------------------------------

def review_function(documented: dict, truth: dict) -> dict:
    """Score one completed function against the source it was built from.

    `documented` is what the pipeline produced; `truth` is what the PDB and the
    original source say. Both are plain dicts so this stays testable offline
    with no Ghidra, no PDB reader and no network.
    """
    nv = compare_names(documented.get("name", ""), truth.get("name", ""))
    sv = compare_structure(documented, truth)
    scorable = [s for s in sv if s.scorable]
    disagreed = [s for s in scorable if not s.agrees]

    return {
        "address": documented.get("address") or truth.get("address"),
        "name": {
            "documented": nv.documented, "truth": nv.truth,
            "verdict": nv.verdict, "recall": round(nv.recall, 3),
            "matched": nv.matched, "missed": nv.missed, "invented": nv.invented,
        },
        "structure": {
            "verdict": ("agrees" if not disagreed
                        else "disagrees") if scorable else "unscorable",
            "compared": [s.field_name for s in scorable],
            "disagreements": [
                {"field": s.field_name, "documented": s.documented, "truth": s.truth}
                for s in disagreed
            ],
        },
        "source_file": truth.get("source_file"),
        # The headline: a function can be structurally perfect and still be
        # documented as the wrong thing. Both halves have to pass.
        "verdict": ("accurate" if nv.verdict == "correct" and not disagreed
                    else "misnamed" if not disagreed
                    else "structurally_wrong"),
    }


def review_batch(pairs) -> dict:
    """Review many (documented, truth) pairs and summarise.

    The summary is the number that should drive workflow changes: not how many
    functions we documented, but how many we documented CORRECTLY.
    """
    reviews = [review_function(d, t) for d, t in pairs]
    n = len(reviews) or 1
    by_name = {}
    for r in reviews:
        by_name[r["name"]["verdict"]] = by_name.get(r["name"]["verdict"], 0) + 1
    accurate = sum(1 for r in reviews if r["verdict"] == "accurate")
    return {
        "reviewed": len(reviews),
        "accurate": accurate,
        "accuracy": round(accurate / n, 3),
        "name_verdicts": by_name,
        "structurally_wrong": sum(1 for r in reviews
                                  if r["verdict"] == "structurally_wrong"),
        "reviews": reviews,
    }


def load_pdb_truth(path: str | Path) -> dict:
    """Index a pdb_attribute.py dump by Ghidra address (image base applied)."""
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    return {r["rva"]: r for r in rows}
