"""Plates must not describe compiler-generated machinery as behaviour.

MEASURED 2026-08-06 against the original source of a binary we compile
ourselves. Of the plates that correctly identified their function, ZERO were
free of invented claims -- and one cause dominated: the decompiler shows the
compiled form of ordinary C++ language features, and the pipeline wrote them up
as algorithm steps.

The clearest case, judged cold AND warm with the same result:

    void UnloadCelFile(CelFile* f) { UnloadCelFile_1_00((CelFile_1_00*)f); }

documented as "lazy-loads and dispatches the GDI UnloadCelFile API under SEH and
TLS-gated reference counting", with five steps about TLS blocks, SRW locks and a
dispatch table. Every one of those is the compiler's, not the author's. The
`_tls_index` + SRW lock + InitOnce + `__onexit` combination IS a function-local
static; SEH frames and scope tables are C++ exception handling; vector
constructor/destructor iterators are ordinary object construction.

Two prompts specify the plate format and BOTH must carry the rule -- a rule in
one is a rule the other path ignores, which is this codebase's most repeated
defect shape (see feedback_two_writers_one_field).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# fun-doc on sys.path even though this file only reads text: the shared conftest
# fixture imports event_log, which lives there.
_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

_PROMPTS = _FUNDOC / "prompts"
_FILES = ("step-comments.md", "fix-plate-comment.md")


def _flat(name):
    """Prompt text with whitespace collapsed.

    These files are hard-wrapped, so a phrase like "lazily initialised on first
    call" spans a newline. Substring-matching the raw text fails on prose that
    is entirely correct -- the test would be asserting the line width, not the
    instruction.
    """
    import re
    return re.sub(r"\s+", " ", (_PROMPTS / name).read_text(encoding="utf-8")).lower()


@pytest.mark.parametrize("name", _FILES)
def test_the_prompt_exists(name):
    assert (_PROMPTS / name).exists(), f"{name} missing -- plate format is specified here"


@pytest.mark.parametrize("name", _FILES)
def test_every_plate_prompt_forbids_compiler_scaffolding(name):
    """A rule in one prompt is a rule the other path ignores."""
    src = _flat(name)
    assert "compiler-generated" in src or "compiler's" in src, (
        f"{name} no longer tells the model that compiler machinery is not behaviour")


@pytest.mark.parametrize("name", _FILES)
def test_the_specific_artefacts_are_named(name):
    """Naming them matters: 'be concise' did not prevent five steps about SRW
    locks. The model needs to know WHICH constructs are the compiler's."""
    src = _flat(name)
    for artefact in ("seh", "cookie", "_tls_index", "srw", "vftable"):
        assert artefact in src, f"{name} does not name {artefact!r} as scaffolding"


@pytest.mark.parametrize("name", _FILES)
def test_the_function_local_static_translation_is_given(name):
    """The TLS+SRW+InitOnce+__onexit cluster is the single most misread pattern
    in the measured corpus, and it has a one-line correct rendering."""
    src = _flat(name)
    assert "function-local static" in src
    assert "lazily initialised on first call" in src


@pytest.mark.parametrize("name", _FILES)
def test_it_says_what_to_do_when_nothing_is_left(name):
    """Removing the scaffolding from a three-line forwarder leaves one step. A
    rule that only says 'do not' invites padding it back with something else."""
    src = _flat(name)
    assert "one step, write one step" in src


def test_the_measured_case_is_recorded_in_the_prompt():
    """The evidence travels with the instruction -- a bare rule gets softened by
    the next person who edits it and cannot see why it was worth stating."""
    src = _flat("step-comments.md")
    assert "unloadcelfile" in src and "2026-08-06" in src
