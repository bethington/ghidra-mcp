"""The harness itself, proven before anything is asserted through it.

A fake backend that quietly returns nothing makes every downstream test pass
for the wrong reason. These checks fail loudly if the fake stopped being
wired in, so the rest of the tier can be trusted.
"""

from __future__ import annotations

import fake_ghidra as fg


def test_app_builds_without_ghidra_or_a_browser(harness):
    r = harness.get("/")
    assert r.status_code == 200
    assert b"<html" in r.data.lower()


def test_the_fake_backend_is_actually_being_used(harness):
    # `/matrix` goes through conformance_dashboard, i.e. through the patched
    # transport. (`/coverage` deliberately does not -- it reads OpenD2's
    # committed @PD2S12 markers off disk, not Ghidra.)
    harness.json("/api/conformance/matrix")
    assert harness.ghidra_corpus.calls, (
        "no call reached FakeGhidra -- conformance_dashboard._get is not patched, "
        "so this tier is silently talking to the operator's real Ghidra (or to "
        "nothing at all)."
    )


def test_monitors_are_fakes_and_were_started(harness):
    assert harness.oracle.started, "OracleHealthMonitor.start() never ran"
    assert harness.ghidra.started, "GhidraHealthMonitor.start() never ran"


def test_corpus_arithmetic_is_what_the_tests_assume(harness):
    """Guard the fixture's own numbers.

    Every assertion in this tier is anchored on these, so a corpus edit that
    changes them should fail HERE with a clear message rather than as eleven
    confusing failures elsewhere.
    """
    corpus = harness.ghidra_corpus
    assert len(corpus.functions) == fg.N_FUNCTIONS
    assert len(corpus.tags["LIB_CRT"]) == fg.N_LIBRARY
    assert corpus.expected_evaluated == 28
    assert corpus.expected_untriaged == fg.N_IN_SCOPE - 28 == 12


def test_sandbox_paths_are_all_under_tmp(harness):
    for key in ("STATE_FILE", "QUEUE_FILE", "LOG_FILE"):
        path = harness.app.config[key]
        assert str(harness.sandbox) in str(path), (
            f"{key} points at {path}, outside the sandbox at {harness.sandbox}"
        )
