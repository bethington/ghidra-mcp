"""Guard that CI actually fires on the branches this project works on.

Why this exists
---------------
On 2026-08-04 `dev` was made the working branch AND the repository's default
branch. Both CI workflows still listed only ``main`` (plus a ``develop`` that
nothing pushes to), so every push to the branch where all work now happens ran
**zero tests and zero code scanning**. Nothing failed. Nothing warned. The first
signal would have been a red `main` at merge time, long after the commit that
broke it -- which is the most expensive moment to find out.

A workflow that does not run cannot fail, so the absence of CI is invisible to
CI by construction. That is precisely the shape of bug that needs an offline
test rather than a convention.

What is deliberately NOT asserted
---------------------------------
* The exact branch list. Branches come and go; requiring an exact set makes this
  test a chore that gets edited to match reality instead of checking it.
* Release workflows, which trigger on tags rather than branches.

Scorecard used to be excluded here too, on the reasoning that it scores the
repo's *published* posture and is "intentionally main-only". That reasoning was
right about the intent and wrong about the mechanism: ``scorecard-action``
refuses to run on anything but the repository's **default branch**, hard-failing
with ``validating options: only the default branch main is supported``. So its
push trigger is not a preference, it is a constraint -- and the constraint has
now been violated in both directions. The default moved ``main`` -> ``dev``
while the trigger said ``main`` (3 failures), and later moved back to ``main``
while the trigger said ``dev``: every one of the 8 most recent scorecard runs
failed in 13 seconds. The scheduled runs follow the default branch
automatically and passed throughout, so the badge stayed green and the failures
read as noise. It is asserted now.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# The repository's default branch. scorecard-action accepts no other push
# trigger. Cross-checked against git's own `origin/HEAD` below wherever that
# is resolvable, so this constant cannot quietly go stale on a dev machine.
DEFAULT_BRANCH = "main"

# Branches that must be covered by the test + code-scanning workflows. `main` is
# the release branch; `dev` is where the work happens and is the default branch,
# so it is the one whose coverage gap is silent.
REQUIRED_BRANCHES = ("main", "dev")

# Workflows that gate correctness and must therefore see every working branch.
GATING_WORKFLOWS = ("tests.yml", "codeql.yml")


def _load(name: str) -> dict:
    path = WORKFLOWS / name
    assert path.is_file(), f"{name} is missing from {WORKFLOWS}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    """Return the workflow's `on:` block.

    YAML 1.1 resolves a bare ``on`` key to the BOOLEAN ``True``, not the string
    ``"on"`` -- so ``doc["on"]`` raises KeyError on a perfectly valid workflow
    and a naive version of this test passes by never checking anything. Accept
    whichever key the parser produced.
    """
    for key in (True, "on", "On", "ON"):
        if key in doc:
            return doc[key]
    raise AssertionError(f"workflow has no `on:` block; keys were {list(doc)}")


@pytest.mark.parametrize("workflow", GATING_WORKFLOWS)
@pytest.mark.parametrize("event", ["push", "pull_request"])
@pytest.mark.parametrize("branch", REQUIRED_BRANCHES)
def test_gating_workflow_triggers_on_working_branches(workflow, event, branch):
    """tests.yml and codeql.yml must fire on push AND pull_request for main+dev."""
    on = _triggers(_load(workflow))
    assert event in on, (
        f"{workflow} has no `{event}:` trigger, so changes reaching a branch "
        f"that way are never checked."
    )
    branches = (on[event] or {}).get("branches")
    assert branches, (
        f"{workflow}'s `{event}:` trigger has no `branches:` filter. That is "
        f"not automatically wrong -- an unfiltered trigger fires on every "
        f"branch -- but this project filters deliberately, so an empty filter "
        f"here is far more likely to be an editing accident than a decision."
    )
    assert branch in branches, (
        f"{workflow} does not run on `{branch}` (push/pull_request branches: "
        f"{branches}). Work pushed to `{branch}` would run no {workflow} checks "
        f"at all, and the gap is invisible: a workflow that never runs never "
        f"reports a failure."
    )


def test_scorecard_pushes_only_on_the_default_branch():
    """scorecard-action hard-fails on any other branch.

    Not a style rule. The action validates this itself and exits with
    ``validating options: only the default branch main is supported``. A push
    trigger on anything else is a run that cannot succeed -- and because the
    *scheduled* runs follow the default branch automatically and keep passing,
    the badge stays green while every push run goes red, which reads as noise
    rather than as a misconfiguration.
    """
    on = _triggers(_load("scorecard.yml"))
    branches = (on.get("push") or {}).get("branches")
    assert branches == [DEFAULT_BRANCH], (
        f"scorecard.yml pushes on {branches}, but scorecard-action only runs "
        f"on the default branch ({DEFAULT_BRANCH!r}). Every run on any other "
        f"branch fails in seconds with 'only the default branch "
        f"{DEFAULT_BRANCH} is supported'."
    )


def test_default_branch_constant_matches_git():
    """Keep DEFAULT_BRANCH honest wherever git can answer.

    The constant above is the one thing in this file not derived from the thing
    it checks, and it has been wrong before -- twice, in opposite directions.
    `origin/HEAD` is not always populated (a fresh CI checkout usually has no
    remote HEAD ref), so this skips rather than fails when git cannot say; a
    test that fails on an environment detail teaches people to ignore it.
    """
    try:
        resolved = subprocess.run(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("origin/HEAD is not resolvable in this checkout")

    actual = resolved.rsplit("/", 1)[-1]
    assert actual == DEFAULT_BRANCH, (
        f"git says this repository's default branch is {actual!r}, but "
        f"DEFAULT_BRANCH here is {DEFAULT_BRANCH!r}. Move both, and move "
        f"scorecard.yml's push trigger with them -- scorecard-action fails on "
        f"anything but the default branch."
    )


def test_build_status_gate_requires_every_blocking_job():
    """The `build-status` summary job must depend on every blocking job.

    `build-status` is what a branch-protection rule keys on. A blocking job left
    out of its `needs:` list still shows in the run, but can fail without
    turning the overall status red -- so protection silently stops protecting.

    Advisory jobs are excluded on purpose: they end in `|| true` and are meant
    to surface drift without blocking.
    """
    doc = _load("tests.yml")
    jobs = doc["jobs"]
    needs = set(jobs["build-status"]["needs"])

    advisory = {
        name for name, spec in jobs.items()
        if "advisory" in str(spec.get("name", "")).lower()
    }
    blocking = set(jobs) - advisory - {"build-status"}

    missing = sorted(blocking - needs)
    assert not missing, (
        f"these blocking jobs are absent from build-status.needs: {missing}. "
        f"A branch-protection rule keyed on build-status would go green while "
        f"they fail."
    )


def test_build_status_script_checks_every_job_it_depends_on():
    """Every job in `needs:` must also be tested in the summary shell script.

    Adding a job to `needs:` alone is not enough -- it makes the job *run* and
    makes `build-status` wait for it, but the reported status comes from an
    explicit `needs.<job>.result` comparison in the run script. A job listed in
    `needs:` but absent from that script is waited on and then ignored, which
    looks exactly like coverage from the outside.
    """
    doc = _load("tests.yml")
    build_status = doc["jobs"]["build-status"]
    script = "\n".join(
        str(step.get("run", "")) for step in build_status.get("steps", [])
    )
    unchecked = sorted(
        job for job in build_status["needs"]
        if f"needs.{job}.result" not in script
    )
    assert not unchecked, (
        f"build-status waits for {unchecked} but never compares "
        f"needs.<job>.result for them, so their failures do not affect the "
        f"reported build status."
    )
