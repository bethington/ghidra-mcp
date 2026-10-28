"""Branch protection must match what the workflows actually report.

Issue #481: the repo asserts in-repo which checks a branch-protection rule is
expected to key on (``tests/unit/test_ci_workflow_triggers.py``), and GitHub
enforces the rule in a ruleset that lives outside the repository.  Nothing
reconciles the two, so a ruleset can drift away from the repo's expectations
with nothing noticing -- and the drift is invisible from both sides.

This test closes that loop offline.  It reads a checked-in snapshot of the
live rulesets (``tests/ci/required_status_checks.json``, written by
``tools/refresh_branch_protection_snapshot.py``) and checks:

1. every required status check maps to a job the workflows can actually
   report -- a required context that no job produces blocks every PR forever;
2. every blocking job aggregated by ``build-status`` is covered by a required
   check, either directly or through the ``Build Status`` aggregator itself;
3. the default branch is covered by an active ruleset.

(2) is the drift the issue describes.  It is allowlisted in ``KNOWN_DRIFT``
until the ruleset is updated; deleting an entry makes that job's coverage
mandatory, so the allowlist is a ratchet rather than a permanent exception.

Note on the legacy API: ``/repos/{owner}/{repo}/branches/{branch}/protection``
reports "Branch not protected" for ``dev`` even though the ruleset covers it.
That endpoint only knows about classic branch protection; rulesets are a
separate mechanism.  Read the rulesets, not that endpoint.
"""

from __future__ import annotations

import datetime as dt
import itertools
import json
import pathlib

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SNAPSHOT_PATH = REPO_ROOT / "tests" / "ci" / "required_status_checks.json"
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# The aggregator: the summary job that is meant to be the single gate a
# branch-protection rule keys on.  Its `needs:` list and its run script are
# checked by tests/unit/test_ci_workflow_triggers.py.
AGGREGATOR_JOB = "build-status"
AGGREGATOR_CONTEXT = "Build Status"

# Blocking jobs that no required check currently covers.  Each entry is a job
# id from tests.yml with the reason it is not covered yet.  When the ruleset
# starts requiring `Build Status` (or these jobs directly), delete the entry:
# the coverage test then enforces it, and re-adding an entry becomes a
# deliberate, visible act.
KNOWN_DRIFT: dict[str, str] = {
    "python-tests-windows": (
        "not required: `Python Tests (pytest, Windows)` is the only place the "
        "os.name == 'nt' half of the bridge runs, so it can fail without "
        "blocking anything"
    ),
    "offline-http-tier": "not required: `Offline HTTP Tier (no Ghidra)`",
    "markdown-lint": "not required: `Documentation Quality`",
    "pester-tests": "not required: `Pester (ghidra-mcp-setup.ps1)`",
    "code-quality": (
        "advisory by name, gating in effect: the ruff F step inside "
        "`Code Quality` fails the job, and build-status compares "
        "needs.code-quality.result, so the gate only reaches the branch "
        "through `Build Status` -- which nothing currently requires"
    ),
}

SNAPSHOT_STALE_DAYS = 90


def _load_workflows() -> dict:
    workflows = {}
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            workflows[path.name] = yaml.safe_load(handle)
    return workflows


def _matrix_values(matrix: dict) -> list[list[str]] | None:
    """Expand a strategy matrix into the value combinations GitHub reports.

    GitHub names a matrix check ``<job name> (<values>)`` where the values are
    joined by ", " in matrix-key order.  ``include``/``exclude`` entries are
    not modelled: they add or remove whole combinations, and modelling them
    wrongly would make a required context look unreportable.
    """
    if not matrix:
        return [[]]
    keys = [key for key in matrix if key not in ("include", "exclude")]
    if not keys:
        return [[]]
    value_lists = []
    for key in keys:
        values = matrix[key]
        if not isinstance(values, list):
            return None
        value_lists.append([str(value) for value in values])
    return [list(combo) for combo in itertools.product(*value_lists)]


def _reportable_contexts(workflows: dict) -> dict[str, set[str]]:
    """Map job id -> the status-check contexts that job can report."""
    contexts: dict[str, set[str]] = {}
    for doc in workflows.values():
        for job_id, spec in (doc.get("jobs") or {}).items():
            display = spec.get("name") or job_id
            combos = _matrix_values((spec.get("strategy") or {}).get("matrix"))
            if combos is None:
                # A matrix this helper cannot expand: the job may report
                # contexts we cannot predict, so treat it as opaque.
                contexts[job_id] = {display}
                continue
            contexts[job_id] = {
                display if not combo else f"{display} ({', '.join(combo)})"
                for combo in combos
            }
    return contexts


def _tests_workflow() -> dict:
    with (WORKFLOW_DIR / "tests.yml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _snapshot() -> dict:
    if not SNAPSHOT_PATH.exists():
        pytest.fail(
            f"branch protection snapshot is missing: {SNAPSHOT_PATH}\n"
            "Run: python3 tools/refresh_branch_protection_snapshot.py"
        )
    with SNAPSHOT_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _active_rulesets(snapshot: dict) -> list[dict]:
    return [
        ruleset
        for ruleset in snapshot.get("rulesets", [])
        if ruleset.get("enforcement") == "active"
        and ruleset.get("target") == "branch"
    ]


def _required_contexts(snapshot: dict) -> set[str]:
    required: set[str] = set()
    for ruleset in _active_rulesets(snapshot):
        required.update(ruleset.get("required_status_checks") or [])
    return required


def _covers_branch(ruleset: dict, branch: str) -> bool:
    """Does this ruleset apply to ``branch``?"""
    for pattern in ruleset.get("branches") or []:
        if pattern == "~DEFAULT_BRANCH":
            return True
        if pattern == f"refs/heads/{branch}":
            return True
    return False


def test_snapshot_is_parseable_and_names_the_default_branch():
    snapshot = _snapshot()
    assert snapshot.get("repo"), "snapshot does not name the repository"
    assert snapshot.get("default_branch"), "snapshot does not name the default branch"
    assert snapshot.get("rulesets"), "snapshot contains no rulesets"


def test_default_branch_is_protected_by_an_active_ruleset():
    """The working branch must be covered by a ruleset.

    The legacy branch-protection endpoint answers "Branch not protected" for
    `dev` even when a ruleset covers it -- rulesets are a different mechanism
    and the legacy endpoint knows nothing about them.  Read the rulesets.
    """
    snapshot = _snapshot()
    default_branch = snapshot["default_branch"]
    protecting = [
        ruleset
        for ruleset in _active_rulesets(snapshot)
        if _covers_branch(ruleset, default_branch)
    ]
    assert protecting, (
        f"no active branch ruleset covers the default branch "
        f"{default_branch!r}. Rulesets: "
        f"{[(r.get('id'), r.get('name'), r.get('branches')) for r in snapshot.get('rulesets', [])]}"
    )


def test_every_required_check_is_a_context_the_workflows_report():
    """A required context no job produces blocks every PR, forever.

    Required status checks are matched by exact context name.  A matrix leg
    that is renamed, dropped, or added without touching the ruleset makes the
    ruleset name a context that no longer exists -- and the branch then waits
    for a check that will never report.
    """
    snapshot = _snapshot()
    required = _required_contexts(snapshot)
    reportable = set()
    for contexts in _reportable_contexts(_load_workflows()).values():
        reportable.update(contexts)

    unknown = sorted(required - reportable)
    assert not unknown, (
        f"the ruleset requires status checks no workflow reports: {unknown}. "
        f"A required check that never reports blocks every pull request. "
        f"Either the workflow stopped emitting that context or the ruleset is "
        f"stale -- refresh it with "
        f"`python3 tools/refresh_branch_protection_snapshot.py` and fix the "
        f"ruleset."
    )


def test_every_blocking_job_is_covered_by_a_required_check():
    """The drift issue #481 describes: the gate and the enforcement disagree.

    `build-status` is the job the repo expects a branch-protection rule to
    key on -- it waits on every blocking job and compares each result.  If the
    ruleset instead requires a handful of individual contexts, then the
    blocking jobs it does not name (the Windows Python leg, the offline HTTP
    tier, the Pester suite) can fail without blocking anything.
    """
    snapshot = _snapshot()
    required = _required_contexts(snapshot)
    workflows = _load_workflows()
    contexts_by_job = _reportable_contexts(workflows)

    tests_doc = _tests_workflow()
    jobs = tests_doc["jobs"]
    aggregator = jobs[AGGREGATOR_JOB]
    blocking = sorted(
        set(aggregator.get("needs") or [])
        - {AGGREGATOR_JOB}
    )
    assert blocking, "build-status has no needs -- nothing to cover"

    aggregator_is_required = AGGREGATOR_CONTEXT in required
    uncovered = []
    for job_id in blocking:
        job_contexts = contexts_by_job.get(job_id, set())
        directly_required = bool(job_contexts) and job_contexts.issubset(required)
        if directly_required or aggregator_is_required:
            continue
        uncovered.append(job_id)

    # Allowlisted jobs are known drift: they are uncovered today, and the
    # allowlist entry says why.  Anything NOT allowlisted is new drift.
    unallowlisted = sorted(job for job in uncovered if job not in KNOWN_DRIFT)
    assert not unallowlisted, (
        f"blocking jobs that no required status check covers: {unallowlisted}. "
        f"Required checks: {sorted(required)}. Either the ruleset should "
        f"require {AGGREGATOR_CONTEXT!r} (which waits on and compares every "
        f"blocking job) or it should require these jobs directly."
    )


def test_known_drift_allowlist_matches_the_actual_drift():
    """The allowlist must name exactly the jobs that are currently uncovered.

    Two ways to get this wrong: an entry for a job that IS covered (the
    ratchet never tightens), or a job that is uncovered but not listed (the
    ratchet is silently stale).  Either way the allowlist stops describing
    reality, so it has to be maintained -- but only as the ruleset changes.
    """
    snapshot = _snapshot()
    required = _required_contexts(snapshot)
    contexts_by_job = _reportable_contexts(_load_workflows())

    tests_doc = _tests_workflow()
    aggregator = tests_doc["jobs"][AGGREGATOR_JOB]
    blocking = sorted(set(aggregator.get("needs") or []) - {AGGREGATOR_JOB})
    aggregator_is_required = AGGREGATOR_CONTEXT in required

    uncovered = []
    for job_id in blocking:
        job_contexts = contexts_by_job.get(job_id, set())
        if job_contexts and job_contexts.issubset(required):
            continue
        if aggregator_is_required:
            continue
        uncovered.append(job_id)

    allowlisted = sorted(KNOWN_DRIFT)
    assert allowlisted == uncovered, (
        f"KNOWN_DRIFT lists {allowlisted} but the actual uncovered jobs are "
        f"{uncovered}. If the ruleset now covers a job, delete its entry so "
        f"the ratchet tightens; if a new blocking job is uncovered, add it "
        f"with the reason."
    )


def test_snapshot_is_not_stale():
    """A snapshot that was never refreshed stops describing reality."""
    snapshot = _snapshot()
    captured = snapshot.get("captured_at")
    assert captured, "snapshot has no captured_at timestamp"
    when = dt.datetime.strptime(captured, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    age = dt.datetime.now(dt.timezone.utc) - when
    if age > dt.timedelta(days=SNAPSHOT_STALE_DAYS):
        pytest.fail(
            f"the branch protection snapshot is {age.days} days old "
            f"(> {SNAPSHOT_STALE_DAYS}). Refresh it with "
            f"`python3 tools/refresh_branch_protection_snapshot.py` -- it "
            f"reads the live rulesets, so a stale snapshot is the one thing "
            f"that cannot report the drift this file exists to catch."
        )
