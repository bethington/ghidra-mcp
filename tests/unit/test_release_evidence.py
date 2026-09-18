"""The gate that stops a release publishing on a regression that never ran.

Context
-------
``release.yml`` and ``pre-release.yml`` gated publishing on::

    needs.release-regression.result == 'success' || == 'skipped'

On a **tag push** that job is always skipped -- its own ``if`` requires
``workflow_dispatch`` -- so ``skipped`` was the only value a tagged release ever
produced, and the gate had never once blocked one.

It cannot be fixed by running the tier in CI. It needs a live Ghidra GUI on
Windows and targets ``[self-hosted, Windows]``; **no self-hosted runner is
registered**, and that is deliberate -- on a public repository, labelling a fork
PR would run a stranger's code on the maintainer's machine. So the gate is
recorded local evidence, and these tests are what stop that record being
reduced to a formality.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from tools import release_evidence
from tools.release_evidence import (
    EVIDENCE_PATH,
    GATING_TIER,
    SOURCE_PATHS,
    EvidenceError,
    record,
    source_fingerprint,
    verify,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PUBLISHING_WORKFLOWS = ("release.yml", "pre-release.yml")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway git repo carrying one file under each fingerprinted path."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "t@example.invalid"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    for rel in SOURCE_PATHS:
        target = tmp_path / rel
        if Path(rel).suffix:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("seed\n", encoding="utf-8")
        else:
            target.mkdir(parents=True, exist_ok=True)
            (target / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=tmp_path, check=True)
    return tmp_path


# ---------------------------------------------------------------------------
# The fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_is_stable_for_an_unchanged_tree(repo: Path):
    assert source_fingerprint(repo) == source_fingerprint(repo)


def test_fingerprint_moves_when_fingerprinted_source_changes(repo: Path):
    before = source_fingerprint(repo)
    (repo / "src" / "main" / "java" / "seed.txt").write_text("changed\n", encoding="utf-8")
    assert source_fingerprint(repo) != before, (
        "an edit under a fingerprinted path must invalidate the evidence -- "
        "otherwise the record says a regression ran against code it never saw"
    )


def test_fingerprint_sees_uncommitted_edits(repo: Path):
    """It describes the TREE THAT WAS TESTED, not the last commit.

    The maintainer runs the tier against a working tree. Hashing HEAD would
    record a fingerprint for code the regression did not exercise.
    """
    before = source_fingerprint(repo)
    (repo / "pom.xml").write_text("dirty\n", encoding="utf-8")
    assert source_fingerprint(repo) != before


def test_fingerprint_ignores_docs_and_the_changelog(repo: Path):
    """Not everything: a gate people work around is not a gate.

    Hours of live testing must not be invalidated by a CHANGELOG line written
    after it -- including the CHANGELOG entry describing the release itself.
    """
    before = source_fingerprint(repo)
    (repo / "CHANGELOG.md").write_text("new release notes\n", encoding="utf-8")
    (repo / "README.md").write_text("typo fixed\n", encoding="utf-8")
    assert source_fingerprint(repo) == before


def test_fingerprint_ignores_the_evidence_file_itself(repo: Path):
    """Otherwise writing the record would invalidate the record."""
    before = source_fingerprint(repo)
    record(repo, version="9.9.9", tier=GATING_TIER)
    assert source_fingerprint(repo) == before


def test_fingerprint_refuses_an_empty_source_set(tmp_path: Path):
    """A fingerprint of nothing matches every other fingerprint of nothing."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    with pytest.raises(EvidenceError, match="broken checkout"):
        source_fingerprint(tmp_path)


def test_fingerprint_is_line_ending_independent(repo: Path):
    """CRLF locally, LF in CI -- the same content must hash the same.

    `core.autocrlf=true` on the maintainer's Windows machine and an LF checkout
    on the ubuntu runner is not a corner case, it is every single release. Blob
    ids are used precisely so git's own normalisation applies.
    """
    target = repo / "pom.xml"
    target.write_bytes(b"<project>\n  <version>1</version>\n</project>\n")
    lf = source_fingerprint(repo)
    target.write_bytes(b"<project>\r\n  <version>1</version>\r\n</project>\r\n")
    crlf = source_fingerprint(repo)
    assert lf == crlf


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


def test_missing_evidence_is_refused_and_says_how_to_produce_it(repo: Path):
    with pytest.raises(EvidenceError) as excinfo:
        verify(repo, version="7.0.0")
    message = str(excinfo.value)
    assert "no live-regression evidence" in message
    assert f"--test {GATING_TIER}" in message, (
        "the refusal must name the command that produces the evidence; a gate "
        "nobody can satisfy gets deleted"
    )


def test_matching_evidence_verifies(repo: Path):
    record(repo, version="7.0.0", tier=GATING_TIER, ghidra_version="12.1.3")
    data = verify(repo, version="7.0.0")
    assert data["tier"] == GATING_TIER
    assert data["ghidra_version"] == "12.1.3"


def test_evidence_for_another_version_is_refused(repo: Path):
    record(repo, version="6.0.0", tier=GATING_TIER)
    with pytest.raises(EvidenceError, match="6.0.0"):
        verify(repo, version="7.0.0")


def test_evidence_from_a_narrower_tier_is_refused(repo: Path):
    """`selected-contract` passing is not the release gate passing."""
    record(repo, version="7.0.0", tier="selected-contract")
    with pytest.raises(EvidenceError, match="not the release gate"):
        verify(repo, version="7.0.0")


def test_evidence_is_invalidated_by_a_later_source_change(repo: Path):
    """The whole point: evidence describes code, not a moment in time."""
    record(repo, version="7.0.0", tier=GATING_TIER)
    verify(repo, version="7.0.0")

    (repo / "python" / "bridge_mcp_ghidra" / "seed.txt").write_text(
        "changed after the gate ran\n", encoding="utf-8"
    )
    with pytest.raises(EvidenceError, match="source fingerprint mismatch"):
        verify(repo, version="7.0.0")


def test_a_failed_result_is_refused(repo: Path):
    record(repo, version="7.0.0", tier=GATING_TIER)
    path = repo / EVIDENCE_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    data["result"] = "failed"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EvidenceError, match="result is 'failed'"):
        verify(repo, version="7.0.0")


def test_malformed_evidence_is_refused_not_ignored(repo: Path):
    path = repo / EVIDENCE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(EvidenceError, match="not valid JSON"):
        verify(repo, version="7.0.0")


def test_evidence_recorded_against_a_different_path_set_is_refused(repo: Path):
    """Two fingerprints over different inputs are not comparable.

    If SOURCE_PATHS is ever widened, old evidence must stop verifying rather
    than compare a hash of five paths against a hash of seven.
    """
    record(repo, version="7.0.0", tier=GATING_TIER)
    path = repo / EVIDENCE_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    data["fingerprinted_paths"] = ["pom.xml"]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EvidenceError, match="not comparable"):
        verify(repo, version="7.0.0")


# ---------------------------------------------------------------------------
# The workflows
# ---------------------------------------------------------------------------


def _publish_job(workflow: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    jobs = doc["jobs"]
    name = next(j for j in jobs if j != "release-regression")
    return jobs[name]


@pytest.mark.parametrize("workflow", PUBLISHING_WORKFLOWS)
def test_publishing_job_verifies_evidence_when_the_regression_did_not_run(workflow):
    job = _publish_job(workflow)
    steps = job["steps"]
    verify_steps = [
        s for s in steps if "tools.release_evidence verify" in str(s.get("run", ""))
    ]
    assert verify_steps, (
        f"{workflow} publishes without ever checking recorded live-regression "
        f"evidence. Its job-level `if` accepts "
        f"needs.release-regression.result == 'skipped', and on a TAG PUSH that "
        f"job is ALWAYS skipped -- so with no such step the gate cannot block "
        f"anything."
    )
    condition = str(verify_steps[0].get("if", ""))
    assert "release-regression.result" in condition and "success" in condition, (
        f"{workflow}'s evidence step must be conditioned on the regression NOT "
        f"having succeeded in-workflow (`if: needs.release-regression.result != "
        f"'success'`), so a real self-hosted run is still accepted as its own "
        f"evidence. Found: {condition!r}"
    )


@pytest.mark.parametrize("workflow", PUBLISHING_WORKFLOWS)
def test_evidence_step_has_no_fallback(workflow):
    """No `|| true`, no `|| echo`, no continue-on-error.

    `release.yml` published "Headless Endpoints: 1" in v6.0.0 because a grep of
    a deleted file was softened with `|| echo "0"`. A suppressed read error
    became a plausible number. These checks get no default of any kind.
    """
    job = _publish_job(workflow)
    steps = [
        s for s in job["steps"] if "tools.release_evidence verify" in str(s.get("run", ""))
    ]
    assert steps, (
        f"{workflow} has no evidence-verification step at all -- see the test "
        f"above, which is the one that explains why it needs one."
    )
    step = steps[0]
    run = str(step["run"])
    assert "|| true" not in run and "|| echo" not in run
    assert not step.get("continue-on-error"), (
        "continue-on-error is what makes a broken gate indistinguishable from a "
        "clean one"
    )


def test_gating_tier_is_a_real_deploy_tier():
    """The evidence gate and the thing that produces it must name one tier."""
    from tools.setup.ghidra import DEPLOY_TEST_MODES

    assert GATING_TIER in DEPLOY_TEST_MODES


def test_deploy_records_evidence_only_for_the_gating_tier(repo, monkeypatch):
    """A narrower tier must not leave a record that reads like a release gate."""
    from tools.setup import ghidra

    monkeypatch.setattr(
        ghidra, "read_pom_versions", lambda root: type("V", (), {"project_version": "7.0.0"})()
    )

    assert ghidra.record_release_regression_evidence(
        repo, Path("F:/ghidra_12.1.3_PUBLIC"), ["selected-contract"]
    ) is None
    assert not (repo / EVIDENCE_PATH).exists()

    written = ghidra.record_release_regression_evidence(
        repo, Path("F:/ghidra_12.1.3_PUBLIC"), [GATING_TIER]
    )
    assert written is not None
    data = json.loads(written.read_text(encoding="utf-8"))
    assert data["version"] == "7.0.0"
    assert data["ghidra_version"] == "12.1.3"
    verify(repo, version="7.0.0")


def test_committed_evidence_if_present_is_well_formed():
    """Whatever is in the tree must at least parse and name the gating tier.

    Deliberately does NOT require the file to exist -- it is written by a run on
    the maintainer's machine, not by this repository's tests.
    """
    path = REPO_ROOT / EVIDENCE_PATH
    if not path.is_file():
        pytest.skip("no evidence recorded in this checkout")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == release_evidence.SCHEMA_VERSION
    assert data["tier"] == GATING_TIER
    assert re.fullmatch(r"[0-9a-f]{64}", data["source_fingerprint"])
