"""Recorded evidence that the live Ghidra release regression actually ran.

Why this exists
---------------
``release.yml`` and ``pre-release.yml`` both gate publishing on::

    needs.release-regression.result == 'success' || == 'skipped'

``skipped`` is accepted, and on a **tag push** that job is always skipped — its
own ``if`` requires ``workflow_dispatch``. So the gate that is supposed to stop
a broken release from shipping has never blocked a tag, and could not.

The obvious fix — run it in CI — is not available here, and not by accident.
The regression needs a live Ghidra GUI on Windows, so it targets
``runs-on: [self-hosted, Windows]``, and **zero self-hosted runners are
registered**. That is a deliberate decision: on a public repository, labelling a
fork PR would run a stranger's code on the maintainer's machine.

So the gate has to be **recorded local evidence** instead: the maintainer runs
the tier on their own machine, the run records what it proved, and the release
workflow refuses to publish unless that record matches the release being cut.

What the record has to pin
--------------------------
Not a timestamp — a timestamp says a regression ran, not that it ran against
*this code*. It records a **source fingerprint**: the git blob id of every file
whose change could invalidate a live regression, hashed together. CI recomputes
it at the released commit and requires an exact match, so any edit under
:data:`SOURCE_PATHS` after the gate was run invalidates the evidence and the
release fails until it is re-run. Edits that cannot change behaviour — docs, the
CHANGELOG, the evidence file itself — do not.

Line endings are normalised before hashing, and that is not a detail. The
maintainer records the evidence on Windows with ``core.autocrlf=true`` — the
working tree there really is CRLF, checked — and the release workflow verifies
it on an ubuntu runner with an LF checkout. Hash the bytes as they sit on disk
and the two never match, on every single release, and the gate gets switched
off within a week.

The first version of this delegated that to ``git hash-object``, on the
reasoning that git applies whatever normalisation it would apply on commit. It
does — **usually**. Measured: in this repository a CRLF working-tree file hashes
to its stored LF blob, but in a freshly cloned repo with the same
``core.autocrlf=true`` it hashes the CRLF bytes instead. "Works on this machine
today" is not a property to hang a release gate on, so the normalisation is done
here, explicitly: a file containing a NUL byte is hashed raw (binary — the
benchmark fixture's PE images), everything else has ``\\r\\n`` collapsed to
``\\n`` first. Deterministic on every platform, and it needs no git filter
semantics to be true.

Content is read from the **working tree**, not from HEAD, so an uncommitted edit
changes the fingerprint. That is the behaviour wanted: the evidence describes
the tree that was tested, not the last commit. ``git ls-files`` still supplies
the file *list*, so untracked build output and ``__pycache__`` cannot perturb
it.

Never give any of this a fallback default. ``release.yml`` used to grep a
deleted ``EndpointRegistry.java`` with ``|| echo "0"`` and published
"Headless Endpoints: 1" in v6.0.0. A gate that cannot read its input must fail,
not guess.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_PATH = Path("docs") / "releases" / "live-regression-evidence.json"

SCHEMA_VERSION = 1

# The tier whose evidence gates a release. `release` is the tier
# release-regression.yml defaults to, the one RELEASE_CHECKLIST.md names, and
# CLAUDE.md's fourth release-floor command.
GATING_TIER = "release"

# Paths whose contents could change what a live regression would conclude.
#
# Deliberately NOT "everything": a CHANGELOG edit or a README typo between the
# gate run and the tag must not invalidate hours of live testing, or the gate
# becomes something people work around. Equally deliberately, every path here is
# one a live regression actually exercises.
SOURCE_PATHS = (
    "src/main/java",            # the plugin and the headless server
    "python/bridge_mcp_ghidra",  # the bridge the tier drives Ghidra through
    "tools/setup",              # the harness that runs the tier
    "tests/fixtures/benchmark",  # the fixture and its address-keyed baselines
    "tests/endpoints.json",     # the catalog the contract tiers read
    "pom.xml",
    "build.gradle",
)


class EvidenceError(RuntimeError):
    """The recorded evidence is missing, malformed, or does not match."""


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _tracked_files(repo_root: Path) -> list[str]:
    """Every tracked file under SOURCE_PATHS, as forward-slash repo paths."""
    existing = [p for p in SOURCE_PATHS if (repo_root / p).exists()]
    if not existing:
        raise EvidenceError(
            f"none of the fingerprinted source paths exist under {repo_root}. "
            f"This is a broken checkout, not an empty project -- refusing to "
            f"fingerprint nothing and call it a match."
        )
    out = _git(repo_root, "ls-files", "-z", "--", *existing)
    files = sorted(p for p in out.split("\0") if p)
    if not files:
        raise EvidenceError(
            f"git tracks no files under {SOURCE_PATHS}. Refusing to fingerprint "
            f"an empty set: it would match every other empty set."
        )
    return files


def _normalised_content(path: Path) -> tuple[str, bytes]:
    """``(kind, bytes)`` for hashing, with line endings made platform-neutral.

    A NUL byte means binary (the benchmark fixture's PE images) and is hashed
    exactly. Everything else has ``\\r\\n`` collapsed to ``\\n``, so a CRLF
    working tree on Windows and an LF one on Linux agree. The kind is part of
    the hash so a file changing category is itself a change.
    """
    raw = path.read_bytes()
    if b"\0" in raw:
        return "binary", raw
    return "text", raw.replace(b"\r\n", b"\n")


def source_fingerprint(repo_root: Path) -> str:
    """A stable id for the tree the regression would exercise.

    SHA-256 over ``<path> <kind> <sha256-of-normalised-content>`` lines, one per
    tracked file under :data:`SOURCE_PATHS`, sorted. Read from the WORKING TREE,
    so an uncommitted edit moves it. See the module docstring for why the
    normalisation is done here rather than left to git.
    """
    import hashlib

    files = _tracked_files(repo_root)
    digest = hashlib.sha256()
    for rel in files:
        target = repo_root / rel
        if not target.is_file():
            # Tracked but absent: a deletion is a change, and must not be
            # silently skipped into an unchanged fingerprint.
            digest.update(f"{rel} missing\n".encode("utf-8"))
            continue
        kind, content = _normalised_content(target)
        digest.update(
            f"{rel} {kind} {hashlib.sha256(content).hexdigest()}\n".encode("utf-8")
        )
    return digest.hexdigest()


def record(
    repo_root: Path,
    *,
    version: str,
    tier: str,
    ghidra_version: str | None = None,
    tiers_run: list[str] | None = None,
) -> Path:
    """Write the evidence file after a tier has PASSED. Callers must not
    call this on a failure path -- a record of a failed run is worse than none,
    because it reads exactly like a record of a passing one."""
    path = repo_root / EVIDENCE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA_VERSION,
        "version": version,
        "tier": tier,
        "tiers_run": tiers_run or [tier],
        "result": "passed",
        "source_fingerprint": source_fingerprint(repo_root),
        "fingerprinted_paths": list(SOURCE_PATHS),
        "ghidra_version": ghidra_version,
        "recorded_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load(repo_root: Path) -> dict:
    path = repo_root / EVIDENCE_PATH
    if not path.is_file():
        raise EvidenceError(
            f"no live-regression evidence at {EVIDENCE_PATH.as_posix()}.\n"
            f"The live Ghidra release regression cannot run in CI -- it needs a "
            f"Windows self-hosted runner and none is registered, deliberately "
            f"(labelling a fork PR would run its code on the maintainer's "
            f"machine). So a release must carry recorded local evidence "
            f"instead. Produce it with:\n"
            f"    python -m tools.setup deploy --ghidra-path <path> --test {GATING_TIER}\n"
            f"then commit {EVIDENCE_PATH.as_posix()}."
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceError(
            f"{EVIDENCE_PATH.as_posix()} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise EvidenceError(
            f"{EVIDENCE_PATH.as_posix()} must contain a JSON object"
        )
    return data


def verify(repo_root: Path, *, version: str) -> dict:
    """Raise :class:`EvidenceError` unless the evidence covers this release.

    Returns the evidence on success so a caller can print it.
    """
    data = load(repo_root)
    problems: list[str] = []

    if data.get("schema") != SCHEMA_VERSION:
        problems.append(
            f"schema is {data.get('schema')!r}, expected {SCHEMA_VERSION}"
        )
    if data.get("result") != "passed":
        problems.append(f"result is {data.get('result')!r}, expected 'passed'")
    if data.get("tier") != GATING_TIER:
        problems.append(
            f"tier is {data.get('tier')!r}, expected {GATING_TIER!r} -- a "
            f"narrower tier is not the release gate"
        )
    recorded_version = data.get("version")
    if recorded_version != version:
        problems.append(
            f"evidence is for version {recorded_version!r}, this release is "
            f"{version!r}"
        )

    recorded_paths = data.get("fingerprinted_paths")
    if recorded_paths != list(SOURCE_PATHS):
        problems.append(
            f"evidence fingerprinted {recorded_paths!r}, this checkout "
            f"fingerprints {list(SOURCE_PATHS)!r} -- the two are not comparable"
        )
    else:
        actual = source_fingerprint(repo_root)
        if data.get("source_fingerprint") != actual:
            problems.append(
                f"source fingerprint mismatch.\n"
                f"  recorded : {data.get('source_fingerprint')}\n"
                f"  this tree: {actual}\n"
                f"Something under {', '.join(SOURCE_PATHS)} changed after the "
                f"regression was run, so the evidence describes different code "
                f"than this release ships. Re-run the tier."
            )

    if problems:
        raise EvidenceError(
            "recorded live-regression evidence does not cover this release:\n  - "
            + "\n  - ".join(problems)
        )
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Record and verify evidence that the live Ghidra release regression "
            "ran against the code being released."
        )
    )
    parser.add_argument(
        "action", choices=["verify", "show", "fingerprint"],
    )
    parser.add_argument(
        "--version",
        help="the release version the evidence must cover (required by `verify`)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)

    if args.action == "fingerprint":
        print(source_fingerprint(args.repo_root))
        return 0

    if args.action == "show":
        try:
            print(json.dumps(load(args.repo_root), indent=2))
        except EvidenceError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        return 0

    if not args.version:
        parser.error("verify requires --version")
    try:
        data = verify(args.repo_root, version=args.version)
    except EvidenceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"Live-regression evidence OK: tier={data['tier']} "
        f"version={data['version']} recorded={data['recorded_utc']} "
        f"ghidra={data.get('ghidra_version')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
