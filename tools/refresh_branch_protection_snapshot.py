#!/usr/bin/env python3
"""Capture this repository's branch-protection rulesets into a checked-in snapshot.

Branch protection is enforced by a GitHub ruleset that lives *outside* the
repository, while the repository asserts in-repo (see
tests/unit/test_ci_workflow_triggers.py) which checks a protection rule is
expected to key on.  Nothing reconciles the two, so the ruleset can drift away
from the repo's expectations with nothing noticing -- which is exactly the
failure mode issue #481 describes.

This tool writes the live ruleset state to tests/ci/required_status_checks.json
so tests/unit/test_branch_protection.py can compare it against what the
workflows actually report.  The test is offline: no network, no token.

Usage
-----
    python3 tools/refresh_branch_protection_snapshot.py           # rewrite the snapshot
    python3 tools/refresh_branch_protection_snapshot.py --check   # fail if it is stale

``--check`` exits 1 and prints a diff when the live rulesets no longer match
the snapshot.  It needs a token that can read repository rulesets:
``GITHUB_TOKEN`` in CI, or ``gh auth token`` locally.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "tests" / "ci" / "required_status_checks.json"


def resolve_repo(explicit: str | None) -> str:
    """Return ``owner/name`` for the repository."""
    if explicit:
        return explicit
    try:
        out = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        out = ""
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if out.startswith(prefix):
            candidate = out[len(prefix):].removesuffix(".git")
            if candidate.count("/") == 1:
                return candidate
    raise SystemExit(
        "Could not resolve owner/name from the git remote. Pass --repo owner/name."
    )


def resolve_token() -> str:
    """Return a token able to read repository rulesets."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    try:
        out = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        out = ""
    if not out:
        raise SystemExit(
            "No token available. Set GITHUB_TOKEN, or run `gh auth login`."
        )
    return out


def _get(path: str, token: str) -> dict:
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_all(path: str, token: str) -> list:
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def collect(repo: str, token: str) -> dict:
    """Build the snapshot payload from the live repository settings."""
    try:
        meta = _get(f"/repos/{repo}", token)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Cannot read repository metadata: HTTP {error.code}")

    rulesets = []
    for summary in _get_all(f"/repos/{repo}/rulesets?per_page=100", token):
        detail = _get(f"/repos/{repo}/rulesets/{summary['id']}", token)        rules = detail.get("rules") or []
        required_checks = []
        approving_reviews = 0
        merge_methods = []
        copilot_review = False
        for rule in rules:
            params = rule.get("parameters") or {}
            if rule.get("type") == "required_status_checks":
                for check in params.get("required_status_checks") or []:
                    context = check.get("context")
                    if context and context not in required_checks:
                        required_checks.append(context)
            elif rule.get("type") == "pull_request":
                approving_reviews = params.get("required_approving_review_count", 0)
                merge_methods = params.get("allowed_merge_methods") or []
            elif rule.get("type") == "copilot_code_review":
                copilot_review = True
        conditions = detail.get("conditions") or {}
        branches = ((conditions.get("ref_name") or {}).get("include")) or []
        rulesets.append(
            {
                "id": detail.get("id"),
                "name": detail.get("name"),
                "target": detail.get("target"),
                "enforcement": detail.get("enforcement"),
                "branches": sorted(branches),
                "required_status_checks": sorted(required_checks),
                "required_approving_review_count": approving_reviews,
                "allowed_merge_methods": sorted(merge_methods),
                "copilot_code_review": copilot_review,
            }
        )

    rulesets.sort(key=lambda r: r["id"] or 0)
    return {
        "captured_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": repo,
        "default_branch": meta.get("default_branch"),
        "rulesets": rulesets,
    }


def comparable(payload: dict) -> dict:
    """The part of a snapshot that must match the live state."""
    return {k: v for k, v in payload.items() if k != "captured_at"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=None, help="owner/name (default: from git remote)")
    parser.add_argument(
        "--out", default=str(SNAPSHOT_PATH), help="snapshot path to write"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the live state differs from the snapshot",
    )
    args = parser.parse_args()

    repo = resolve_repo(args.repo)
    token = resolve_token()
    try:
        live = collect(repo, token)
    except urllib.error.HTTPError as error:
        # Exit 2 means "could not read the live state" -- distinct from exit 1,
        # which means "read it fine, and it differs".  CI needs the difference:
        # an unreadable ruleset is a permissions problem, not drift.
        print(f"Cannot read repository rulesets: HTTP {error.code}")
        return 2
    except urllib.error.URLError as error:
        print(f"Cannot reach api.github.com: {error.reason}")
        return 2

    if args.check:
        path = pathlib.Path(args.out)
        if not path.exists():
            print(f"SNAPSHOT MISSING: {path}")
            print("Run: python3 tools/refresh_branch_protection_snapshot.py")
            return 1
        stored = json.loads(path.read_text(encoding="utf-8"))
        if comparable(stored) == comparable(live):
            print(f"branch protection snapshot is current ({repo})")
            return 0
        print("branch protection rulesets have CHANGED since the snapshot was taken.")
        print(f"  snapshot: {path}")
        print(f"  repo:     {repo}")
        for old, new in zip(
            sorted(stored.get("rulesets", []), key=lambda r: r.get("id") or 0),
            sorted(live.get("rulesets", []), key=lambda r: r.get("id") or 0),
        ):
            if old != new:
                print(f"  ruleset {new.get('id')} ({new.get('name')}):")
                print(f"    before: {json.dumps(old, sort_keys=True)}")
                print(f"    after:  {json.dumps(new, sort_keys=True)}")
        if len(stored.get("rulesets", [])) != len(live.get("rulesets", [])):
            print("  the set of rulesets itself changed.")
        print("Refresh with: python3 tools/refresh_branch_protection_snapshot.py")
        return 1

    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(live, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")
    for ruleset in live["rulesets"]:
        print(
            f"  {ruleset['id']} {ruleset['name']!r} [{ruleset['enforcement']}] "
            f"branches={ruleset['branches']} checks={ruleset['required_status_checks']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
