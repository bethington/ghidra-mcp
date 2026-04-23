from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .versioning import read_pom_versions


VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class ReplacementRule:
    file_path: Path
    pattern: str
    replacement: str


def validate_version(value: str) -> str:
    if not VERSION_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid version '{value}'. Expected X.Y.Z")
    return value


def get_current_version(repo_root: Path) -> str:
    return read_pom_versions(repo_root).project_version


def build_rules(
    repo_root: Path, old_version: str, new_version: str
) -> list[ReplacementRule]:
    escaped_old = re.escape(old_version)
    return [
        ReplacementRule(
            repo_root / "pom.xml",
            rf"(<version>){escaped_old}(</version>)",
            rf"\g<1>{new_version}\g<2>",
        ),
        ReplacementRule(repo_root / "pom.xml", rf"v{escaped_old}:", f"v{new_version}:"),
        ReplacementRule(
            repo_root / "src/main/resources/META-INF/MANIFEST.MF",
            rf"(Plugin-Version:\s*){escaped_old}",
            rf"\g<1>{new_version}",
        ),
        ReplacementRule(
            repo_root / "src/main/java/com/xebyte/GhidraMCPPlugin.java",
            rf'"{escaped_old}"',
            f'"{new_version}"',
        ),
        ReplacementRule(
            repo_root
            / "src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java",
            rf'"{escaped_old}-headless"',
            f'"{new_version}-headless"',
        ),
        ReplacementRule(
            repo_root
            / "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java",
            rf'"{escaped_old}-headless"',
            f'"{new_version}-headless"',
        ),
        ReplacementRule(
            repo_root / "tests/endpoints.json",
            r'("version":\s*")\d+\.\d+\.\d+(")',
            rf"\g<1>{new_version}\g<2>",
        ),
        ReplacementRule(
            repo_root / "CLAUDE.md",
            r"(\*\*Version\*\*:\s*)\d+\.\d+\.\d+",
            rf"\g<1>{new_version}",
        ),
        ReplacementRule(
            repo_root / "README.md",
            r"(\|\s*\*\*Version\*\*\s*\|\s*)\d+\.\d+\.\d+(\s*\|)",
            rf"\g<1>{new_version}\g<2>",
        ),
        ReplacementRule(
            repo_root / "README.md",
            rf"Version-{escaped_old}-brightgreen",
            f"Version-{new_version}-brightgreen",
        ),
        ReplacementRule(
            repo_root / "README.md",
            rf"GhidraMCP Headless Server v{escaped_old}",
            f"GhidraMCP Headless Server v{new_version}",
        ),
        ReplacementRule(
            repo_root / "AGENTS.md",
            r"(\*\*Version\*\*:\s*)\d+\.\d+\.\d+",
            rf"\g<1>{new_version}",
        ),
        ReplacementRule(
            repo_root / "docs/releases/README.md",
            r"### v\d+\.\d+\.\d+ \(Latest\)",
            f"### v{new_version} (Latest)",
        ),
        ReplacementRule(
            repo_root / "docs/releases/README.md",
            r"\(v\d+\.\d+\.\d+\)",
            f"(v{new_version})",
        ),
    ]


def apply_version_bump(
    repo_root: Path,
    new_version: str,
    *,
    old_version: str | None = None,
    dry_run: bool = False,
    tag: bool = False,
) -> int:
    validated_new = validate_version(new_version)
    effective_old = (
        validate_version(old_version) if old_version else get_current_version(repo_root)
    )

    if effective_old == validated_new:
        print(f"SKIP: already at version {validated_new}")
        return 0

    print(f"Bumping version: {effective_old} -> {validated_new}")
    if dry_run:
        print("DRY RUN: no files will be modified.")

    changed = 0
    for rule in build_rules(repo_root, effective_old, validated_new):
        if not rule.file_path.is_file():
            print(f"SKIP (not found): {rule.file_path.relative_to(repo_root)}")
            continue

        original = rule.file_path.read_text(encoding="utf-8")
        updated = re.sub(rule.pattern, rule.replacement, original)

        relative_path = rule.file_path.relative_to(repo_root)
        if original == updated:
            print(f"no-match: {relative_path}")
            continue

        if dry_run:
            print(f"would update: {relative_path}")
            continue

        rule.file_path.write_text(updated, encoding="utf-8", newline="")
        print(f"updated: {relative_path}")
        changed += 1

    if not dry_run:
        print("")
        print(f"Updated {changed} file(s) to v{validated_new}.")

    if tag:
        tag_name = f"v{validated_new}"
        if dry_run:
            print(f"would tag: {tag_name}")
            return 0

        print("")
        print(f"Creating git tag {tag_name}...")
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "tag",
                "-a",
                tag_name,
                "-m",
                f"Release {tag_name}",
            ],
            check=False,
        )
        if completed.returncode == 0:
            print(f"tagged: {tag_name}")
            print(f"Push with: git push origin {tag_name}")
        else:
            print("WARNING: git tag failed (tag may already exist)")
            return completed.returncode

    return 0
