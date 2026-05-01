"""
Unit tests for tools.setup.version_bump — validate_version, build_rules, apply_version_bump.

Tests pass `old_version` explicitly so no pom.xml is required for most cases.
The complete-repo test creates a minimal file tree and verifies all 14 rules fire.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


OLD = "5.4.1"
NEW = "5.5.0"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """Minimal file tree with OLD version in every location that build_rules targets."""
    # pom.xml — two rules: <version> tag and docker tag reference
    (tmp_path / "pom.xml").write_text(
        f"<version>{OLD}</version>\n"
        f"  ghidra image: v{OLD}:latest\n",
        encoding="utf-8",
    )

    # MANIFEST.MF
    manifest_dir = tmp_path / "src" / "main" / "resources" / "META-INF"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "MANIFEST.MF").write_text(f"Plugin-Version: {OLD}\n", encoding="utf-8")

    # Java source files
    plugin_dir = tmp_path / "src" / "main" / "java" / "com" / "xebyte"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "GhidraMCPPlugin.java").write_text(
        f'private static final String VERSION = "{OLD}";\n', encoding="utf-8"
    )

    headless_dir = plugin_dir / "headless"
    headless_dir.mkdir(parents=True)
    (headless_dir / "HeadlessEndpointHandler.java").write_text(
        f'return "{OLD}-headless";\n', encoding="utf-8"
    )
    (headless_dir / "GhidraMCPHeadlessServer.java").write_text(
        f'static final String VER = "{OLD}-headless";\n', encoding="utf-8"
    )

    # endpoints.json
    (tmp_path / "tests").mkdir(parents=True)
    (tmp_path / "tests" / "endpoints.json").write_text(
        f'{{"version": "{OLD}", "total_endpoints": 222}}\n', encoding="utf-8"
    )

    # Markdown docs
    (tmp_path / "CLAUDE.md").write_text(f"**Version**: {OLD}\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text(f"**Version**: {OLD}\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        f"| **Version** | {OLD} |\n"
        f"![Version](https://img.shields.io/badge/Version-{OLD}-brightgreen)\n"
        f"GhidraMCP Headless Server v{OLD} is available\n",
        encoding="utf-8",
    )

    # docs/releases/README.md — two rules: header and date reference
    releases_dir = tmp_path / "docs" / "releases"
    releases_dir.mkdir(parents=True)
    (releases_dir / "README.md").write_text(
        f"### v{OLD} (Latest)\n"
        f"Released (v{OLD})\n",
        encoding="utf-8",
    )

    return tmp_path


# ---------------------------------------------------------------------------
# validate_version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["1.0.0", "5.4.1", "100.200.300", "0.0.1"])
def test_validate_version_accepts_valid(version: str):
    from tools.setup.version_bump import validate_version

    assert validate_version(version) == version


@pytest.mark.parametrize("version", ["1.0", "1.0.0.0", "v1.0.0", "alpha", "", "1.0.x", "1.0.0-rc1"])
def test_validate_version_rejects_invalid(version: str):
    from tools.setup.version_bump import validate_version

    with pytest.raises(ValueError, match="Invalid version"):
        validate_version(version)


# ---------------------------------------------------------------------------
# apply_version_bump — control flow
# ---------------------------------------------------------------------------

def test_apply_version_bump_skips_when_already_at_version(repo: Path, capsys):
    from tools.setup.version_bump import apply_version_bump

    result = apply_version_bump(repo, OLD, old_version=OLD)

    assert result == 0
    assert "already at version" in capsys.readouterr().out


def test_apply_version_bump_dry_run_does_not_modify_files(repo: Path, capsys):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD, dry_run=True)

    # pom.xml must not be modified
    content = (repo / "pom.xml").read_text(encoding="utf-8")
    assert OLD in content
    assert NEW not in content


def test_apply_version_bump_dry_run_prints_would_update(repo: Path, capsys):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD, dry_run=True)

    out = capsys.readouterr().out
    assert "would update" in out or "DRY RUN" in out


def test_apply_version_bump_skips_missing_files_without_error(tmp_path: Path):
    from tools.setup.version_bump import apply_version_bump

    # No files exist in tmp_path — should skip all and return 0
    result = apply_version_bump(tmp_path, NEW, old_version=OLD)
    assert result == 0


def test_apply_version_bump_returns_zero_on_success(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    result = apply_version_bump(repo, NEW, old_version=OLD)
    assert result == 0


def test_apply_version_bump_reports_changed_count(repo: Path, capsys):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    out = capsys.readouterr().out
    # Some files should have been updated
    assert "Updated" in out
    assert "file(s)" in out


# ---------------------------------------------------------------------------
# Individual replacement rules
# ---------------------------------------------------------------------------

def test_rule_pom_version_tag(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "pom.xml").read_text(encoding="utf-8")
    assert f"<version>{NEW}</version>" in content
    assert f"<version>{OLD}</version>" not in content


def test_rule_pom_docker_tag(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "pom.xml").read_text(encoding="utf-8")
    assert f"v{NEW}:" in content
    assert f"v{OLD}:" not in content


def test_rule_manifest_plugin_version(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "src" / "main" / "resources" / "META-INF" / "MANIFEST.MF").read_text(encoding="utf-8")
    assert f"Plugin-Version: {NEW}" in content
    assert OLD not in content


def test_rule_java_plugin_version_string(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "src" / "main" / "java" / "com" / "xebyte" / "GhidraMCPPlugin.java").read_text(encoding="utf-8")
    assert f'"{NEW}"' in content
    assert OLD not in content


def test_rule_headless_endpoint_handler(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (
        repo / "src" / "main" / "java" / "com" / "xebyte" / "headless" / "HeadlessEndpointHandler.java"
    ).read_text(encoding="utf-8")
    assert f'"{NEW}-headless"' in content
    assert OLD not in content


def test_rule_headless_server(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (
        repo / "src" / "main" / "java" / "com" / "xebyte" / "headless" / "GhidraMCPHeadlessServer.java"
    ).read_text(encoding="utf-8")
    assert f'"{NEW}-headless"' in content
    assert OLD not in content


def test_rule_endpoints_json_version(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "tests" / "endpoints.json").read_text(encoding="utf-8")
    assert f'"version": "{NEW}"' in content
    assert OLD not in content


def test_rule_claude_md_version(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert f"**Version**: {NEW}" in content
    assert OLD not in content


def test_rule_readme_table_version(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "README.md").read_text(encoding="utf-8")
    assert NEW in content
    # Badge and headless title should also be updated — check OLD is gone entirely
    assert OLD not in content


def test_rule_readme_badge_version(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "README.md").read_text(encoding="utf-8")
    assert f"Version-{NEW}-brightgreen" in content


def test_rule_readme_headless_server_title(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "README.md").read_text(encoding="utf-8")
    assert f"GhidraMCP Headless Server v{NEW}" in content


def test_rule_agents_md_version(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "AGENTS.md").read_text(encoding="utf-8")
    assert f"**Version**: {NEW}" in content
    assert OLD not in content


def test_rule_docs_releases_header(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "docs" / "releases" / "README.md").read_text(encoding="utf-8")
    assert f"### v{NEW} (Latest)" in content
    assert f"### v{OLD} (Latest)" not in content


def test_rule_docs_releases_date_reference(repo: Path):
    from tools.setup.version_bump import apply_version_bump

    apply_version_bump(repo, NEW, old_version=OLD)

    content = (repo / "docs" / "releases" / "README.md").read_text(encoding="utf-8")
    assert f"(v{NEW})" in content
    assert f"(v{OLD})" not in content


# ---------------------------------------------------------------------------
# build_rules — structural checks
# ---------------------------------------------------------------------------

def test_build_rules_covers_all_expected_files(tmp_path: Path):
    from tools.setup.version_bump import build_rules

    rules = build_rules(tmp_path, OLD, NEW)
    paths = {r.file_path.relative_to(tmp_path).as_posix() for r in rules}

    expected = {
        "pom.xml",
        "src/main/resources/META-INF/MANIFEST.MF",
        "src/main/java/com/xebyte/GhidraMCPPlugin.java",
        "src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java",
        "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java",
        "tests/endpoints.json",
        "CLAUDE.md",
        "README.md",
        "AGENTS.md",
        "docs/releases/README.md",
    }
    assert expected.issubset(paths), f"Missing files: {expected - paths}"


def test_build_rules_are_all_valid_regex(tmp_path: Path):
    from tools.setup.version_bump import build_rules

    for rule in build_rules(tmp_path, OLD, NEW):
        # Should not raise re.error
        re.compile(rule.pattern)


def test_build_rules_no_match_does_not_modify_unrelated_text(tmp_path: Path):
    from tools.setup.version_bump import build_rules

    pom_rule = next(r for r in build_rules(tmp_path, OLD, NEW) if r.file_path.name == "pom.xml" and "<version>" in r.pattern)
    unrelated = "<description>Some description 5.4.1 mentions version</description>"
    result = re.sub(pom_rule.pattern, pom_rule.replacement, unrelated)
    # The <version> rule should not match inside <description>
    assert result == unrelated


# ---------------------------------------------------------------------------
# get_current_version
# ---------------------------------------------------------------------------

def test_get_current_version_reads_pom(tmp_path: Path):
    from tools.setup.version_bump import get_current_version

    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        f"  <version>{OLD}</version>\n"
        "  <properties>\n"
        "    <ghidra.version>12.0.4</ghidra.version>\n"
        "  </properties>\n"
        "</project>\n",
        encoding="utf-8",
    )

    assert get_current_version(tmp_path) == OLD
