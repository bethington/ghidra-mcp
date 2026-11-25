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
    # pom.xml — two rules: <version> tag and docker tag reference.
    # Project version is anchored after <packaging>jar</packaging> so the
    # bump regex doesn't catch dependency versions; the fixture mirrors the
    # real pom's coordinates block.
    (tmp_path / "pom.xml").write_text(
        f"<packaging>jar</packaging>\n"
        f"<version>{OLD}</version>\n"
        f"  ghidra image: v{OLD}:latest\n",
        encoding="utf-8",
    )

    # MANIFEST.MF
    manifest_dir = tmp_path / "src" / "main" / "resources" / "META-INF"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "MANIFEST.MF").write_text(f"Plugin-Version: {OLD}\n", encoding="utf-8")

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


def test_java_sources_carry_no_version_literal():
    """Both servers read the version from version.properties (core VersionInfo).
    Headless used to hard-code "7.0.0-headless" and report it for every build
    after 7.0.0, which is why no bump rule targets Java any more."""
    from tools.setup.versioning import read_pom_versions

    repo_root = Path(__file__).resolve().parents[2]
    version = read_pom_versions(repo_root).project_version
    for rel in ("src/main/java/com/xebyte/GhidraMCPPlugin.java",
                "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java",
                "src/main/java/com/xebyte/core/VersionInfo.java"):
        text = (repo_root / rel).read_text(encoding="utf-8")
        assert f'"{version}' not in text, rel


def test_build_rules_covers_all_expected_files(tmp_path: Path):
    from tools.setup.version_bump import build_rules

    rules = build_rules(tmp_path, OLD, NEW)
    paths = {r.file_path.relative_to(tmp_path).as_posix() for r in rules}

    expected = {
        "pom.xml",
        "src/main/resources/META-INF/MANIFEST.MF",
        "tests/endpoints.json",
        "CLAUDE.md",
        "README.md",
        "AGENTS.md",
        "docs/releases/README.md",
        "uv.lock",
        "CONTRIBUTING.md",
        "docs/INSTALL_GUI.md",
    }
    assert expected.issubset(paths), f"Missing files: {expected - paths}"


def test_bump_rewrites_the_install_examples(tmp_path: Path):
    """The examples a reader copies: the wheel URL, the expected /check_connection
    answer, the sample preflight output and the extension zip name."""
    from tools.setup.version_bump import apply_version_bump

    (tmp_path / "README.md").write_text(
        f'# {{"status": "ok", "server_kind": "gui", "version": "{OLD}"}}\n'
        f'# {{"status": "ok", "server_kind": "headless", "version": "{OLD}"}}\n'
        f"uv tool install https://github.com/o/r/releases/download/v{OLD}/"
        f"ghidra_mcp_bridge-{OLD}-py3-none-any.whl\n"
        f"The migration guide for {OLD} stays as written.\n",
        encoding="utf-8",
    )
    (tmp_path / "CONTRIBUTING.md").write_text(
        f"Project version: {OLD}\nProject version         : {OLD}\n", encoding="utf-8"
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "INSTALL_GUI.md").write_text(
        f"unzip -p GhidraMCP-{OLD}.zip GhidraMCP/extension.properties\n"
        f"![chooser with GhidraMCP-{OLD}.zip selected](shot.png)\n",
        encoding="utf-8",
    )

    apply_version_bump(tmp_path, NEW, old_version=OLD)

    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert readme.count(f'"version": "{NEW}"') == 2
    assert f"download/v{NEW}/ghidra_mcp_bridge-{NEW}-py3" in readme
    # Prose that names a past release is history, not a pin.
    assert f"The migration guide for {OLD} stays as written." in readme

    contributing = (tmp_path / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert OLD not in contributing and contributing.count(NEW) == 2

    install = (tmp_path / "docs" / "INSTALL_GUI.md").read_text(encoding="utf-8")
    assert f"unzip -p GhidraMCP-{NEW}.zip" in install
    # The alt text describes a screenshot, which a bump does not retake.
    assert f"GhidraMCP-{OLD}.zip selected" in install


def test_readme_install_pins_match_pom():
    """Between bumps, nothing else notices these going stale: after the 7.1.0 bump
    the Quickstart still installed the 7.0.0 wheel and showed 7.0.0 as the
    expected answer, and every check stayed green."""
    from tools.setup.versioning import read_pom_versions

    repo_root = Path(__file__).resolve().parents[2]
    version = read_pom_versions(repo_root).project_version

    found: dict[str, set[str]] = {}
    for rel, pattern in (
        ("README.md", r'"server_kind": "(?:gui|headless)", "version": "(\d+\.\d+\.\d+)"'),
        ("README.md", r"releases/download/v(\d+\.\d+\.\d+)/ghidra_mcp_bridge-"),
        ("README.md", r"/ghidra_mcp_bridge-(\d+\.\d+\.\d+)-py3"),
        ("CONTRIBUTING.md", r"Project version\s*:\s*(\d+\.\d+\.\d+)"),
        ("docs/INSTALL_GUI.md", r"unzip -p GhidraMCP-(\d+\.\d+\.\d+)\.zip"),
    ):
        text = (repo_root / rel).read_text(encoding="utf-8")
        hits = set(re.findall(pattern, text))
        # A pattern that matches nothing would pass forever, pinning nothing.
        assert hits, f"{rel}: no match for {pattern!r}; the example moved or was reworded"
        found[f"{rel} :: {pattern}"] = hits

    stale = {where: hits for where, hits in found.items() if hits != {version}}
    assert not stale, f"install examples disagree with pom.xml {version}: {stale}"


def test_apply_version_bump_preserves_crlf(tmp_path: Path):
    from tools.setup.version_bump import apply_version_bump

    path = tmp_path / "pyproject.toml"
    original = f'[project]\r\nname = "ghidra-mcp-bridge"\r\nversion = "{OLD}"\r\n'.encode()
    path.write_bytes(original)

    apply_version_bump(tmp_path, NEW, old_version=OLD)

    assert path.read_bytes() == original.replace(OLD.encode(), NEW.encode())


def test_apply_version_bump_updates_uv_lock_bridge_entry_only(tmp_path: Path):
    from tools.setup.version_bump import apply_version_bump

    lock = tmp_path / "uv.lock"
    lock.write_bytes(
        (
            f'[[package]]\r\nname = "other"\r\nversion = "{OLD}"\r\n\r\n'
            f'[[package]]\r\nname = "ghidra-mcp-bridge"\r\nversion = "{OLD}"\r\n'
        ).encode()
    )

    apply_version_bump(tmp_path, NEW, old_version=OLD)

    text = lock.read_bytes().decode()
    assert f'name = "ghidra-mcp-bridge"\r\nversion = "{NEW}"' in text
    assert f'name = "other"\r\nversion = "{OLD}"' in text


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


def test_build_rules_pom_version_does_not_match_dependency_version(tmp_path: Path):
    """Regression for v5.9.0 → v5.9.1 release: mockito-core's <version>5.9.0</version>
    was rewritten to 5.9.1 by the project-version bump because the regex was a
    bare (<version>5.9.0</version>) match. mockito-core 5.9.1 doesn't exist on
    Maven Central and the build failed mid-release. Anchoring to the project's
    coordinates block (<packaging>jar</packaging>) is what fixes it.
    """
    from tools.setup.version_bump import build_rules

    pom_rule = next(
        r for r in build_rules(tmp_path, OLD, NEW)
        if r.file_path.name == "pom.xml" and "<version>" in r.pattern
    )

    # Realistic pom shape: project version + dependency that shares the version.
    pom_content = (
        "<project>\n"
        "  <groupId>com.xebyte</groupId>\n"
        "  <artifactId>GhidraMCP</artifactId>\n"
        "  <packaging>jar</packaging>\n"
        f"  <version>{OLD}</version>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.mockito</groupId>\n"
        "      <artifactId>mockito-core</artifactId>\n"
        f"      <version>{OLD}</version>\n"
        "      <scope>test</scope>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    result = re.sub(pom_rule.pattern, pom_rule.replacement, pom_content)

    # Project version is rewritten exactly once.
    assert f"<packaging>jar</packaging>\n  <version>{NEW}</version>" in result
    # Dependency version is left alone (mockito-core 5.9.1 doesn't exist).
    assert f"<artifactId>mockito-core</artifactId>\n      <version>{OLD}</version>" in result


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
        "    <ghidra.version>12.1</ghidra.version>\n"
        "  </properties>\n"
        "</project>\n",
        encoding="utf-8",
    )

    assert get_current_version(tmp_path) == OLD
