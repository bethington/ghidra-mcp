from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tools.setup.ghidra import (
    PLUGIN_CLASS,
    REQUIRED_GHIDRA_JARS,
    collect_preflight_issues,
    find_plugin_archive,
    patch_codebrowser_tcd,
    patch_frontend_tool_config,
    resolve_ghidra_user_dir,
)
from tools.setup.versioning import VersionInfo


def test_patch_frontend_tool_config_adds_plugin_to_self_closing_utility_block():
    content = '<TOOL><PACKAGE NAME="Utility" /></TOOL>'

    updated, modified = patch_frontend_tool_config(content)

    assert modified is True
    assert PLUGIN_CLASS in updated
    assert '<PACKAGE NAME="Utility">' in updated


def test_patch_frontend_tool_config_removes_stale_package_and_inserts_plugin():
    content = (
        '<TOOL>\n'
        '  <PACKAGE NAME="GhidraMCP">\n'
        '    <INCLUDE CLASS="old.Plugin" />\n'
        '  </PACKAGE>\n'
        '  <ROOT_NODE NAME="root" />\n'
        '</TOOL>'
    )

    updated, modified = patch_frontend_tool_config(content)

    assert modified is True
    assert 'PACKAGE NAME="GhidraMCP"' not in updated
    assert PLUGIN_CLASS in updated
    assert updated.count(PLUGIN_CLASS) == 1


def test_patch_codebrowser_tcd_removes_ghidra_mcp_package_block():
    content = (
        '<TOOL>\n'
        '  <PACKAGE NAME="GhidraMCP">\n'
        f'    <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
        '  </PACKAGE>\n'
        '</TOOL>'
    )

    updated, modified = patch_codebrowser_tcd(content)

    assert modified is True
    assert PLUGIN_CLASS not in updated
    assert 'PACKAGE NAME="GhidraMCP"' not in updated


def test_resolve_ghidra_user_dir_prefers_matching_public_dir(tmp_path: Path):
    user_base = tmp_path / 'ghidra'
    matching_dir = user_base / 'ghidra_12.0.4_PUBLIC'
    other_dir = user_base / 'ghidra_12.0.3_PUBLIC'
    matching_dir.mkdir(parents=True)
    other_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path('F:/ghidra_12.0.4_PUBLIC'), user_base)

    assert resolved == matching_dir


def test_resolve_ghidra_user_dir_falls_back_to_latest_existing_dir(tmp_path: Path):
    user_base = tmp_path / 'ghidra'
    latest_dir = user_base / 'ghidra_12.1.0_PUBLIC'
    older_dir = user_base / 'ghidra_12.0.4_PUBLIC'
    latest_dir.mkdir(parents=True)
    older_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path('F:/custom-ghidra-install'), user_base)

    assert resolved == latest_dir


def test_collect_preflight_issues_reports_missing_jar_and_debugger_requirements(tmp_path: Path):
    ghidra_path = tmp_path / 'ghidra_12.0.4_PUBLIC'
    (ghidra_path / 'Extensions' / 'Ghidra').mkdir(parents=True)
    (ghidra_path / 'ghidraRun.bat').write_text('echo off\n', encoding='utf-8')
    user_base = tmp_path / 'user-ghidra'
    (user_base / 'ghidra_12.0.4_PUBLIC').mkdir(parents=True)

    issues = collect_preflight_issues(
        tmp_path,
        ghidra_path,
        Path(sys.executable),
        install_debugger=True,
        strict=False,
        user_base_dir=user_base,
    )

    assert any('Missing required Ghidra dependency' in issue for issue in issues)
    assert any('Debugger requirements file not found' in issue for issue in issues)


def _stub_version(monkeypatch: pytest.MonkeyPatch, repo_root: Path, version: str = "5.4.1") -> None:
    monkeypatch.setattr(
        "tools.setup.ghidra.read_pom_versions",
        lambda _root: VersionInfo(project_version=version, ghidra_version="12.0.4"),
    )


class TestFindPluginArchive:
    def test_prefers_gradle_output_over_maven(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_version(monkeypatch, tmp_path)
        gradle_zip = tmp_path / "build" / "distributions" / "GhidraMCP-5.4.1.zip"
        maven_zip = tmp_path / "target" / "GhidraMCP-5.4.1.zip"
        gradle_zip.parent.mkdir(parents=True)
        maven_zip.parent.mkdir(parents=True)
        gradle_zip.write_bytes(b"gradle")
        maven_zip.write_bytes(b"maven")

        assert find_plugin_archive(tmp_path) == gradle_zip

    def test_falls_back_to_maven_target_when_gradle_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_version(monkeypatch, tmp_path)
        maven_zip = tmp_path / "target" / "GhidraMCP-5.4.1.zip"
        maven_zip.parent.mkdir(parents=True)
        maven_zip.write_bytes(b"maven")

        assert find_plugin_archive(tmp_path) == maven_zip

    def test_finds_versioned_gradle_zip_by_glob_when_name_differs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_version(monkeypatch, tmp_path)
        dist_dir = tmp_path / "build" / "distributions"
        dist_dir.mkdir(parents=True)
        other_zip = dist_dir / "GhidraMCP-5.4.0.zip"
        other_zip.write_bytes(b"old")

        assert find_plugin_archive(tmp_path) == other_zip

    def test_raises_when_no_archive_exists(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_version(monkeypatch, tmp_path)

        with pytest.raises(FileNotFoundError, match="build/distributions"):
            find_plugin_archive(tmp_path)


def test_collect_preflight_issues_passes_with_required_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ghidra_path = tmp_path / 'ghidra_12.0.4_PUBLIC'
    (ghidra_path / 'Extensions' / 'Ghidra').mkdir(parents=True)
    (ghidra_path / 'ghidraRun.bat').write_text('echo off\n', encoding='utf-8')
    for _artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        jar_path.parent.mkdir(parents=True, exist_ok=True)
        jar_path.write_text('jar', encoding='utf-8')

    (tmp_path / 'requirements-debugger.txt').write_text('pybag==1.0\n', encoding='utf-8')
    user_base = tmp_path / 'user-ghidra'
    (user_base / 'ghidra_12.0.4_PUBLIC').mkdir(parents=True)
    monkeypatch.setattr('tools.setup.ghidra.shutil.which', lambda name: 'java' if name == 'java' else None)

    issues = collect_preflight_issues(
        tmp_path,
        ghidra_path,
        Path(sys.executable),
        install_debugger=True,
        strict=False,
        user_base_dir=user_base,
    )

    assert issues == []