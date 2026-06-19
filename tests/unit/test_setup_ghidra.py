from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tools.setup.ghidra import (
    DEFAULT_MCP_URL,
    PLUGIN_CLASS,
    REQUIRED_GHIDRA_JARS,
    _has_dependency_group,
    collect_preflight_issues,
    find_plugin_archive,
    mark_extension_known_in_tool_config,
    patch_codebrowser_tcd,
    patch_frontend_tool_config,
    patch_ghidra_user_configs,
    resolve_mcp_url,
    resolve_deploy_test_modes,
    resolve_ghidra_user_dir,
    run_deploy_tests,
    run_default_smoke_test,
    run_endpoint_catalog_test,
    run_selected_endpoint_contract_test,
)
from tools.setup.versioning import VersionInfo


def test_patch_frontend_tool_config_adds_plugin_to_self_closing_utility_block():
    content = '<TOOL><PACKAGE NAME="Utility" /></TOOL>'

    updated, modified = patch_frontend_tool_config(content)

    assert modified is True
    assert PLUGIN_CLASS in updated
    assert '<PACKAGE NAME="Utility">' in updated
    assert '<EXTENSION NAME="GhidraMCP" />' in updated


def test_patch_frontend_tool_config_removes_stale_package_and_inserts_plugin():
    content = (
        "<TOOL>\n"
        '  <PACKAGE NAME="GhidraMCP">\n'
        '    <INCLUDE CLASS="old.Plugin" />\n'
        "  </PACKAGE>\n"
        '  <ROOT_NODE NAME="root" />\n'
        "</TOOL>"
    )

    updated, modified = patch_frontend_tool_config(content)

    assert modified is True
    assert 'PACKAGE NAME="GhidraMCP"' not in updated
    assert PLUGIN_CLASS in updated
    assert updated.count(PLUGIN_CLASS) == 1
    assert '<EXTENSION NAME="GhidraMCP" />' in updated


def test_patch_frontend_tool_config_inserts_into_existing_open_utility_block():
    """The shape produced by an already-running Ghidra: Utility block is
    open and has other INCLUDE entries inside. The plugin INCLUDE must
    land *inside* the existing block, not duplicate the block.

    This is the layout I had to patch by hand on the v5.10 -> v5.11
    deploy when the script picked the wrong user-config dir (#217), so
    nail it down with a test."""
    content = (
        "<TOOL>\n"
        '    <PACKAGE NAME="Utility">\n'
        '        <INCLUDE CLASS="ghidra.framework.someother.Plugin" />\n'
        "    </PACKAGE>\n"
        "</TOOL>"
    )

    updated, modified = patch_frontend_tool_config(content)

    assert modified is True
    assert updated.count('<PACKAGE NAME="Utility">') == 1
    assert PLUGIN_CLASS in updated
    assert "ghidra.framework.someother.Plugin" in updated, (
        "preexisting Utility INCLUDE must be preserved"
    )
    # Our INCLUDE must be inside the Utility block, not after </PACKAGE>.
    plugin_idx = updated.find(PLUGIN_CLASS)
    closing_idx = updated.find("</PACKAGE>")
    assert plugin_idx < closing_idx, "plugin INCLUDE leaked outside Utility block"


def test_patch_frontend_tool_config_is_idempotent_when_plugin_present():
    """If the plugin is already in the Utility block, the file should
    not get a second INCLUDE entry, and `modified` flips off so the
    deploy script skips the disk write."""
    content = (
        "<TOOL>\n"
        '    <PACKAGE NAME="Utility">\n'
        f'        <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
        "    </PACKAGE>\n"
        '    <EXTENSIONS>\n'
        '        <EXTENSION NAME="GhidraMCP" />\n'
        "    </EXTENSIONS>\n"
        "</TOOL>"
    )

    updated, modified = patch_frontend_tool_config(content)

    assert updated.count(PLUGIN_CLASS) == 1, (
        "Plugin already present — must not be re-added"
    )
    assert updated.count('<EXTENSION NAME="GhidraMCP" />') == 1
    assert modified is False, "no-op patch must report unmodified"


def test_patch_codebrowser_tcd_removes_ghidra_mcp_package_block():
    content = (
        "<TOOL>\n"
        '  <PACKAGE NAME="GhidraMCP">\n'
        f'    <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
        "  </PACKAGE>\n"
        "</TOOL>"
    )

    updated, modified = patch_codebrowser_tcd(content)

    assert modified is True
    assert PLUGIN_CLASS not in updated
    assert 'PACKAGE NAME="GhidraMCP"' not in updated
    assert '<EXTENSION NAME="GhidraMCP" />' in updated


def test_resolve_ghidra_user_dir_prefers_matching_public_dir(tmp_path: Path):
    user_base = tmp_path / "ghidra"
    matching_dir = user_base / "ghidra_12.1_PUBLIC"
    other_dir = user_base / "ghidra_12.0.3_PUBLIC"
    matching_dir.mkdir(parents=True)
    other_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/ghidra_12.1_PUBLIC"), user_base)

    assert resolved == matching_dir


def test_resolve_ghidra_user_dir_picks_public_when_dev_and_public_coexist(
    tmp_path: Path,
):
    """A Ghidra dev install creates `ghidra_<v>_DEV/` next to `_PUBLIC/`.
    When the user is deploying for the PUBLIC release we must not let
    the resolver pick the DEV dir. This is the exact scenario behind
    #217 — when the v5.10->v5.11 deploy installed to a `_DEV` user
    config and the FrontEnd patch landed in the wrong place."""
    user_base = tmp_path / "ghidra"
    dev_dir = user_base / "ghidra_12.1_DEV"
    dev_loc = user_base / "ghidra_12.1_DEV_location_ghidra"
    public_dir = user_base / "ghidra_12.1_PUBLIC"
    dev_dir.mkdir(parents=True)
    dev_loc.mkdir(parents=True)
    public_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/ghidra_12.1_PUBLIC"), user_base)

    assert resolved == public_dir
    assert resolved != dev_dir
    assert resolved != dev_loc


def test_resolve_ghidra_user_dir_returns_public_when_only_dev_exists(tmp_path: Path):
    """#217 regression: a freshly-installed Ghidra has no user-config
    dir yet (Ghidra creates it lazily on first launch). If the deploy
    target is ``ghidra_12.1_PUBLIC`` and only a leftover
    ``ghidra_12.1_DEV`` sibling exists in ``%APPDATA%\\ghidra\\``, the
    resolver must NOT silently fall back to the DEV dir — that
    installs the extension where the running PUBLIC Ghidra never
    looks. Return the (nonexistent) PUBLIC path; Ghidra will create
    it."""
    user_base = tmp_path / "ghidra"
    dev_dir = user_base / "ghidra_12.1_DEV"
    dev_dir.mkdir(parents=True)
    # Note: no _PUBLIC dir created — the bug scenario.

    resolved = resolve_ghidra_user_dir(Path("F:/ghidra_12.1_PUBLIC"), user_base)

    assert resolved == user_base / "ghidra_12.1_PUBLIC"
    assert resolved != dev_dir


def test_resolve_ghidra_user_dir_returns_dev_when_install_is_dev(tmp_path: Path):
    """Symmetric to the PUBLIC case: a DEV install resolves to the
    DEV user dir, even when a PUBLIC sibling exists from a prior
    install."""
    user_base = tmp_path / "ghidra"
    public_dir = user_base / "ghidra_12.1_PUBLIC"
    public_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/ghidra_12.1_DEV"), user_base)

    assert resolved == user_base / "ghidra_12.1_DEV"
    assert resolved != public_dir


def test_resolve_ghidra_user_dir_ignores_unrelated_appdata_dirs(tmp_path: Path):
    """The resolver must not be influenced by sibling Ghidra-version
    dirs from older installs when constructing the target dir name.
    Previously the resolver globbed for ``ghidra_<version>*`` and
    could match e.g. ``ghidra_12.1_DEV_location_ghidra`` (a Ghidra
    locator file) instead of the proper user dir."""
    user_base = tmp_path / "ghidra"
    (user_base / "ghidra_12.0.4_PUBLIC").mkdir(parents=True)
    (user_base / "ghidra_12.1_DEV_location_ghidra").mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/ghidra_12.1_PUBLIC"), user_base)

    assert resolved == user_base / "ghidra_12.1_PUBLIC"


def test_resolve_ghidra_user_dir_reads_application_properties_when_path_unnamed(
    tmp_path: Path,
):
    """A custom install path that doesn't follow the standard
    ``ghidra_<version>_<layout>`` naming falls back to reading
    ``application.properties`` for the version. Layout is unknown in
    that case; resolver defaults to PUBLIC since released Ghidras are
    PUBLIC."""
    install = tmp_path / "custom-ghidra-install"
    (install / "Ghidra").mkdir(parents=True)
    (install / "Ghidra" / "application.properties").write_text(
        "application.version=12.1\n", encoding="utf-8"
    )
    user_base = tmp_path / "ghidra"

    resolved = resolve_ghidra_user_dir(install, user_base)

    assert resolved == user_base / "ghidra_12.1_PUBLIC"


def test_resolve_ghidra_user_dir_falls_back_to_latest_existing_dir(tmp_path: Path):
    user_base = tmp_path / "ghidra"
    latest_dir = user_base / "ghidra_12.1.0_PUBLIC"
    older_dir = user_base / "ghidra_12.1_PUBLIC"
    latest_dir.mkdir(parents=True)
    older_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/custom-ghidra-install"), user_base)

    assert resolved == latest_dir


def test_collect_preflight_issues_reports_missing_jar_and_debugger_requirements(
    tmp_path: Path,
):
    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    (ghidra_path / "Extensions" / "Ghidra").mkdir(parents=True)
    (ghidra_path / "ghidraRun.bat").write_text("echo off\n", encoding="utf-8")
    user_base = tmp_path / "user-ghidra"
    (user_base / "ghidra_12.1_PUBLIC").mkdir(parents=True)

    issues = collect_preflight_issues(
        tmp_path,
        ghidra_path,
        Path(sys.executable),
        install_debugger=True,
        strict=False,
        user_base_dir=user_base,
    )

    assert any("Missing required Ghidra dependency" in issue for issue in issues)
    assert any(
        "Debugger dependency group not found" in issue for issue in issues
    )


class TestHasDependencyGroup:
    def test_true_for_real_entry(self, tmp_path: Path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[dependency-groups]\ndebugger = [\"pybag==2.2.16\"]\n",
            encoding="utf-8",
        )
        assert _has_dependency_group(pyproject, "debugger") is True

    def test_true_for_quoted_key(self, tmp_path: Path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[dependency-groups]\n\"debugger\" = [\"pybag\"]\n",
            encoding="utf-8",
        )
        assert _has_dependency_group(pyproject, "debugger") is True

    def test_false_when_word_only_in_comment(self, tmp_path: Path):
        # The reviewer's false-positive case: "debugger" appears as prose but
        # there is no resolvable dependency group, so uv sync would fail.
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "# TODO: add a debugger dependency group later\n"
            "[dependency-groups]\ntest = [\"pytest\"]\n",
            encoding="utf-8",
        )
        assert _has_dependency_group(pyproject, "debugger") is False

    def test_false_when_key_in_other_section(self, tmp_path: Path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[tool.something]\ndebugger = true\n"
            "[dependency-groups]\ntest = [\"pytest\"]\n",
            encoding="utf-8",
        )
        assert _has_dependency_group(pyproject, "debugger") is False

    def test_false_when_file_missing(self, tmp_path: Path):
        assert _has_dependency_group(tmp_path / "nope.toml", "debugger") is False


def _stub_version(
    monkeypatch: pytest.MonkeyPatch, repo_root: Path, version: str = "5.4.1"
) -> None:
    monkeypatch.setattr(
        "tools.setup.ghidra.read_pom_versions",
        lambda _root: VersionInfo(project_version=version, ghidra_version="12.1"),
    )


class TestFindPluginArchive:
    def test_prefers_gradle_output_over_maven(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        _stub_version(monkeypatch, tmp_path)
        gradle_zip = tmp_path / "build" / "distributions" / "GhidraMCP-5.4.1.zip"
        maven_zip = tmp_path / "target" / "GhidraMCP-5.4.1.zip"
        gradle_zip.parent.mkdir(parents=True)
        maven_zip.parent.mkdir(parents=True)
        gradle_zip.write_bytes(b"gradle")
        maven_zip.write_bytes(b"maven")

        assert find_plugin_archive(tmp_path) == gradle_zip

    def test_falls_back_to_maven_target_when_gradle_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        _stub_version(monkeypatch, tmp_path)
        maven_zip = tmp_path / "target" / "GhidraMCP-5.4.1.zip"
        maven_zip.parent.mkdir(parents=True)
        maven_zip.write_bytes(b"maven")

        assert find_plugin_archive(tmp_path) == maven_zip

    def test_finds_versioned_gradle_zip_by_glob_when_name_differs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        _stub_version(monkeypatch, tmp_path)
        dist_dir = tmp_path / "build" / "distributions"
        dist_dir.mkdir(parents=True)
        other_zip = dist_dir / "GhidraMCP-5.4.0.zip"
        other_zip.write_bytes(b"old")

        assert find_plugin_archive(tmp_path) == other_zip

    def test_raises_when_no_archive_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        _stub_version(monkeypatch, tmp_path)

        with pytest.raises(FileNotFoundError, match="build/distributions"):
            find_plugin_archive(tmp_path)


def test_collect_preflight_issues_passes_with_required_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    (ghidra_path / "Extensions" / "Ghidra").mkdir(parents=True)
    (ghidra_path / "ghidraRun.bat").write_text("echo off\n", encoding="utf-8")
    for _artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        jar_path.parent.mkdir(parents=True, exist_ok=True)
        jar_path.write_text("jar", encoding="utf-8")

    (tmp_path / "pyproject.toml").write_text(
        "[dependency-groups]\ndebugger = [\"pybag==2.2.16\"]\n", encoding="utf-8"
    )
    user_base = tmp_path / "user-ghidra"
    (user_base / "ghidra_12.1_PUBLIC").mkdir(parents=True)
    monkeypatch.setattr(
        "tools.setup.ghidra.shutil.which",
        lambda name: "java" if name == "java" else None,
    )

    issues = collect_preflight_issues(
        tmp_path,
        ghidra_path,
        Path(sys.executable),
        install_debugger=True,
        strict=False,
        user_base_dir=user_base,
    )

    assert issues == []


def test_resolve_mcp_url_uses_env_url(tmp_path: Path):
    (tmp_path / ".env").write_text(
        "GHIDRA_MCP_URL=http://127.0.0.1:9999\n", encoding="utf-8"
    )

    assert resolve_mcp_url(tmp_path) == "http://127.0.0.1:9999"


def test_resolve_mcp_url_builds_from_bind_and_port(tmp_path: Path):
    (tmp_path / ".env").write_text(
        "GHIDRA_MCP_BIND_ADDRESS=0.0.0.0\nGHIDRA_MCP_PORT=8090\n",
        encoding="utf-8",
    )

    assert resolve_mcp_url(tmp_path) == "http://127.0.0.1:8090"


def test_resolve_mcp_url_defaults_when_env_missing(tmp_path: Path):
    assert resolve_mcp_url(tmp_path) == DEFAULT_MCP_URL


def test_resolve_deploy_test_modes_defaults_to_cli_only(tmp_path: Path):
    assert resolve_deploy_test_modes(tmp_path, ["selected-contract"]) == [
        "selected-contract"
    ]


def test_resolve_deploy_test_modes_reads_local_env(tmp_path: Path):
    (tmp_path / ".env").write_text(
        "GHIDRA_MCP_DEPLOY_TESTS=release,endpoint-catalog\n", encoding="utf-8"
    )

    assert resolve_deploy_test_modes(tmp_path, []) == ["release", "endpoint-catalog"]


def test_resolve_deploy_test_modes_can_disable_local_env(tmp_path: Path):
    (tmp_path / ".env").write_text("GHIDRA_MCP_DEPLOY_TESTS=off\n", encoding="utf-8")

    assert resolve_deploy_test_modes(tmp_path, []) == []


def test_run_default_smoke_test_requires_key_tools(tmp_path: Path, monkeypatch):
    from tools.setup import ghidra

    schema = {
        "tools": [{"path": f"/{name}"} for name in sorted(ghidra.SMOKE_REQUIRED_TOOLS)]
    }
    monkeypatch.setattr(
        ghidra,
        "_mcp_request",
        lambda repo, url, path, **kwargs: (200, schema),
    )

    run_default_smoke_test(tmp_path, "http://127.0.0.1:8089")


def test_endpoint_catalog_accepts_schema_with_catalog_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    endpoints_dir = tmp_path / "tests"
    endpoints_dir.mkdir()
    (endpoints_dir / "endpoints.json").write_text(
        json.dumps({"endpoints": [{"path": "/one"}, {"path": "/two"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ghidra,
        "_mcp_request",
        lambda repo, url, path, **kwargs: (
            200,
            {"tools": [{"path": "/one"}, {"name": "two"}]},
        ),
    )

    run_endpoint_catalog_test(tmp_path, "http://127.0.0.1:8089")


def test_selected_endpoint_contract_checks_schema_against_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    endpoints_dir = tmp_path / "tests"
    endpoints_dir.mkdir()
    selected = sorted(ghidra.RELEASE_CONTRACT_TOOLS)
    (endpoints_dir / "endpoints.json").write_text(
        json.dumps(
            {
                "endpoints": [
                    {
                        "path": f"/{name}",
                        "method": (
                            "POST"
                            if name in {"create_struct", "delete_file"}
                            else "GET"
                        ),
                        "params": (
                            ["program"] if name != "delete_file" else ["filePath"]
                        ),
                    }
                    for name in selected
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ghidra,
        "_mcp_request",
        lambda repo, url, path, **kwargs: (
            200,
            {
                "tools": [
                    {
                        "path": f"/{name}",
                        "method": (
                            "POST"
                            if name in {"create_struct", "delete_file"}
                            else "GET"
                        ),
                        "params": (
                            [{"name": "filePath"}]
                            if name == "delete_file"
                            else [{"name": "program"}]
                        ),
                    }
                    for name in selected
                ]
            },
        ),
    )

    run_selected_endpoint_contract_test(tmp_path, "http://127.0.0.1:8089")


def test_selected_endpoint_contract_reports_missing_selected_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    endpoints_dir = tmp_path / "tests"
    endpoints_dir.mkdir()
    (endpoints_dir / "endpoints.json").write_text(
        json.dumps({"endpoints": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ghidra,
        "_mcp_request",
        lambda repo, url, path, **kwargs: (200, {"tools": []}),
    )

    with pytest.raises(RuntimeError, match="Release schema missing selected"):
        run_selected_endpoint_contract_test(tmp_path, "http://127.0.0.1:8089")


def test_run_deploy_tests_dispatches_release_tier(monkeypatch: pytest.MonkeyPatch):
    from tools.setup import ghidra

    calls: list[str] = []
    monkeypatch.setattr(
        ghidra, "run_default_smoke_test", lambda *args: calls.append("smoke")
    )
    monkeypatch.setattr(
        ghidra, "reset_benchmark_fixture", lambda *args: calls.append("reset")
    )
    monkeypatch.setattr(
        ghidra, "run_benchmark_read_test", lambda *args: calls.append("read")
    )
    monkeypatch.setattr(
        ghidra, "run_benchmark_write_test", lambda *args: calls.append("write")
    )
    monkeypatch.setattr(
        ghidra, "run_release_regression_tests", lambda *args: calls.append("release")
    )
    monkeypatch.setattr(
        ghidra,
        "_mcp_request",
        lambda *args, **kwargs: calls.append("prompt_policy")
        or (200, {"enabled": True}),
    )

    run_deploy_tests(Path("C:/repo"), "http://127.0.0.1:8089", ["release"])

    assert calls == ["smoke", "prompt_policy", "release"]


def test_run_deploy_tests_default_does_not_import_benchmark(
    monkeypatch: pytest.MonkeyPatch,
):
    from tools.setup import ghidra

    calls: list[str] = []
    monkeypatch.setattr(
        ghidra, "run_default_smoke_test", lambda *args: calls.append("smoke")
    )
    monkeypatch.setattr(
        ghidra, "reset_benchmark_fixture", lambda *args: calls.append("reset")
    )
    monkeypatch.setattr(
        ghidra, "run_benchmark_read_test", lambda *args: calls.append("read")
    )
    monkeypatch.setattr(
        ghidra, "run_benchmark_write_test", lambda *args: calls.append("write")
    )

    run_deploy_tests(Path("C:/repo"), "http://127.0.0.1:8089", [])

    assert calls == ["smoke"]


# ---------------------------------------------------------------------------
# mark_extension_known_in_tool_config — suppress Ghidra's first-run plugin
# dialog by recording the extension as already known. Without this the user
# sees a "new extension found, do you want to enable?" modal that blocks
# Ghidra's startup. Until now it had no direct unit coverage.
# ---------------------------------------------------------------------------


def test_mark_extension_known_promotes_empty_extensions_to_open_form():
    content = (
        "<TOOL>\n"
        "    <EXTENSIONS />\n"
        "</TOOL>"
    )

    updated = mark_extension_known_in_tool_config(content, "GhidraMCP")

    assert "<EXTENSIONS />" not in updated
    assert "<EXTENSIONS>" in updated
    assert '<EXTENSION NAME="GhidraMCP" />' in updated


def test_mark_extension_known_appends_into_existing_open_extensions_block():
    content = (
        "<TOOL>\n"
        "    <EXTENSIONS>\n"
        '        <EXTENSION NAME="OtherExt" />\n'
        "    </EXTENSIONS>\n"
        "</TOOL>"
    )

    updated = mark_extension_known_in_tool_config(content, "GhidraMCP")

    assert updated.count("<EXTENSIONS>") == 1
    assert '<EXTENSION NAME="OtherExt" />' in updated
    assert '<EXTENSION NAME="GhidraMCP" />' in updated


def test_mark_extension_known_is_idempotent():
    content = (
        "<TOOL>\n"
        "    <EXTENSIONS>\n"
        '        <EXTENSION NAME="GhidraMCP" />\n'
        "    </EXTENSIONS>\n"
        "</TOOL>"
    )

    updated = mark_extension_known_in_tool_config(content, "GhidraMCP")

    assert updated == content
    assert updated.count('<EXTENSION NAME="GhidraMCP" />') == 1


def test_mark_extension_known_creates_extensions_block_when_missing():
    content = (
        "<TOOL>\n"
        '    <PACKAGE NAME="Utility" />\n'
        "</TOOL>"
    )

    updated = mark_extension_known_in_tool_config(content, "GhidraMCP")

    assert "<EXTENSIONS>" in updated
    assert '<EXTENSION NAME="GhidraMCP" />' in updated


# ---------------------------------------------------------------------------
# patch_ghidra_user_configs — orchestrator that visits every user-config
# dir under the Ghidra app-data root and patches FrontEndTool.xml /
# tool tcd files. Previously untested.
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_patch_ghidra_user_configs_patches_frontend_tool_xml(tmp_path: Path):
    user_base = tmp_path / "ghidra"
    fe_xml = user_base / "ghidra_12.1_PUBLIC" / "FrontEndTool.xml"
    _write(fe_xml, '<TOOL><PACKAGE NAME="Utility" /></TOOL>')

    patch_ghidra_user_configs(user_base)

    patched = fe_xml.read_text(encoding="utf-8")
    assert PLUGIN_CLASS in patched
    assert '<EXTENSION NAME="GhidraMCP" />' in patched


def test_patch_ghidra_user_configs_dry_run_does_not_modify(tmp_path: Path):
    user_base = tmp_path / "ghidra"
    fe_xml = user_base / "ghidra_12.1_PUBLIC" / "FrontEndTool.xml"
    original = '<TOOL><PACKAGE NAME="Utility" /></TOOL>'
    _write(fe_xml, original)

    patch_ghidra_user_configs(user_base, dry_run=True)

    assert fe_xml.read_text(encoding="utf-8") == original


def test_patch_ghidra_user_configs_handles_missing_user_base(tmp_path: Path):
    """A missing user-config dir is a no-op, not an error. Ghidra creates
    the dir lazily on first run; patching shouldn't blow up if the user
    has never launched Ghidra of that version."""
    missing = tmp_path / "no-such-dir"

    patch_ghidra_user_configs(missing)


def test_patch_ghidra_user_configs_strips_stale_codebrowser_tcd(tmp_path: Path):
    """Stale tcd files from older Ghidra versions get the GhidraMCP
    PACKAGE block removed (the plugin lives in FrontEnd now). The
    deploy depends on this cleanup to avoid double-registration."""
    user_base = tmp_path / "ghidra"
    tcd = user_base / "ghidra_12.1_PUBLIC" / "tools" / "_code_browser.tcd"
    _write(
        tcd,
        (
            "<TOOL>\n"
            '    <PACKAGE NAME="GhidraMCP">\n'
            f'        <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
            "    </PACKAGE>\n"
            "</TOOL>"
        ),
    )

    patch_ghidra_user_configs(user_base)

    patched = tcd.read_text(encoding="utf-8")
    assert PLUGIN_CLASS not in patched
    assert 'PACKAGE NAME="GhidraMCP"' not in patched
    assert '<EXTENSION NAME="GhidraMCP" />' in patched


def test_patch_ghidra_user_configs_idempotent_second_call_no_op(tmp_path: Path):
    """Re-running the deploy when configs are already patched must not
    duplicate INCLUDE entries or grow the file unboundedly."""
    user_base = tmp_path / "ghidra"
    fe_xml = user_base / "ghidra_12.1_PUBLIC" / "FrontEndTool.xml"
    _write(fe_xml, '<TOOL><PACKAGE NAME="Utility" /></TOOL>')

    patch_ghidra_user_configs(user_base)
    after_first = fe_xml.read_text(encoding="utf-8")

    patch_ghidra_user_configs(user_base)
    after_second = fe_xml.read_text(encoding="utf-8")

    assert after_first == after_second
    assert after_second.count(PLUGIN_CLASS) == 1
    assert after_second.count('<EXTENSION NAME="GhidraMCP" />') == 1


# ---------------------------------------------------------------------------
# #217: target-only patching. A deploy targeting Ghidra 12.1 must NOT
# touch user-config dirs from older Ghidra installs sitting next to it.
# Observed twice in production logs (v5.10→v5.11 and the v5.11.2 deploy):
#     Patched FrontEnd config …/ghidra_12.0.4_PUBLIC/FrontEndTool.xml
#     Patched FrontEnd config …/ghidra_12.1_PUBLIC/FrontEndTool.xml
# Only the second line should ever appear.
# ---------------------------------------------------------------------------


def test_patch_ghidra_user_configs_target_dir_only_touches_target(tmp_path: Path):
    """When target_user_dir is supplied, sibling version dirs are skipped."""
    user_base = tmp_path / "ghidra"
    target = user_base / "ghidra_12.1_PUBLIC"
    sibling_old = user_base / "ghidra_12.0.4_PUBLIC"
    sibling_dev = user_base / "ghidra_11.4.2"

    template = '<TOOL><PACKAGE NAME="Utility" /></TOOL>'
    _write(target / "FrontEndTool.xml", template)
    _write(sibling_old / "FrontEndTool.xml", template)
    _write(sibling_dev / "FrontEndTool.xml", template)

    patch_ghidra_user_configs(user_base, target)

    assert PLUGIN_CLASS in (target / "FrontEndTool.xml").read_text(encoding="utf-8")
    # The two sibling dirs must remain untouched — those config files
    # belong to other Ghidra installs and stamping our 12.1 INCLUDE there
    # would point them at an extension that isn't installed.
    assert (sibling_old / "FrontEndTool.xml").read_text(encoding="utf-8") == template
    assert (sibling_dev / "FrontEndTool.xml").read_text(encoding="utf-8") == template


def test_patch_ghidra_user_configs_target_dir_only_touches_target_tcd(tmp_path: Path):
    """Same scope guarantee for tool tcd files, which carry historical
    GhidraMCP PACKAGE blocks that should be cleared only in the target."""
    user_base = tmp_path / "ghidra"
    target = user_base / "ghidra_12.1_PUBLIC"
    sibling = user_base / "ghidra_12.0.4_PUBLIC"

    stale_tcd = (
        "<TOOL>\n"
        '    <PACKAGE NAME="GhidraMCP">\n'
        f'        <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
        "    </PACKAGE>\n"
        "</TOOL>"
    )
    _write(target / "tools" / "_code_browser.tcd", stale_tcd)
    _write(sibling / "tools" / "_code_browser.tcd", stale_tcd)

    patch_ghidra_user_configs(user_base, target)

    assert PLUGIN_CLASS not in (target / "tools" / "_code_browser.tcd").read_text(encoding="utf-8")
    # Sibling tcd must keep its (stale) PACKAGE block — leaving it for
    # whatever Ghidra version actually owns that user dir.
    assert (sibling / "tools" / "_code_browser.tcd").read_text(encoding="utf-8") == stale_tcd


def test_patch_ghidra_user_configs_target_dir_missing_is_no_op(tmp_path: Path):
    """When the target user dir doesn't exist yet (Ghidra hasn't been
    launched once after install), the call should be a clean no-op
    rather than falling back to the broad glob."""
    user_base = tmp_path / "ghidra"
    sibling = user_base / "ghidra_12.0.4_PUBLIC"
    template = '<TOOL><PACKAGE NAME="Utility" /></TOOL>'
    _write(sibling / "FrontEndTool.xml", template)

    nonexistent_target = user_base / "ghidra_12.1_PUBLIC"
    patch_ghidra_user_configs(user_base, nonexistent_target)

    # Sibling was NOT touched even though it has a patchable config —
    # the target dir's absence must not silently fall back to the
    # broad-glob legacy behavior.
    assert (sibling / "FrontEndTool.xml").read_text(encoding="utf-8") == template


def test_patch_ghidra_user_configs_no_target_keeps_legacy_glob(tmp_path: Path):
    """Calling without target_user_dir keeps the historical
    glob-everything behavior — back-compat for anyone calling this
    helper directly without going through deploy_to_ghidra."""
    user_base = tmp_path / "ghidra"
    dir_a = user_base / "ghidra_12.1_PUBLIC"
    dir_b = user_base / "ghidra_12.0.4_PUBLIC"
    template = '<TOOL><PACKAGE NAME="Utility" /></TOOL>'
    _write(dir_a / "FrontEndTool.xml", template)
    _write(dir_b / "FrontEndTool.xml", template)

    patch_ghidra_user_configs(user_base)  # no target — old behavior

    assert PLUGIN_CLASS in (dir_a / "FrontEndTool.xml").read_text(encoding="utf-8")
    assert PLUGIN_CLASS in (dir_b / "FrontEndTool.xml").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Debugger-live test environmental skip. The release-tier deploy used to
# fail outright on machines without the Windows Debugger Toolkit / a
# built BenchmarkDebug.exe — masking real test results as "release tier
# is broken." A DebuggerLiveTestSkipped sentinel exception now lets the
# caller turn those environmental gaps into a SKIPPED line without
# failing the gate.
# ---------------------------------------------------------------------------


def test_debugger_live_skipped_on_non_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    monkeypatch.setattr(ghidra.os, "name", "posix")
    with pytest.raises(ghidra.DebuggerLiveTestSkipped, match="Windows-only"):
        ghidra.run_debugger_live_test(tmp_path, "http://127.0.0.1:8089")


def test_debugger_live_skipped_when_benchmarkdebug_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    monkeypatch.setattr(ghidra.os, "name", "nt")
    # Fresh tmp_path → no BenchmarkDebug.exe at the expected location.
    with pytest.raises(ghidra.DebuggerLiveTestSkipped, match="BenchmarkDebug.exe"):
        ghidra.run_debugger_live_test(tmp_path, "http://127.0.0.1:8089")


def test_debugger_live_skipped_on_environmental_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A /debugger/launch failure whose error matches a known-environmental
    hint (no WDK, ghidratrace mismatch, dbgeng missing) gets re-classified
    as a skip, not a regression."""
    from tools.setup import ghidra

    monkeypatch.setattr(ghidra.os, "name", "nt")
    # Pretend BenchmarkDebug.exe exists so we reach the launch path.
    benchmark_path = tmp_path / ghidra.DEFAULT_BENCHMARK_DEBUG_EXE
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_bytes(b"")

    def fake_mcp_request(repo_root, mcp_url, path, **kwargs):
        return 200, {"error": "Debugger launch failed using 'dbgeng (.bat)': null"}

    monkeypatch.setattr(ghidra, "_mcp_request", fake_mcp_request)
    monkeypatch.setattr(ghidra, "load_env_file", lambda _p: {})
    # The function's `finally:` block calls _terminate_processes_by_name
    # which spawns `taskkill` when os.name == "nt". On Linux CI that
    # binary doesn't exist and the subprocess.run raises FileNotFoundError
    # *out of the finally*, masking the test's actual outcome. Stub.
    monkeypatch.setattr(ghidra, "_terminate_processes_by_name", lambda _name: None)

    with pytest.raises(ghidra.DebuggerLiveTestSkipped, match="Debugger backend unavailable"):
        ghidra.run_debugger_live_test(tmp_path, "http://127.0.0.1:8089")


def test_debugger_live_raises_runtime_error_on_real_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A non-environmental error (something the test actually caught)
    must still bubble up as RuntimeError so the release gate fails."""
    from tools.setup import ghidra

    monkeypatch.setattr(ghidra.os, "name", "nt")
    benchmark_path = tmp_path / ghidra.DEFAULT_BENCHMARK_DEBUG_EXE
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_bytes(b"")

    def fake_mcp_request(repo_root, mcp_url, path, **kwargs):
        return 200, {"error": "Unexpected internal state in trace handler"}

    monkeypatch.setattr(ghidra, "_mcp_request", fake_mcp_request)
    monkeypatch.setattr(ghidra, "load_env_file", lambda _p: {})
    monkeypatch.setattr(ghidra, "_terminate_processes_by_name", lambda _name: None)

    # Real test failure must NOT be swallowed as a skip.
    with pytest.raises(RuntimeError, match="Unexpected internal state"):
        ghidra.run_debugger_live_test(tmp_path, "http://127.0.0.1:8089")


# ---------------------------------------------------------------------------
# install_ghidratrace_for_debugger — keep the launcher Python's ghidratrace
# wheel in sync with the installed Ghidra. Misalignment caused the
# VersionMismatchError observed three times in this release cycle: an old
# 12.0 wheel was pip-installed in the launcher's Python (the one named by
# GHIDRA_DEBUGGER_PYTHON in .env) and shadowed the bundled 12.1 source.
# ---------------------------------------------------------------------------


def test_resolve_debugger_python_prefers_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    fake_py = tmp_path / "ms-store-python.exe"
    fake_py.write_text("", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_DEBUGGER_PYTHON", str(fake_py))
    resolved = ghidra._resolve_debugger_python(tmp_path)
    assert resolved == fake_py


def test_resolve_debugger_python_falls_back_to_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    monkeypatch.delenv("GHIDRA_DEBUGGER_PYTHON", raising=False)
    fake_py = tmp_path / "dotenv-python.exe"
    fake_py.write_text("", encoding="utf-8")
    (tmp_path / ".env").write_text(
        f"GHIDRA_DEBUGGER_PYTHON={fake_py}\n", encoding="utf-8"
    )
    resolved = ghidra._resolve_debugger_python(tmp_path)
    assert resolved == fake_py


def test_install_ghidratrace_skips_when_no_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    from tools.setup import ghidra

    monkeypatch.delenv("GHIDRA_DEBUGGER_PYTHON", raising=False)
    fake_ghidra = tmp_path / "ghidra_install"
    fake_ghidra.mkdir()
    rc = ghidra.install_ghidratrace_for_debugger(tmp_path, fake_ghidra)
    assert rc == 0
    assert "No ghidratrace wheel found" in capsys.readouterr().out


def test_install_ghidratrace_dry_run_does_not_invoke_pip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    from tools.setup import ghidra

    # Build a fake wheel and a fake Python.
    wheel_dir = tmp_path / "ghidra_install" / "Ghidra" / "Debug" / "Debugger-rmi-trace" / "pypkg" / "dist"
    wheel_dir.mkdir(parents=True)
    wheel = wheel_dir / "ghidratrace-12.1-py3-none-any.whl"
    wheel.write_bytes(b"")
    fake_py = tmp_path / "debugger-python.exe"
    fake_py.write_text("", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_DEBUGGER_PYTHON", str(fake_py))

    # subprocess.run must NOT be invoked in dry-run mode.
    def fail_if_called(*_a, **_kw):
        raise AssertionError("subprocess.run must not run in dry_run mode")

    monkeypatch.setattr(ghidra.subprocess, "run", fail_if_called)
    rc = ghidra.install_ghidratrace_for_debugger(
        tmp_path, tmp_path / "ghidra_install", dry_run=True
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "ghidratrace-12.1" in out


def test_install_ghidratrace_invokes_pip_with_force_reinstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from tools.setup import ghidra

    wheel_dir = tmp_path / "ghidra_install" / "Ghidra" / "Debug" / "Debugger-rmi-trace" / "pypkg" / "dist"
    wheel_dir.mkdir(parents=True)
    wheel = wheel_dir / "ghidratrace-12.1-py3-none-any.whl"
    wheel.write_bytes(b"")
    fake_py = tmp_path / "debugger-python.exe"
    fake_py.write_text("", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_DEBUGGER_PYTHON", str(fake_py))

    invocations: list[list[str]] = []

    class FakeCompleted:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kwargs):
        invocations.append(list(cmd))
        return FakeCompleted()

    monkeypatch.setattr(ghidra.subprocess, "run", fake_run)
    rc = ghidra.install_ghidratrace_for_debugger(
        tmp_path, tmp_path / "ghidra_install"
    )
    assert rc == 0
    assert len(invocations) == 2, (
        "expected 2 pip invocations (protobuf + ghidratrace)"
    )
    # First: protobuf upgrade
    assert invocations[0][0] == str(fake_py)
    assert invocations[0][1:5] == ["-m", "pip", "install", "--upgrade"]
    assert any("protobuf" in arg for arg in invocations[0])
    # Second: ghidratrace --force-reinstall pointing at the bundled wheel
    assert invocations[1][1:5] == ["-m", "pip", "install", "--force-reinstall"]
    assert str(wheel) in invocations[1]


def test_run_release_regression_catches_debugger_skip(
    monkeypatch: pytest.MonkeyPatch, capsys
):
    """When debugger-live throws DebuggerLiveTestSkipped, the release
    regression tier prints SKIPPED and reports success — does NOT fail
    the gate."""
    from tools.setup import ghidra

    def fake_skipped(*args, **kwargs):
        raise ghidra.DebuggerLiveTestSkipped("test reason here")

    # Stub every other tier step so we isolate the skip handling.
    for name in (
        "reset_benchmark_fixture",
        "run_selected_endpoint_contract_test",
        "run_benchmark_extended_read_test",
        "run_benchmark_yaml_regression",
        "run_multi_program_targeting_test",
        "run_negative_contract_test",
    ):
        monkeypatch.setattr(ghidra, name, lambda *_args, **_kw: None)
    monkeypatch.setattr(ghidra, "run_debugger_live_test", fake_skipped)

    ghidra.run_release_regression_tests(Path("C:/repo"), "http://127.0.0.1:8089")

    out = capsys.readouterr().out
    assert "SKIPPED debugger live test: test reason here" in out
    assert "Release regression tier passed." in out
