from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tools.setup.ghidra import (
    DEFAULT_MCP_URL,
    PLUGIN_CLASS,
    REQUIRED_GHIDRA_JARS,
    collect_preflight_issues,
    find_plugin_archive,
    patch_codebrowser_tcd,
    patch_frontend_tool_config,
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
    matching_dir = user_base / "ghidra_12.0.4_PUBLIC"
    other_dir = user_base / "ghidra_12.0.3_PUBLIC"
    matching_dir.mkdir(parents=True)
    other_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/ghidra_12.0.4_PUBLIC"), user_base)

    assert resolved == matching_dir


def test_resolve_ghidra_user_dir_falls_back_to_latest_existing_dir(tmp_path: Path):
    user_base = tmp_path / "ghidra"
    latest_dir = user_base / "ghidra_12.1.0_PUBLIC"
    older_dir = user_base / "ghidra_12.0.4_PUBLIC"
    latest_dir.mkdir(parents=True)
    older_dir.mkdir(parents=True)

    resolved = resolve_ghidra_user_dir(Path("F:/custom-ghidra-install"), user_base)

    assert resolved == latest_dir


def test_collect_preflight_issues_reports_missing_jar_and_debugger_requirements(
    tmp_path: Path,
):
    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
    (ghidra_path / "Extensions" / "Ghidra").mkdir(parents=True)
    (ghidra_path / "ghidraRun.bat").write_text("echo off\n", encoding="utf-8")
    user_base = tmp_path / "user-ghidra"
    (user_base / "ghidra_12.0.4_PUBLIC").mkdir(parents=True)

    issues = collect_preflight_issues(
        tmp_path,
        ghidra_path,
        Path(sys.executable),
        install_debugger=True,
        strict=False,
        user_base_dir=user_base,
    )

    assert any("Missing required Ghidra dependency" in issue for issue in issues)
    assert any("Debugger requirements file not found" in issue for issue in issues)


def _stub_version(
    monkeypatch: pytest.MonkeyPatch, repo_root: Path, version: str = "5.4.1"
) -> None:
    monkeypatch.setattr(
        "tools.setup.ghidra.read_pom_versions",
        lambda _root: VersionInfo(project_version=version, ghidra_version="12.0.4"),
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
    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
    (ghidra_path / "Extensions" / "Ghidra").mkdir(parents=True)
    (ghidra_path / "ghidraRun.bat").write_text("echo off\n", encoding="utf-8")
    for _artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        jar_path.parent.mkdir(parents=True, exist_ok=True)
        jar_path.write_text("jar", encoding="utf-8")

    (tmp_path / "requirements-debugger.txt").write_text(
        "pybag==1.0\n", encoding="utf-8"
    )
    user_base = tmp_path / "user-ghidra"
    (user_base / "ghidra_12.0.4_PUBLIC").mkdir(parents=True)
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
    assert resolve_deploy_test_modes(tmp_path, ["selected-contract"]) == ["selected-contract"]


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
        "tools": [
            {"path": f"/{name}"}
            for name in sorted(ghidra.SMOKE_REQUIRED_TOOLS)
        ]
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
                        "method": "POST" if name in {"create_struct", "delete_file"} else "GET",
                        "params": ["program"] if name != "delete_file" else ["filePath"],
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
                        "method": "POST" if name in {"create_struct", "delete_file"} else "GET",
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
    monkeypatch.setattr(ghidra, "run_default_smoke_test", lambda *args: calls.append("smoke"))
    monkeypatch.setattr(ghidra, "reset_benchmark_fixture", lambda *args: calls.append("reset"))
    monkeypatch.setattr(ghidra, "run_benchmark_read_test", lambda *args: calls.append("read"))
    monkeypatch.setattr(ghidra, "run_benchmark_write_test", lambda *args: calls.append("write"))
    monkeypatch.setattr(ghidra, "run_release_regression_tests", lambda *args: calls.append("release"))
    monkeypatch.setattr(
        ghidra,
        "_mcp_request",
        lambda *args, **kwargs: calls.append("prompt_policy") or (200, {"enabled": True}),
    )

    run_deploy_tests(Path("C:/repo"), "http://127.0.0.1:8089", ["release"])

    assert calls == ["smoke", "prompt_policy", "release"]


def test_run_deploy_tests_default_does_not_import_benchmark(monkeypatch: pytest.MonkeyPatch):
    from tools.setup import ghidra

    calls: list[str] = []
    monkeypatch.setattr(ghidra, "run_default_smoke_test", lambda *args: calls.append("smoke"))
    monkeypatch.setattr(ghidra, "reset_benchmark_fixture", lambda *args: calls.append("reset"))
    monkeypatch.setattr(ghidra, "run_benchmark_read_test", lambda *args: calls.append("read"))
    monkeypatch.setattr(ghidra, "run_benchmark_write_test", lambda *args: calls.append("write"))

    run_deploy_tests(Path("C:/repo"), "http://127.0.0.1:8089", [])

    assert calls == ["smoke"]
