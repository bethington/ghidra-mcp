"""Unit tests for debugger/windbg.py runtime resolution."""

from __future__ import annotations

from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from debugger.windbg import ensure_windbg_dir, has_required_dbgeng_dlls, resolve_windbg_dir


def create_dbg_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for dll_name in ("dbgeng.dll", "dbghelp.dll", "dbgmodel.dll"):
        (path / dll_name).write_text(dll_name, encoding="utf-8")
    return path


def test_has_required_dbgeng_dlls(tmp_path):
    valid = create_dbg_dir(tmp_path / "valid")
    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "dbghelp.dll").write_text("dbghelp", encoding="utf-8")

    assert has_required_dbgeng_dlls(valid) is True
    assert has_required_dbgeng_dlls(invalid) is False


def test_resolve_windbg_dir_skips_invalid_env_when_sdk_candidate_is_valid(tmp_path):
    invalid_env = tmp_path / "invalid-env"
    invalid_env.mkdir()
    valid_sdk = create_dbg_dir(tmp_path / "sdk")

    env = {"WINDBG_DIR": str(invalid_env)}
    result = resolve_windbg_dir(env=env, sdk_candidates=[valid_sdk], store_install=None)

    assert result == valid_sdk


def test_resolve_windbg_dir_caches_store_install(tmp_path):
    store_install = create_dbg_dir(tmp_path / "store")
    localappdata = tmp_path / "localappdata"
    localappdata.mkdir()

    result = resolve_windbg_dir(
        env={},
        sdk_candidates=[],
        store_install=store_install,
        localappdata=localappdata,
    )

    assert result == localappdata / "ghidra_mcp_pybag_cache"
    assert has_required_dbgeng_dlls(result)
    assert (result / "version.txt").read_text(encoding="utf-8") == str(store_install)


def test_ensure_windbg_dir_updates_environment(tmp_path):
    valid_sdk = create_dbg_dir(tmp_path / "sdk")
    env = {}

    ensure_windbg_dir(env=env, sdk_candidates=[valid_sdk], store_install=None)

    assert env["WINDBG_DIR"] == str(valid_sdk)
