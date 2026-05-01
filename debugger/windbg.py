"""Helpers for resolving a usable WinDbg runtime for pybag."""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Iterable, MutableMapping, Optional

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows test environments
    winreg = None  # type: ignore[assignment]


_REQUIRED_DLLS = ("dbgeng.dll", "dbghelp.dll", "dbgmodel.dll")
_PACKAGE_REPOSITORY = (
    r"Local Settings\Software\Microsoft\Windows\CurrentVersion"
    r"\AppModel\PackageRepository\Packages"
)


def _sdk_arch_dir() -> str:
    return "x64" if platform.architecture()[0] == "64bit" else "x86"


def _store_arch_dir() -> str:
    return "amd64" if platform.architecture()[0] == "64bit" else "x86"


def has_required_dbgeng_dlls(path: Optional[Path | str]) -> bool:
    if not path:
        return False
    candidate = Path(path)
    return candidate.is_dir() and all((candidate / dll_name).is_file() for dll_name in _REQUIRED_DLLS)


def _iter_sdk_candidates() -> Iterable[Path]:
    seen: set[Path] = set()

    def add(candidate: Optional[Path]) -> Iterable[Path]:
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield candidate

    if winreg is not None:
        try:
            roots_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
            )
            try:
                kits_root = Path(winreg.QueryValueEx(roots_key, "KitsRoot10")[0])
            finally:
                winreg.CloseKey(roots_key)
            yield from add(kits_root / "Debuggers" / _sdk_arch_dir())
        except FileNotFoundError:
            pass

    for base in (
        Path(r"C:\Program Files\Windows Kits\10"),
        Path(r"C:\Program Files (x86)\Windows Kits\10"),
    ):
        yield from add(base / "Debuggers" / _sdk_arch_dir())


def _find_store_install() -> Optional[Path]:
    if winreg is None:
        return None

    packages_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, _PACKAGE_REPOSITORY)
    try:
        index = 0
        while True:
            try:
                package_name = winreg.EnumKey(packages_key, index)
            except OSError:
                return None
            index += 1
            if "WinDbg" not in package_name or "_neutral_" in package_name:
                continue
            candidate = Path(r"C:\Program Files\WindowsApps") / package_name / _store_arch_dir()
            if candidate.is_dir():
                return candidate
    finally:
        winreg.CloseKey(packages_key)


def _cache_store_install(store_dir: Path, localappdata: Optional[Path | str] = None) -> Path:
    local_root = Path(localappdata) if localappdata else Path(os.environ.get("LOCALAPPDATA", ""))
    if not local_root:
        return store_dir

    cache_dir = local_root / "ghidra_mcp_pybag_cache"
    version_file = cache_dir / "version.txt"

    def rebuild_cache() -> None:
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        for dll_name in _REQUIRED_DLLS:
            shutil.copy2(store_dir / dll_name, cache_dir / dll_name)
        version_file.write_text(str(store_dir), encoding="utf-8")

    if not cache_dir.is_dir():
        rebuild_cache()
    else:
        cached_source = version_file.read_text(encoding="utf-8") if version_file.is_file() else ""
        if cached_source != str(store_dir) or not has_required_dbgeng_dlls(cache_dir):
            rebuild_cache()

    return cache_dir


def resolve_windbg_dir(
    env: Optional[MutableMapping[str, str]] = None,
    sdk_candidates: Optional[Iterable[Path]] = None,
    store_install: Optional[Path] = None,
    localappdata: Optional[Path | str] = None,
) -> Optional[Path]:
    runtime_env = env if env is not None else os.environ

    explicit = runtime_env.get("WINDBG_DIR")
    if has_required_dbgeng_dlls(explicit):
        return Path(explicit)

    candidates = list(sdk_candidates) if sdk_candidates is not None else list(_iter_sdk_candidates())
    for candidate in candidates:
        if has_required_dbgeng_dlls(candidate):
            return candidate

    discovered_store = store_install if store_install is not None else _find_store_install()
    if discovered_store and has_required_dbgeng_dlls(discovered_store):
        return _cache_store_install(discovered_store, localappdata=localappdata)

    return None


def ensure_windbg_dir(
    env: Optional[MutableMapping[str, str]] = None,
    sdk_candidates: Optional[Iterable[Path]] = None,
    store_install: Optional[Path] = None,
    localappdata: Optional[Path | str] = None,
) -> Optional[Path]:
    runtime_env = env if env is not None else os.environ
    resolved = resolve_windbg_dir(
        env=runtime_env,
        sdk_candidates=sdk_candidates,
        store_install=store_install,
        localappdata=localappdata,
    )
    if resolved is not None:
        runtime_env["WINDBG_DIR"] = str(resolved)
    return resolved
