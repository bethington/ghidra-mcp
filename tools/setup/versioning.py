from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VersionInfo:
    project_version: str
    ghidra_version: str


def read_pom_versions(repo_root: Path) -> VersionInfo:
    pom_path = repo_root / "pom.xml"
    tree = ET.parse(pom_path)
    root = tree.getroot()
    namespace = (
        {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    )

    def find_text(path: str) -> str:
        if namespace:
            node = root.find(path, namespace)
        else:
            node = root.find(path)
        if node is None or node.text is None:
            raise ValueError(f"Missing expected XML element: {path}")
        return node.text.strip()

    return VersionInfo(
        project_version=find_text("m:version" if namespace else "version"),
        ghidra_version=find_text(
            "m:properties/m:ghidra.version"
            if namespace
            else "properties/ghidra.version"
        ),
    )


_GHIDRA_PATH_RE = re.compile(r"ghidra_([0-9]+(?:\.[0-9]+){1,3})_(PUBLIC|DEV)")


def infer_ghidra_install_meta(ghidra_path: Path) -> tuple[str | None, str | None]:
    """Return ``(version, layout)`` for a Ghidra install path.

    ``layout`` is ``"PUBLIC"`` or ``"DEV"`` when the path follows the
    standard ``ghidra_<version>_<layout>`` naming used by official
    release zips, otherwise ``None``. ``version`` is recovered from the
    path name first and falls back to ``Ghidra/application.properties``.

    Both are needed to construct the user-config dir name explicitly —
    see #217: enumerating ``%APPDATA%\\ghidra\\*`` silently picks a stale
    ``_DEV`` sibling when the target ``_PUBLIC`` dir hasn't been
    created yet (Ghidra creates it lazily on first launch).
    """
    match = _GHIDRA_PATH_RE.search(str(ghidra_path))
    if match:
        return match.group(1), match.group(2)

    props_path = ghidra_path / "Ghidra" / "application.properties"
    if not props_path.is_file():
        return None, None

    version: str | None = None
    for line in props_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("application.version="):
            version = stripped.split("=", 1)[1].strip()
            break
    return version, None


def infer_ghidra_version_from_path(ghidra_path: Path) -> str | None:
    return infer_ghidra_install_meta(ghidra_path)[0]


def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in version.strip().split("."):
        match = re.match(r"\d+", chunk)
        if not match:
            break
        parts.append(int(match.group()))
    return tuple(parts)


def is_ghidra_version_compatible(required: str, installed: str) -> bool:
    """Return True when an installed Ghidra version satisfies the pom requirement.

    The pom pins ``ghidra.version`` to a major.minor series (e.g. ``12.1``).
    Ghidra's API is stable within a minor series, so any patch release of that
    series — ``12.1.0``, ``12.1.2``, ... — is compatible (see #293: ``12.1``
    pinned vs a ``12.1.2`` install should not error). Compatibility is decided
    on the shared major.minor prefix; patch and build components are ignored.
    """
    req = _version_tuple(required)[:2]
    inst = _version_tuple(installed)[:2]
    if not req or not inst:
        return required.strip() == installed.strip()
    return req == inst
