"""Every place that downloads Ghidra must name the same, real release asset.

Ghidra's asset filename carries a build date (``ghidra_12.2_PUBLIC_20261016.zip``)
that a version retarget has to copy by hand into four places. The 12.2
retarget updated ``tests.yml`` and the Dockerfile but left ``release.yml`` and
``pre-release.yml`` on a guessed date. Every PR stayed green, because only
``tests.yml`` runs on a PR, and the v7.1.0 tag push then failed with
``ERROR 404: Not Found`` before building anything. Nothing could catch it
earlier: the release workflows run only on a tag.

This test reads the pins straight out of each file, with no network access,
and requires them to agree with each other and with ``pom.xml``'s
``ghidra.version``. It cannot prove the date is right, but a wrong date can no
longer hide in a workflow that PRs never run.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _pom_ghidra_version() -> str:
    match = re.search(r"<ghidra\.version>([^<]+)</ghidra\.version>", _read(REPO / "pom.xml"))
    assert match, "pom.xml has no <ghidra.version>"
    return match.group(1).strip()


def _env_pin(path: Path) -> tuple[str, str]:
    """(version, date) from a workflow's top-level env block."""
    text = _read(path)
    version = re.search(r'^\s*GHIDRA_VERSION:\s*"?([\d.]+)"?\s*$', text, re.M)
    date = re.search(r'^\s*GHIDRA_DATE:\s*"?(\d{8})"?\s*$', text, re.M)
    assert version and date, f"{path.name}: GHIDRA_VERSION/GHIDRA_DATE env not found"
    return version.group(1), date.group(1)


def _literal_url_pins(path: Path) -> set[tuple[str, str]]:
    """(version, date) for every literal Ghidra asset URL in a file."""
    found = re.findall(r"ghidra_([\d.]+)_PUBLIC_(\d{8})\.zip", _read(path))
    return set(found)


def _dockerfile_pin() -> tuple[str, str]:
    text = _read(REPO / "docker" / "Dockerfile")
    version = re.search(r"^ARG GHIDRA_VERSION=([\d.]+)\s*$", text, re.M)
    date = re.search(r"^ARG GHIDRA_DATE=(\d{8})\s*$", text, re.M)
    assert version and date, "docker/Dockerfile: GHIDRA_VERSION/GHIDRA_DATE ARGs not found"
    return version.group(1), date.group(1)


def _all_pins() -> dict[str, tuple[str, str]]:
    pins = {
        "release.yml": _env_pin(WORKFLOWS / "release.yml"),
        "pre-release.yml": _env_pin(WORKFLOWS / "pre-release.yml"),
        "docker/Dockerfile": _dockerfile_pin(),
    }
    tests_urls = _literal_url_pins(WORKFLOWS / "tests.yml")
    assert len(tests_urls) == 1, f"tests.yml: expected one Ghidra asset URL, found {tests_urls}"
    pins["tests.yml"] = next(iter(tests_urls))
    return pins


def test_every_ghidra_download_names_the_same_asset():
    pins = _all_pins()
    assert len(set(pins.values())) == 1, (
        "Ghidra download pins disagree; a release workflow that 404s fails only on the tag push:\n"
        + "\n".join(f"  {name}: ghidra_{v}_PUBLIC_{d}.zip" for name, (v, d) in sorted(pins.items()))
    )


def test_ghidra_download_version_matches_pom():
    pom = _pom_ghidra_version()
    for name, (version, _date) in _all_pins().items():
        assert version == pom, f"{name} downloads Ghidra {version}; pom.xml builds against {pom}"


def test_tests_yml_cache_key_names_the_same_build():
    """A stale cache key restores the old build and skips the download step entirely."""
    text = _read(WORKFLOWS / "tests.yml")
    keys = set(re.findall(r"key:\s*ghidra-([\d.]+)-PUBLIC-(\d{8})", text))
    assert keys == {_all_pins()["tests.yml"]}, f"tests.yml cache key {keys} does not match its download URL"


@pytest.mark.parametrize("workflow", ["release.yml", "pre-release.yml"])
def test_release_workflows_build_the_url_from_their_env(workflow: str):
    """The env pin is what the test checks; a hard-coded URL beside it would bypass it."""
    text = _read(WORKFLOWS / workflow)
    assert "ghidra_${{ env.GHIDRA_VERSION }}_PUBLIC_${{ env.GHIDRA_DATE }}.zip" in text
    assert not _literal_url_pins(WORKFLOWS / workflow), f"{workflow} hard-codes a Ghidra asset URL"
