"""Unit tests for tools.setup.versioning — Ghidra version compatibility (#293).

The pom pins ``ghidra.version`` to a major.minor series; an installed Ghidra of
any patch release in that series must be accepted instead of hard-failing the
preflight/verify-version check (firefart's ``12.1`` pinned vs ``12.1.2`` install).
"""
from __future__ import annotations

import pytest

from tools.setup.versioning import is_ghidra_version_compatible


@pytest.mark.parametrize(
    "required,installed",
    [
        ("12.1", "12.1.2"),   # #293: pinned minor, patch install
        ("12.1", "12.1"),     # exact
        ("12.1", "12.1.0"),   # explicit .0 patch
        ("12.1.2", "12.1"),   # pinned patch, minor install — same series
        ("12.1.0", "12.1.9"), # patch drift within series
        ("12.1", "12.1.2.1"), # four-component build install
    ],
)
def test_compatible_within_minor_series(required: str, installed: str) -> None:
    assert is_ghidra_version_compatible(required, installed) is True


@pytest.mark.parametrize(
    "required,installed",
    [
        ("12.1", "12.2"),    # different minor
        ("12.1", "12.0.4"),  # different minor (older)
        ("12.1", "11.1"),    # different major
        ("12.1", "13.1.2"),  # different major (newer)
    ],
)
def test_incompatible_across_minor_or_major(required: str, installed: str) -> None:
    assert is_ghidra_version_compatible(required, installed) is False


@pytest.mark.parametrize(
    "required,installed,expected",
    [
        ("", "12.1", False),       # unparseable required -> exact-string fallback
        ("12.1", "", False),       # unparseable installed -> exact-string fallback
        ("weird", "weird", True),  # identical unparseable strings still match
    ],
)
def test_unparseable_falls_back_to_exact_match(
    required: str, installed: str, expected: bool
) -> None:
    assert is_ghidra_version_compatible(required, installed) is expected
