"""Every published tool/endpoint count must agree with ``tests/endpoints.json``.

The catalog is the authoritative repo snapshot. Before this file existed, six
surfaces disagreed with it and with each other at the same commit:
``README.md`` said 272 in one place and 253 in another, ``extension.properties``
said 267, ``AGENTS.md`` said 267, ``CLAUDE.md``'s Tool Inventory said 272 while
its own overview said 253, and ``docs/releases/README.md`` described 7.0.0 as
shipping 251. Nothing compared them, so each one drifted on its own schedule.

Three rules, all learned from release notes that published a wrong number:

1. **Counts are derived, never restated.** Everything here comes from
   ``tools.audit_server_scope.release_counts()`` -- the same function
   ``.github/workflows/release.yml`` reads. A literal in this file would be a
   seventh place to drift.

2. **Nothing gets a fallback.** ``release.yml`` once grepped a deleted file with
   ``|| echo "0"`` and published ``Headless Endpoints: 1`` for two releases
   running, because a suppressed read error looked like a legitimate number. So
   a marker that cannot be found here is a **failure**, not a skip: a reworded
   sentence must fail loudly and say which pattern stopped matching, because a
   pattern that silently matches nothing is a test that cannot fail.

3. **The count is not one number.** The two HTTP servers do not serve the same
   routes, so a figure is only meaningful once you say what it counts. Each
   assertion below names which of the four it is pinning.

Runs offline: no Ghidra, no network, no build.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

import sys

sys.path.insert(0, str(PROJECT_ROOT))

from tools.audit_server_scope import load_catalog, release_counts  # noqa: E402


def _read(rel: str) -> str:
    """File text, line-ending independent (the maintainer's tree is CRLF)."""
    return io.open(PROJECT_ROOT / rel, encoding="utf-8").read()


# --------------------------------------------------------------------------
# The four counts, all derived from the catalog.
# --------------------------------------------------------------------------
TOTAL, GUI, HEADLESS = release_counts(PROJECT_ROOT)

_ENDPOINTS = load_catalog(PROJECT_ROOT)["endpoints"]
GUI_ONLY = sum(1 for e in _ENDPOINTS if e["servers"] == ["gui"])
HEADLESS_ONLY = sum(1 for e in _ENDPOINTS if e["servers"] == ["headless"])
SHARED = sum(1 for e in _ENDPOINTS if "gui" in e["servers"] and "headless" in e["servers"])

#: What each published figure is allowed to be. Anything else in a
#: present-tense surface is drift until it is listed in ``NON_CATALOG_COUNTS``.
CATALOG_COUNTS = {TOTAL, GUI, HEADLESS, SHARED, GUI_ONLY, HEADLESS_ONLY}


# --------------------------------------------------------------------------
# Pinned sites. (file, regex, expected, what it counts)
#
# Each regex must have exactly one capture group holding the number, and must
# match at least once -- see rule 2 above.
# --------------------------------------------------------------------------
PINNED: list[tuple[str, str, int, str]] = [
    # ---- README.md ------------------------------------------------------
    ("README.md", r"\*\*(\d+) MCP tools\*\*", TOTAL, "whole catalog"),
    (
        "README.md",
        r"- \*\*MCP Tools\*\*: (\d+) tools fully implemented",
        TOTAL,
        "whole catalog",
    ),
    ("README.md", r"the GUI plugin serves (\d+) of them", GUI, "GUI plugin"),
    ("README.md", r"and the headless server (\d+)\)", HEADLESS, "headless server"),
    (
        "README.md",
        r"Advertising all (\d+) endpoints in a single `tools/list`",
        TOTAL,
        "whole catalog",
    ),
    (
        "README.md",
        r"translates MCP protocol to HTTP calls \((\d+) catalog entries\)",
        TOTAL,
        "whole catalog",
    ),
    (
        "README.md",
        r"exposes analysis capabilities via HTTP \((\d+) endpoints\)",
        GUI,
        "GUI plugin",
    ),
    (
        "README.md",
        r"Standalone headless server — (\d+) endpoints",
        HEADLESS,
        "headless server",
    ),
    (
        "README.md",
        r"MCP server package \(Python, (\d+) catalog entries\)",
        TOTAL,
        "whole catalog",
    ),
    ("README.md", r"# GUI plugin \((\d+) endpoints\)", GUI, "GUI plugin"),
    ("README.md", r"# Headless server \((\d+) endpoints\)", HEADLESS, "headless server"),
    # The generated API-reference block. Regenerate with
    # `python -m tools.gen_readme_api_reference --write`.
    (
        "README.md",
        r"(?m)^(\d+) MCP tools backed by HTTP endpoints",
        TOTAL,
        "whole catalog",
    ),
    (
        "README.md",
        r"(?m)^(\d+) of these are served by both the GUI plugin",
        SHARED,
        "both servers",
    ),
    ("README.md", r"\*\*\(GUI only\)\*\* \((\d+)\)", GUI_ONLY, "GUI-only"),
    ("README.md", r"\*\*\(headless only\)\*\* \((\d+)\)", HEADLESS_ONLY, "headless-only"),
    # ---- CLAUDE.md ------------------------------------------------------
    ("CLAUDE.md", r"(\d+) MCP tools for binary analysis", TOTAL, "whole catalog"),
    (
        "CLAUDE.md",
        r"`tests/endpoints\.json` \((\d+) endpoints, categories",
        TOTAL,
        "whole catalog",
    ),
    ("CLAUDE.md", r"— (\d+) endpoints are on both", SHARED, "both servers"),
    ("CLAUDE.md", r"endpoints are on both, (\d+) are GUI-only", GUI_ONLY, "GUI-only"),
    (
        "CLAUDE.md",
        r"and (\d+) are headless-only \(`HeadlessManagementService`",
        HEADLESS_ONLY,
        "headless-only",
    ),
    # ---- AGENTS.md ------------------------------------------------------
    (
        "AGENTS.md",
        r"\*\*Key feature\*\*: (\d+) MCP tools for binary analysis",
        TOTAL,
        "whole catalog",
    ),
    # ---- CONTRIBUTING.md ------------------------------------------------
    (
        "CONTRIBUTING.md",
        r"\*\*Tool inventory\*\* \((\d+) endpoints, generated\)",
        TOTAL,
        "whole catalog",
    ),
    # ---- ROADMAP.md -----------------------------------------------------
    ("ROADMAP.md", r"The server advertises (\d+) tools", TOTAL, "whole catalog"),
    ("ROADMAP.md", r"The catalog stands at (\d+) today", TOTAL, "whole catalog"),
    # ---- Issue template -------------------------------------------------
    (
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        r"(\d+) tools are listed in tests/endpoints\.json",
        TOTAL,
        "whole catalog",
    ),
    # ---- Shipped artifact metadata --------------------------------------
    # Both of these describe the GUI extension specifically. The extension
    # does not serve the headless-only routes, so TOTAL would be wrong here.
    (
        "src/main/resources/extension.properties",
        r"Provides (\d+) MCP endpoints for reverse engineering automation",
        GUI,
        "GUI plugin",
    ),
    (
        "src/main/resources/META-INF/MANIFEST.MF",
        r"HTTP server plugin with (\d+) MCP endpoints",
        GUI,
        "GUI plugin",
    ),
    (
        "src/main/java/com/xebyte/GhidraMCPPlugin.java",
        r"Provides (\d+) endpoints for reverse engineering automation",
        GUI,
        "GUI plugin",
    ),
    # ---- Release index (the current, unreleased entry) -------------------
    (
        "docs/releases/README.md",
        r"\*\*7\.0\.0 ships (\d+) tools\*\*",
        TOTAL,
        "whole catalog",
    ),
    (
        "docs/releases/README.md",
        r"7\.0\.0 ships \d+ tools\*\*\s*— (\d+) served by the GUI plugin",
        GUI,
        "GUI plugin",
    ),
    (
        "docs/releases/README.md",
        r"served by the GUI plugin, (\d+) by the headless server",
        HEADLESS,
        "headless server",
    ),
    (
        "docs/releases/README.md",
        r"by the headless server, (\d+) by both",
        SHARED,
        "both servers",
    ),
]


# --------------------------------------------------------------------------
# The sweep. Catches a NEW stale count appearing anywhere in a present-tense
# surface, including in a sentence nobody thought to pin above.
#
# CHANGELOG.md and the archived release entries are deliberately excluded:
# they are history, and "v6.0.0 ... 272 tools" is a true statement about a
# past release. docs/Context-Window-Analysis.md is excluded for the same
# reason -- it is a dated measurement that says so in its own header, and a
# test asserts that disclaimer is still there (see below).
# --------------------------------------------------------------------------
PRESENT_TENSE_SURFACES = [
    "README.md",
    "CLAUDE.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "ROADMAP.md",
    "src/main/resources/extension.properties",
    "src/main/resources/META-INF/MANIFEST.MF",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
]

#: Numbers next to "tools"/"endpoints" in the surfaces above that are
#: legitimately NOT catalog counts. A ratchet in both directions: an entry that
#: stops matching fails, so the list cannot outlive the sentence it excuses.
#: (file, number, reason)
NON_CATALOG_COUNTS: list[tuple[str, int, str]] = [
    ("README.md", 4, "the minimum viable read-only tool allowlist, not a catalog size"),
    ("README.md", 84, "endpoints in the three default tool groups loaded under --lazy"),
    ("ROADMAP.md", 84, "endpoints in the three default tool groups loaded under --lazy"),
    ("CLAUDE.md", 5, "REST endpoints on the optional external re-kb archive service"),
    ("CLAUDE.md", 22, "debugger proxy tools in the bridge, not catalog endpoints"),
    ("ROADMAP.md", 272, "the pre-consolidation surface; a statement about the past"),
]

_COUNT_NEAR_NOUN = re.compile(
    r"(?<![\w.])(\d{1,4})\+?[  ]+(?:MCP[  ]+)?(?:tools|endpoints)\b"
)


class TestCatalogIsInternallyConsistent(unittest.TestCase):
    """The catalog must agree with itself before anything else can agree with it."""

    def test_total_endpoints_field_matches_the_array(self):
        catalog = load_catalog(PROJECT_ROOT)
        self.assertEqual(
            catalog["total_endpoints"],
            len(catalog["endpoints"]),
            "tests/endpoints.json's total_endpoints field disagrees with the "
            "number of entries in its own endpoints array.",
        )

    def test_release_counts_agree_with_the_catalog(self):
        self.assertEqual(TOTAL, len(_ENDPOINTS))
        self.assertEqual(GUI, SHARED + GUI_ONLY)
        self.assertEqual(HEADLESS, SHARED + HEADLESS_ONLY)
        self.assertEqual(TOTAL, SHARED + GUI_ONLY + HEADLESS_ONLY)

    def test_every_entry_is_stamped_with_a_server_scope(self):
        """``release_counts`` raises on an unstamped entry; prove it cannot."""
        unstamped = [e["path"] for e in _ENDPOINTS if not e.get("servers")]
        self.assertEqual(
            unstamped,
            [],
            "Entries with no `servers` field; re-stamp with "
            "`python -m tools.audit_server_scope --write`.",
        )


class TestPublishedCountsMatchTheCatalog(unittest.TestCase):
    """Each published figure equals the catalog count it claims to be."""

    def test_pinned_sites(self):
        problems: list[str] = []
        for rel, pattern, expected, what in PINNED:
            text = _read(rel)
            found = re.findall(pattern, text)
            if not found:
                problems.append(
                    f"{rel}: pattern {pattern!r} matched NOTHING.\n"
                    f"    A published count for the {what} used to live here. "
                    f"Either the sentence was reworded (update this test) or the "
                    f"count was deleted (say so deliberately). A pattern that "
                    f"matches nothing asserts nothing."
                )
                continue
            for raw in found:
                if int(raw) != expected:
                    problems.append(
                        f"{rel}: published {raw}, catalog says {expected} "
                        f"({what}). tests/endpoints.json is authoritative; "
                        f"derive with `python -m tools.audit_server_scope "
                        f"--release-counts`."
                    )
        self.assertEqual(problems, [], "\n\n".join(problems))

    def test_no_unexplained_counts_in_present_tense_surfaces(self):
        """Sweep for a stale figure in a sentence nobody pinned."""
        allowed_by_file: dict[str, set[int]] = {}
        for rel, number, _reason in NON_CATALOG_COUNTS:
            allowed_by_file.setdefault(rel, set()).add(number)

        problems: list[str] = []
        seen: dict[str, set[int]] = {}
        for rel in PRESENT_TENSE_SURFACES:
            text = _read(rel)
            numbers = {int(m) for m in _COUNT_NEAR_NOUN.findall(text)}
            seen[rel] = numbers
            for number in sorted(numbers):
                if number in CATALOG_COUNTS:
                    continue
                if number in allowed_by_file.get(rel, set()):
                    continue
                context = ""
                match = re.search(
                    r".{0,90}(?<![\w.])" + str(number) + r"\+?[  ]+(?:MCP[  ]+)?"
                    r"(?:tools|endpoints)\b.{0,50}",
                    text,
                    re.S,
                )
                if match:
                    context = " ".join(match.group(0).split())
                problems.append(
                    f"{rel}: '{number} tools/endpoints' is neither a catalog "
                    f"count {sorted(CATALOG_COUNTS)} nor listed in "
                    f"NON_CATALOG_COUNTS.\n    ...{context}...\n"
                    f"    Fix the number, or add it to NON_CATALOG_COUNTS with "
                    f"the reason it is not a catalog count."
                )

        # Ratchet the other way: an excuse that no longer excuses anything is
        # a stale entry, and a stale allowlist is how a guard quietly stops
        # guarding.
        for rel, number, reason in NON_CATALOG_COUNTS:
            if number not in seen.get(rel, set()):
                problems.append(
                    f"NON_CATALOG_COUNTS lists ({rel}, {number}) for "
                    f"{reason!r}, but no such count appears there any more. "
                    f"Delete the entry."
                )

        self.assertEqual(problems, [], "\n\n".join(problems))


class TestPublishedTextIsNotCorrupted(unittest.TestCase):
    """No tracked text file contains a control character.

    On 2026-07-21 a bulk count bump replaced ``256 MCP tools`` with ``267``
    followed by a literal SOH byte -- the word "tools" was eaten and the
    control character left in its place. It shipped in every release from
    v5.17.0 onward: Ghidra's *Install Extensions* dialog rendered a control
    character and a sentence with no noun, and no gate saw it because nothing
    read those strings.

    The first fix listed the files to scan, and that list missed
    ``META-INF/MANIFEST.MF`` -- a **third** copy of the same corrupted string,
    inside the jar, describing the plugin to the same dialog. An allowlist
    cannot see the file nobody thought to add, which is precisely the shape of
    the bug it was written to catch. So this sweeps every tracked text file
    instead: a control character is never correct in one, and a file that
    genuinely needs an exemption is one worth arguing about in review.
    """

    #: Extensions whose contents are binary. Anything else is scanned, and a
    #: file holding a NUL is treated as binary by content -- so a new binary
    #: format needs no entry here to avoid a false positive.
    BINARY_SUFFIXES = frozenset(
        """
        .png .jpg .jpeg .gif .ico .svgz .pdf .zip .gar .gzf .jar .dll .exe
        .bin .so .dylib .class .woff .woff2 .ttf .otf .eot .gz .xz .7z
        """.split()
    )

    def _tracked_files(self):
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=True,
        )
        return [f for f in out.stdout.decode("utf-8").split("\0") if f]

    def test_no_control_characters(self):
        bad = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")
        problems = []
        scanned = 0

        for rel in self._tracked_files():
            path = PROJECT_ROOT / rel
            if path.suffix.lower() in self.BINARY_SUFFIXES:
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue  # submodule, or a link pointing outside the tree
            if b"\x00" in raw:
                continue  # binary by content, whatever it is called
            scanned += 1
            hit = bad.search(raw)
            if not hit:
                continue
            offset = hit.start()
            lineno = raw.count(b"\n", 0, offset) + 1
            context = raw[max(0, offset - 60):offset + 30]
            problems.append(
                f"{rel}:{lineno}: control character "
                f"{hex(raw[offset])} in tracked text: {context!r}"
            )

        # Rule 2 again: a sweep that scans nothing is a test that cannot fail.
        self.assertGreater(
            scanned,
            200,
            f"only {scanned} tracked text files scanned -- the enumeration "
            f"broke, so this assertion proves nothing",
        )
        self.assertEqual(problems, [], "\n".join(problems))


class TestDatedMeasurementsSayThatTheyAreDated(unittest.TestCase):
    """A document full of stale counts must say why it is allowed to be.

    ``docs/Context-Window-Analysis.md`` reports token totals measured against a
    251-endpoint catalog. Re-labelling those to 253 without re-running the
    measurement would make the token figures a lie, so the counts stay and the
    document carries a disclaimer instead. That disclaimer is what excuses the
    file from the sweep above, so it is asserted rather than trusted.
    """

    def test_context_window_analysis_carries_its_disclaimer(self):
        text = _read("docs/Context-Window-Analysis.md")
        self.assertIn(
            "This is a dated measurement, not a live figure.",
            text,
            "docs/Context-Window-Analysis.md is excluded from the count sweep "
            "only because it declares its figures to be a dated measurement. "
            "Restore the disclaimer, or re-measure and add the file to "
            "PRESENT_TENSE_SURFACES.",
        )
        self.assertRegex(
            text,
            r"stands at \*\*%d\*\* today" % TOTAL,
            "The disclaimer names the current catalog size; it no longer "
            "matches tests/endpoints.json.",
        )


class TestReleaseNotesCannotInventANumber(unittest.TestCase):
    """The release workflow must keep reading the catalog, with no fallback.

    ``release.yml`` published ``Headless Endpoints: 1`` in v6.0.0 because a grep
    of a file deleted three weeks earlier was softened with ``|| echo "0"``.
    """

    def test_release_workflow_uses_release_counts_without_a_default(self):
        text = _read(".github/workflows/release.yml")
        self.assertIn(
            "tools.audit_server_scope --release-counts",
            text,
            "release.yml no longer derives its counts from the catalog.",
        )
        for line in text.splitlines():
            if "--release-counts" not in line:
                continue
            self.assertNotRegex(
                line.strip(),
                r"\|\|\s*(echo|true|:)",
                f"release-counts line has a fallback default: {line.strip()}\n"
                f"A suppressed read error must fail the release, not become a "
                f"plausible number.",
            )


if __name__ == "__main__":
    unittest.main()
