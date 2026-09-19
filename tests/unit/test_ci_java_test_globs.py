"""Guard that every Java test class is reachable by the CI test glob.

Why this exists
---------------
CI does not run ``mvn test``. It runs a *filtered* build::

    mvn -q test -Pcoverage-gate -Dtest='com.xebyte.offline.*Test,com.xebyte.core.*Test'

Surefire's ``*`` does not cross the package separator, so a test class that
lands anywhere other than ``com.xebyte.offline`` or ``com.xebyte.core`` is
simply not selected. It compiles. It is committed. It is never executed, and
nothing anywhere says so -- a test that is never selected cannot fail, so its
absence is invisible to the very system it was added to inform.

That is not hypothetical. ``GarArchiveRestoreTest`` (9 tests) and
``GzfExportImportTest`` (5 tests) were added in PR #264 as the path-traversal
and exact-name guards for the GZF/GAR endpoints, in package ``com.xebyte``.
They had never run in CI (issue #483). Measured directly from the surefire
reports published by run 35343488609 at ``0cf545b1``: **59 classes executed,
and neither of those two was among them.**

The fix for those two classes was to move them next to their sibling
``HeadlessPathsTest``, which tests the same #264 surface from
``com.xebyte.offline``. This file is the part that keeps it fixed: it fails
when a test class exists in a package the CI glob cannot reach, so the *next*
orphan is loud instead of silently dead.

What is asserted
----------------
1. Every Java class that declares tests is selected by at least one CI glob,
   or is named in :data:`UNSELECTED_BY_DESIGN` with a reason.
2. :data:`UNSELECTED_BY_DESIGN` carries no stale entries -- a ratchet in both
   directions, so the exemption list cannot outlive the classes it excuses.
3. The offline glob is character-identical in ``tests.yml``, ``release.yml``
   and ``pre-release.yml``. Those three are meant to run the same tier; a
   release gate quietly running a narrower set than the PR gate is the same
   class of bug one level up.

Detection is deliberately by content, not by a ``*Test.java`` filename. A
class named ``FooTests`` or ``TestFoo`` is missed by every glob in this
repository, and a filename-based scan would agree with the glob instead of
checking it.

Detection also has to span two JUnit generations, and getting that wrong is
not theoretical either: the first cut of this guard scanned for ``@Test``
alone, and reported that ``AppTest``, ``EndpointRegistrationTest`` and
``GhidraMCPPluginTest`` "no longer exist". All three are alive and are
**JUnit 3** -- ``extends TestCase`` with bare ``testXxx()`` methods and not one
annotation between them. A scan that sees only annotations declares the older
half of this suite to be not-tests, which is the same blind spot as the glob it
is supposed to be checking.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
JAVA_TEST_ROOT = REPO_ROOT / "src" / "test" / "java"

# The offline tier's glob, as the three workflows that run it must spell it.
# Kept as a literal on purpose: this is the one string the guard cannot derive
# from the thing it is guarding.
OFFLINE_TIER_GLOB = "com.xebyte.offline.*Test,com.xebyte.core.*Test"

# Workflows that run the offline Java tier and must therefore agree on it.
OFFLINE_TIER_WORKFLOWS = ("tests.yml", "release.yml", "pre-release.yml")

# Classes that no CI glob selects, on purpose, each with the reason. Two kinds
# live here and both must stay rare:
#
#   * integration tests, which need a live Ghidra on :8089 with a program open.
#     CI has no such instance, so they cannot run there at all.
#   * maintenance tools that JUnit happens to carry. RegenerateEndpointsJson
#     REWRITES tests/endpoints.json; it is invoked by name with
#     `-Dregenerate=true` and no-ops otherwise. Selecting it in CI would give
#     the gate a way to edit the catalog it is checking.
#
# Anything added here must be genuinely unrunnable in CI, not merely
# inconvenient: an entry is a decision to ship something no gate executes.
UNSELECTED_BY_DESIGN = {
    "com.xebyte.AppTest": "smoke test against a running GhidraMCP HTTP server",
    "com.xebyte.EndpointRegistrationTest": "asserts routes on a live server",
    "com.xebyte.GhidraMCPPluginTest": "drives the plugin inside a running Ghidra",
    "com.xebyte.offline.RegenerateEndpointsJson": (
        "catalog regenerator, run by name with -Dregenerate=true; its behaviour "
        "is covered in CI by RegenerateEndpointsJsonMergeTest"
    ),
}

_PACKAGE_DECL = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_DTEST_ARG = re.compile(r"-Dtest=(['\"])(?P<patterns>.+?)\1")

# Three shapes, because this suite spans two JUnit generations:
#   JUnit 4/5 -- an @Test annotation.
#   JUnit 3   -- `extends TestCase` (which may sit on its own line), or a bare
#                `public void testXxx()` method, which is how JUnit 3 names a
#                test with no annotation anywhere in the file.
_TEST_MARKERS = (
    re.compile(r"^\s*@Test\b", re.MULTILINE),
    re.compile(r"\bextends\s+TestCase\b"),
    re.compile(r"^\s*public\s+void\s+test\w*\s*\(", re.MULTILINE),
)


def _surefire_pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Model Surefire's ``-Dtest`` glob over a fully-qualified class name.

    ``*`` matches within one package/class segment and does NOT cross ``.``;
    ``**`` crosses freely; ``?`` matches one non-separator character. This
    model is not taken on faith -- it reproduces exactly which 59 classes CI
    executed at ``0cf545b1`` (see the module docstring), including the two it
    did not.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^.]*")
        elif ch == "?":
            out.append("[^.]")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def _ci_globs() -> list[str]:
    """Every ``-Dtest`` pattern any workflow passes, flattened and deduped."""
    patterns: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for match in _DTEST_ARG.finditer(path.read_text(encoding="utf-8")):
            for piece in match.group("patterns").split(","):
                piece = piece.strip()
                if piece and piece not in patterns:
                    patterns.append(piece)
    assert patterns, (
        "no -Dtest glob found in any workflow. Either CI stopped filtering "
        "(in which case delete this guard) or the parse broke -- and a guard "
        "that silently finds nothing to check is worse than no guard."
    )
    return patterns


def _java_test_classes() -> dict[str, pathlib.Path]:
    """Fully-qualified name -> file, for every Java class that declares tests."""
    found: dict[str, pathlib.Path] = {}
    for path in sorted(JAVA_TEST_ROOT.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        if not any(marker.search(text) for marker in _TEST_MARKERS):
            continue
        package_match = _PACKAGE_DECL.search(text)
        package = package_match.group(1) if package_match else ""
        fqcn = f"{package}.{path.stem}" if package else path.stem
        found[fqcn] = path
    assert found, f"no test-bearing classes found under {JAVA_TEST_ROOT}"
    return found


def _offline_tier_commands(workflow: str) -> list[str]:
    """Every ``run:`` script line in `workflow` that passes a ``-Dtest`` glob."""
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    return [m.group("patterns") for m in _DTEST_ARG.finditer(text)]


@pytest.mark.parametrize("fqcn", sorted(_java_test_classes()))
def test_every_java_test_class_is_reachable_by_a_ci_glob(fqcn):
    """A test class CI cannot select is a test that does not exist."""
    if fqcn in UNSELECTED_BY_DESIGN:
        pytest.skip(f"exempt: {UNSELECTED_BY_DESIGN[fqcn]}")

    globs = _ci_globs()
    matched = [g for g in globs if _surefire_pattern_to_regex(g).match(fqcn)]
    assert matched, (
        f"{fqcn} is not selected by any CI test glob {globs}.\n"
        f"Surefire's `*` does not cross the package separator, so this class "
        f"compiles, commits and NEVER RUNS -- and because an unselected test "
        f"cannot fail, nothing will ever report it.\n"
        f"Fix it by moving the class into com.xebyte.offline (offline tier) or "
        f"com.xebyte.core (Mockito/real-Ghidra tier), whichever it actually is. "
        f"Widening the glob is the harder option it looks like: "
        f"`com.xebyte.offline.*` without the Test suffix matches helper classes "
        f"and fails the build, and `com.xebyte.*Test` sweeps in the live-server "
        f"classes already exempted below.\n"
        f"If it genuinely cannot run in CI, add it to UNSELECTED_BY_DESIGN with "
        f"the reason -- that is a decision to ship an unexecuted test, so make "
        f"it deliberately."
    )


def test_unselected_by_design_has_no_stale_entries():
    """The exemption list must not outlive the classes it excuses.

    A stale entry is an exemption nobody can see is unused, and it quietly
    pre-authorises a future class that happens to reuse the name.
    """
    present = set(_java_test_classes())
    stale = sorted(set(UNSELECTED_BY_DESIGN) - present)
    assert not stale, (
        f"UNSELECTED_BY_DESIGN names classes that no longer exist: {stale}. "
        f"Delete them -- an exemption for a class that is gone excuses nothing "
        f"and silently covers whatever takes the name next."
    )


@pytest.mark.parametrize("workflow", OFFLINE_TIER_WORKFLOWS)
def test_offline_tier_glob_is_identical_in_every_workflow_that_runs_it(workflow):
    """tests.yml, release.yml and pre-release.yml must run the SAME tier.

    They are three copies of one command. If the release gate's copy drifts
    narrower than the PR gate's, a release ships having run fewer tests than
    every PR that fed it -- and both report green.
    """
    commands = _offline_tier_commands(workflow)
    assert OFFLINE_TIER_GLOB in commands, (
        f"{workflow} does not run the offline tier glob "
        f"'{OFFLINE_TIER_GLOB}'. Globs found: {commands}. If the tier's "
        f"definition really changed, change OFFLINE_TIER_GLOB here and in all "
        f"of {list(OFFLINE_TIER_WORKFLOWS)} together -- that is the point."
    )


def test_workflows_still_parse_as_yaml():
    """Cheap backstop: the regex scan above reads raw text, not parsed YAML.

    A workflow can be syntactically broken and still satisfy a text search, so
    the reachability guard alone could pass over a file GitHub refuses to run.
    """
    for path in sorted(WORKFLOWS.glob("*.yml")):
        assert yaml.safe_load(path.read_text(encoding="utf-8")), f"{path.name} parsed empty"
