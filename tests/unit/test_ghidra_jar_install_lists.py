"""Every place that hand-installs Ghidra jars must cover pom.xml's dependencies.

Why this exists
---------------
Ghidra is not on Maven Central. Four files therefore carry a hand-maintained
list of ``mvn install:install-file`` calls that stamp jars out of a Ghidra
installation into a local repository: ``tests.yml``, ``release.yml``,
``pre-release.yml`` and ``docker/Dockerfile``. Four copies of one list, none of
them derived from ``pom.xml``, which is the thing that decides what the build
actually needs.

They drifted. ``ghidra:Graph`` became a dependency and three of the four were
updated; ``docker/Dockerfile`` was not. The result:

```text
[ERROR] Failed to execute goal on project GhidraMCP: Could not resolve dependencies
[ERROR] dependency: ghidra:Graph:jar:12.1.2 (test)
[ERROR]     Could not find artifact ghidra:Graph:jar:12.1.2 in central
```

So ``docker build -f docker/Dockerfile`` — and therefore ``docker compose up``,
and therefore the entire documented Docker deployment — could not succeed. **CI
stayed green throughout**, because nothing in CI builds the Docker image. The
only signal was a person actually running the documented command, which is the
worst possible place to discover it and exactly why this check is cheap and
offline.

This asserts coverage, not equality: the CI workflows also install ``PDB`` and
``FunctionID``, which the pom does not declare as dependencies. Extra jars are
harmless; a missing one is a build that cannot resolve.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
POM = REPO_ROOT / "pom.xml"

# Every file that hand-maintains an install-file list, relative to the repo.
INSTALLERS = (
    ".github/workflows/tests.yml",
    ".github/workflows/release.yml",
    ".github/workflows/pre-release.yml",
    "docker/Dockerfile",
)

_POM_GHIDRA_DEP = re.compile(
    r"<groupId>ghidra</groupId>\s*<artifactId>([^<]+)</artifactId>"
)
_INSTALLED_ARTIFACT = re.compile(r"-DartifactId=([A-Za-z0-9_.-]+)")


def _pom_ghidra_dependencies() -> set[str]:
    deps = set(_POM_GHIDRA_DEP.findall(POM.read_text(encoding="utf-8")))
    assert deps, (
        "no ghidra:* dependencies found in pom.xml. Either the build stopped "
        "depending on Ghidra (in which case delete this guard) or the parse "
        "broke -- and a guard that silently finds nothing to check is worse "
        "than no guard."
    )
    return deps


def _installed_artifacts(relative_path: str) -> set[str]:
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    found = set(_INSTALLED_ARTIFACT.findall(text))
    assert found, f"{relative_path} passes no -DartifactId= at all"
    return found


@pytest.mark.parametrize("installer", INSTALLERS)
def test_installer_covers_every_ghidra_dependency(installer):
    """A missing jar is a build that cannot resolve, wherever it runs."""
    missing = sorted(_pom_ghidra_dependencies() - _installed_artifacts(installer))
    assert not missing, (
        f"{installer} never installs ghidra:{{{','.join(missing)}}}, which "
        f"pom.xml declares as a dependency. Maven will fail with 'Could not "
        f"find artifact ghidra:{missing[0]}:jar:<version> in central' -- Ghidra "
        f"is not on Maven Central, so an artifact nothing install-files is "
        f"simply absent.\n"
        f"This is four hand-maintained copies of one list, and it has already "
        f"drifted once: `Graph` was added to three of them and not to "
        f"docker/Dockerfile, so the documented `docker compose up` could not "
        f"build while CI stayed green -- nothing in CI builds that image."
    )


def test_every_installer_is_a_real_file():
    """A renamed workflow must not silently drop out of the check."""
    for installer in INSTALLERS:
        assert (REPO_ROOT / installer).is_file(), (
            f"{installer} is listed here but does not exist. If it moved, move "
            f"this entry with it; if it is gone, delete the entry. An installer "
            f"list that quietly checks fewer files each year is not a guard."
        )
