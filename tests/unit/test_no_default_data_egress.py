"""Regression tests for outbound archive and BSim defaults."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_archive_exchange_is_disabled_by_default():
    # fun-doc moved out of this repo (it is a curation subsystem, not part of
    # the Ghidra MCP server). Its own opt-in-default archive check travels with
    # it; here we assert only the Java side, which is what this repo ships.
    java_source = _read(
        "src/main/java/com/xebyte/core/DocumentationHashService.java"
    )

    assert 'env == null ? "" : env.trim()' in java_source
    assert "DEFAULT_ARCHIVE_URL" not in java_source


def test_bsim_scripts_have_no_default_destination():
    """No BSim script may carry a baked-in destination.

    The glob used to be `BSim*.java`, which matched nothing once the scripts
    were named `Analyze_BSim*`. Ten of them shipped a hardcoded private
    address straight past this test; only the broader
    `test_removed_private_destination_does_not_reappear` caught it. Match on
    the substring so a rename cannot silently retire the check again.
    """
    scripts = [
        p for p in (REPO_ROOT / "ghidra_scripts").rglob("*.java")
        if "bsim" in p.name.lower()
    ]
    assert scripts, "expected BSim scripts to exist; glob is matching nothing"
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        # A constant is fine as long as it is sourced from the environment;
        # what must never appear is a literal URL assigned to one.
        for line in source.splitlines():
            if "DEFAULT_BSIM_URL" in line and "=" in line:
                value = line.split("=", 1)[1]
                assert "://" not in value, f"{script}: literal destination -> {line.strip()}"


def test_bsim_credentials_file_is_not_committed():
    """db.env holds a real password; only the template belongs in git."""
    import subprocess

    try:
        tracked = subprocess.run(
            ["git", "ls-files", "ghidra_scripts/db.env"], cwd=REPO_ROOT,
            capture_output=True, check=True, timeout=30,
        ).stdout.decode().strip()
    except (OSError, subprocess.SubprocessError):
        return  # no git available; the egress test still covers the address
    assert not tracked, "ghidra_scripts/db.env is tracked -- it contains a password"
    assert (REPO_ROOT / "ghidra_scripts" / "db.env.example").exists()


def _tracked_files() -> list[Path] | None:
    """Files git knows about (tracked + staged), or None if git is unavailable.

    The guard is about what gets *committed*, so asking git is both more
    accurate and immune to local build artifacts. Scanning the raw filesystem
    used to fail on gitignored droppings -- e.g. a surefire/pytest report that
    happened to quote the address inside an assertion message, which cost real
    debugging time for a leak that could never have shipped.
    """
    import subprocess

    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"], cwd=REPO_ROOT,
            capture_output=True, check=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return [
        REPO_ROOT / rel.decode("utf-8")
        for rel in proc.stdout.split(b"\0")
        if rel
    ]


def test_removed_private_destination_does_not_reappear():
    removed_destination = ".".join(("10", "0", "10", "30"))
    # No "fun-doc" -- it left this repo. Roots are matched against *tracked*
    # files, so a root that no longer exists silently contributes nothing;
    # keeping a dead one here would make this guard quietly narrower than it
    # reads. Add a root back only when this repo tracks files under it.
    #
    # "scripts" -> "tools" on 2026-08-12: scripts/ was dissolved into
    # ghidra_scripts/ and tools/. Dropping the dead root WITHOUT adding tools/
    # would have shrunk this guard silently, because scripts/bsim/
    # build_reference_index.py -- BSim tooling, i.e. exactly the code that can
    # carry a private destination -- landed in tools/, which was never checked.
    checked_roots = ("src", "ghidra_scripts", "docker", "tools", "tests")

    tracked = _tracked_files()
    if tracked is None:
        # No git: fall back to a filesystem walk, skipping the artifact
        # directories that git would have excluded anyway.
        skip_parts = {"__pycache__", "target", "build", ".pytest_cache", "node_modules"}
        candidates = []
        for root in checked_roots:
            for path in (REPO_ROOT / root).rglob("*"):
                if path.is_file() and not skip_parts & set(path.parts):
                    candidates.append(path)
    else:
        candidates = [
            p for p in tracked
            if p.parts[len(REPO_ROOT.parts):][:1] and p.parts[len(REPO_ROOT.parts)] in checked_roots
        ]

    for path in candidates:
        if not path.is_file():
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        assert removed_destination not in source, path
