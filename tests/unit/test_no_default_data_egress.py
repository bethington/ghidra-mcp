"""Regression tests for outbound archive and BSim defaults."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_archive_exchange_is_disabled_by_default():
    java_source = _read(
        "src/main/java/com/xebyte/core/DocumentationHashService.java"
    )
    fun_doc_source = _read("fun-doc/fun_doc.py")

    assert 'env == null ? "" : env.trim()' in java_source
    assert 'os.environ.get("RE_KB_ARCHIVE_URL", "")' in fun_doc_source
    assert "DEFAULT_ARCHIVE_URL" not in java_source


def test_bsim_scripts_have_no_default_destination():
    for script in (REPO_ROOT / "ghidra_scripts").glob("BSim*.java"):
        source = script.read_text(encoding="utf-8")
        assert "DEFAULT_BSIM_URL" not in source, script


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
    checked_roots = ("src", "fun-doc", "ghidra_scripts", "docker", "scripts", "tests")

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
