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


def test_removed_private_destination_does_not_reappear():
    removed_destination = ".".join(("10", "0", "10", "30"))
    checked_paths = [
        REPO_ROOT / "src",
        REPO_ROOT / "fun-doc",
        REPO_ROOT / "ghidra_scripts",
        REPO_ROOT / "docker",
        REPO_ROOT / "scripts",
        REPO_ROOT / "tests",
    ]
    for root in checked_paths:
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    source = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                assert removed_destination not in source, path
