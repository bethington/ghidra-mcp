"""Unit tests for tools/upgrade_project_language.py.

Pure Python -- no Ghidra, no server, no subprocess. Every behaviour pinned here
is one that produced a silent wrong answer during development:

* credential precedence  -- an ambient ``GHIDRA_PASS`` the Ghidra Server rejects
  beat the correct ``GHIDRA_SERVER_PASSWORD`` in ``.env`` and looked like an
  auth outage.
* MSYS argument mangling -- ``--folder /benchmark`` became
  ``C:/Program Files/Git/benchmark``, matched nothing, and the run reported
  success having done nothing.
* versioned/private split -- a ``ghidra://`` URL cannot see a private file, so
  counting private files in the plan overstates coverage.
* log parsing            -- ``saved`` is not ``committed``; on a shared project
  only the commit line means the work reached the server.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "upgrade_project_language.py"


def _load():
    spec = importlib.util.spec_from_file_location("upgrade_project_language", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


upl = _load()


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


def test_dotenv_parses_and_skips_comments(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "\n"
        "GHIDRA_SERVER_USER=benam\n"
        'GHIDRA_SERVER_PASSWORD="s3cret"\n'
        "EMPTY=\n"
        "no_equals_line\n",
        encoding="utf-8",
    )
    values = upl.read_dotenv(env)
    assert values["GHIDRA_SERVER_USER"] == "benam"
    assert values["GHIDRA_SERVER_PASSWORD"] == "s3cret"
    assert "EMPTY" not in values, "blank values must not shadow a real one downstream"
    assert "no_equals_line" not in values


def test_missing_dotenv_is_empty_not_an_error(tmp_path: Path):
    assert upl.read_dotenv(tmp_path / "nope.env") == {}


@pytest.fixture(autouse=True)
def _isolate_cwd_dotenv(tmp_path_factory, monkeypatch):
    """credential_sources() reads ./.env, and the repo has a real one.

    Without this the suite's answers depend on the developer's checkout, which is
    exactly the kind of ambient-state dependency these tests exist to catch.
    """
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))


def test_server_password_outranks_ambient_ghidra_pass(tmp_path: Path, monkeypatch):
    """The specific name must beat the general one REGARDLESS of source.

    This is the regression that matters: GHIDRA_PASS exists in this environment
    holding a credential the Ghidra Server rejects. If source order won, the
    ambient wrong value would beat the correct .env value and present as an
    authentication failure with no obvious cause.
    """
    monkeypatch.setenv("GHIDRA_PASS", "wrong-ambient-value")
    monkeypatch.delenv("GHIDRA_SERVER_PASSWORD", raising=False)
    (tmp_path / ".env").write_text("GHIDRA_SERVER_PASSWORD=correct-value\n", encoding="utf-8")

    password, source = upl.resolve_password(tmp_path)
    assert password == "correct-value"
    assert "GHIDRA_SERVER_PASSWORD" in source


def test_password_falls_back_to_ghidra_pass_when_no_specific_one(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GHIDRA_PASS", "fallback")
    monkeypatch.delenv("GHIDRA_SERVER_PASSWORD", raising=False)
    password, source = upl.resolve_password(tmp_path)
    assert password == "fallback"
    assert "GHIDRA_PASS" in source


def test_user_prefers_server_specific_name(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GHIDRA_USER", "generic")
    monkeypatch.delenv("GHIDRA_SERVER_USER", raising=False)
    (tmp_path / ".env").write_text("GHIDRA_SERVER_USER=specific\n", encoding="utf-8")
    assert upl.resolve_user(tmp_path) == "specific"


# --------------------------------------------------------------------------- #
# Server / repository discovery
# --------------------------------------------------------------------------- #


def test_no_private_destination_is_baked_into_the_module():
    """This is a public repo; a private host in source outlives its removal.

    tests/unit/test_no_default_data_egress.py enforces this repo-wide, but it
    only scans git-TRACKED files -- so it stays silent on a new script right up
    until the commit that publishes it. This check fires immediately.
    """
    source = MODULE_PATH.read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or '"""' in stripped:
            continue
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b(?<!127\.0\.0\.1)", stripped), (
            f"literal IP in source: {stripped}")


def test_server_and_repo_come_from_the_live_instance(monkeypatch, tmp_path):
    monkeypatch.setattr(
        upl, "mcp_get",
        lambda base, endpoint, **kw: {"project": "someproj", "server_info": "host.example:13100"},
    )
    server, repo, origin = upl.resolve_server_and_repo("http://x", tmp_path, None, None)
    assert (server, repo) == ("host.example:13100", "someproj")
    assert "project/info" in origin


def test_explicit_flags_win_over_discovery(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise AssertionError("must not query Ghidra when both flags are given")

    monkeypatch.setattr(upl, "mcp_get", boom)
    assert upl.resolve_server_and_repo("http://x", tmp_path, "h:1", "r")[:2] == ("h:1", "r")


def test_dotenv_supplies_the_server_when_ghidra_is_unreachable(monkeypatch, tmp_path):
    def unreachable(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(upl, "mcp_get", unreachable)
    (tmp_path / ".env").write_text(
        "GHIDRA_SERVER_HOST=host.example\nGHIDRA_SERVER_PORT=13100\n", encoding="utf-8")
    server, repo, _origin = upl.resolve_server_and_repo("http://x", tmp_path, None, None)
    assert server == "host.example:13100"
    assert repo is None, "repo is not in .env; caller must refuse rather than guess"


def test_unresolvable_returns_none_rather_than_a_guess(monkeypatch, tmp_path):
    monkeypatch.setattr(upl, "mcp_get", lambda *a, **k: {})
    server, repo, origin = upl.resolve_server_and_repo("http://x", tmp_path, None, None)
    assert server is None and repo is None
    assert origin == "unresolved"


# --------------------------------------------------------------------------- #
# Log parsing
# --------------------------------------------------------------------------- #


SAMPLE_LOG = """\
INFO  Connected to repository 'diablo2' (RepositoryAdapter)
INFO  REPORT: Processing project file: /Vanilla/1.01/Ijl11.dll (HeadlessAnalyzer)
INFO  REPORT: Save succeeded for processed file: /Vanilla/1.01/Ijl11.dll (HeadlessAnalyzer)
INFO  REPORT: Committed file changes to repository: /Vanilla/1.01/Ijl11.dll (HeadlessAnalyzer)
WARN  Skipped processing for /Vanilla/1.01/Game.exe -- failed to get exclusive file checkout required for commit
ERROR /Vanilla/1.02/D2Win.dll: this file was created with an older version of Ghidra.
ERROR /Vanilla/1.03/Fog.dll: this file was created with a newer version of Ghidra, and can not be processed.
ERROR REPORT: Error trying to save changes to file: /Vanilla/1.04b/Storm.dll
"""


def _scan(text: str) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {
        "processed": [],
        "saved": [],
        "committed": [],
        "older": [],
        "newer": [],
        "no_exclusive": [],
        "save_errors": [],
    }
    pairs = (
        (upl.RE_PROCESSING, "processed"),
        (upl.RE_SAVED, "saved"),
        (upl.RE_COMMITTED, "committed"),
        (upl.RE_OLDER, "older"),
        (upl.RE_NEWER, "newer"),
        (upl.RE_NO_EXCLUSIVE, "no_exclusive"),
        (upl.RE_SAVE_ERROR, "save_errors"),
    )
    for line in text.splitlines():
        for regex, key in pairs:
            match = regex.search(line)
            if match:
                buckets[key].append(match.group(1))
    return buckets


def test_log_parser_recognises_every_outcome():
    found = _scan(SAMPLE_LOG)
    assert found["processed"] == ["/Vanilla/1.01/Ijl11.dll"]
    assert found["committed"] == ["/Vanilla/1.01/Ijl11.dll"]
    assert found["no_exclusive"] == ["/Vanilla/1.01/Game.exe"]
    assert found["older"] == ["/Vanilla/1.02/D2Win.dll"]
    assert found["newer"] == ["/Vanilla/1.03/Fog.dll"]
    assert found["save_errors"] == ["/Vanilla/1.04b/Storm.dll"]


def test_saved_and_committed_are_distinct_signals():
    """A save without a commit means the work never reached the server."""
    saved_only = "INFO  REPORT: Save succeeded for processed file: /Vanilla/1.05/Fog.dll\n"
    found = _scan(saved_only)
    assert found["saved"] == ["/Vanilla/1.05/Fog.dll"]
    assert found["committed"] == [], "a save must never be counted as a commit"


def test_trailing_log_decoration_is_stripped_from_paths():
    """Ghidra suffixes every log line with " (ComponentName)".

    If that rides along in the captured path, no reported path ever equals the
    inventory path it corresponds to, and any reconciliation of "planned vs
    actually upgraded" silently finds zero matches.
    """
    line = "INFO  REPORT: Processing project file: /Vanilla/1.06/D2Lang.dll (HeadlessAnalyzer)  "
    match = upl.RE_PROCESSING.search(line)
    assert match
    assert match.group(1) == "/Vanilla/1.06/D2Lang.dll"


def test_undecorated_lines_still_parse():
    line = "INFO  REPORT: Committed file changes to repository: /Vanilla/1.06/D2Lang.dll"
    match = upl.RE_COMMITTED.search(line)
    assert match and match.group(1) == "/Vanilla/1.06/D2Lang.dll"


def test_program_name_containing_parentheses_survives():
    line = "INFO  REPORT: Processing project file: /Lab/Game (copy).exe (HeadlessAnalyzer)"
    match = upl.RE_PROCESSING.search(line)
    assert match and match.group(1) == "/Lab/Game (copy).exe"


SPACED = "/Vanilla/1.00/Diablo II.exe"


@pytest.mark.parametrize(
    ("regex_name", "line"),
    [
        ("RE_PROCESSING", f"INFO  REPORT: Processing project file: {SPACED} (HeadlessAnalyzer)"),
        ("RE_SAVED", f"INFO  REPORT: Save succeeded for processed file: {SPACED} (HeadlessAnalyzer)"),
        ("RE_COMMITTED", f"INFO  REPORT: Committed file changes to repository: {SPACED} (HeadlessAnalyzer)"),
        ("RE_SAVE_ERROR", f"ERROR REPORT: Error trying to save changes to file: {SPACED}"),
        (
            "RE_NO_EXCLUSIVE",
            f"WARN  Skipped processing for {SPACED} -- failed to get exclusive file "
            "checkout required for commit (HeadlessAnalyzer)",
        ),
        (
            "RE_NON_EXCLUSIVE",
            f"ERROR Skipped processing for {SPACED} -- file is checked-out non-exclusive",
        ),
        (
            "RE_READONLY_REPO",
            f"WARN  Skipped processing for {SPACED} within read-only repository",
        ),
        ("RE_OLDER", f"ERROR {SPACED}: this file was created with an older version of Ghidra."),
        (
            "RE_NEWER",
            f"ERROR {SPACED}: this file was created with a newer version of Ghidra, "
            "and can not be processed.",
        ),
    ],
)
def test_paths_containing_spaces_are_captured_whole(regex_name: str, line: str):
    """`Diablo II.exe` exists in all 25 Vanilla folders.

    The first cut matched skip/error paths with ``(\\S+)``, which cannot span the
    space -- the line failed to match AT ALL, so the file vanished from the tally
    rather than being reported as skipped. Reconciliation caught exactly one
    unaccounted program corpus-wide and this was it.
    """
    match = getattr(upl, regex_name).search(line)
    assert match, f"{regex_name} failed to match a path containing a space"
    assert match.group(1) == SPACED


@pytest.mark.parametrize(
    "line",
    [
        "ERROR Server access denied (ghidra.example:13100). (RepositoryServerAdapter)",
        "ghidra.framework.client.NotConnectedException: Unauthorized",
    ],
)
def test_unauthorized_is_detected(line: str):
    assert upl.RE_UNAUTHORIZED.search(line)


def test_healthy_log_is_not_flagged_unauthorized():
    assert not upl.RE_UNAUTHORIZED.search("INFO  Connected to repository 'diablo2'")


# --------------------------------------------------------------------------- #
# Inventory shape
# --------------------------------------------------------------------------- #


def test_walk_project_recurses_and_keeps_only_programs(monkeypatch):
    """`/list_project_files` is folder-scoped: reading `/` alone finds nothing."""
    tree = {
        "/": {"folders": ["Vanilla"], "files": []},
        "/Vanilla": {"folders": ["1.01"], "files": []},
        "/Vanilla/1.01": {
            "folders": [],
            "files": [
                {"path": "/Vanilla/1.01/D2Game.dll", "content_type": "Program", "is_versioned": True},
                {"path": "/Vanilla/1.01/notes.txt", "content_type": "File", "is_versioned": True},
            ],
        },
    }
    monkeypatch.setattr(upl, "mcp_get", lambda base, path, **kw: tree[kw["folder"]])
    found = upl.walk_project("http://x")
    assert [e["path"] for e in found] == ["/Vanilla/1.01/D2Game.dll"]


def test_walk_project_survives_a_failing_folder(monkeypatch):
    """One unreadable folder must not abort the whole inventory."""

    def flaky(base, path, **kw):
        if kw["folder"] == "/bad":
            raise RuntimeError("boom")
        return {
            "/": {"folders": ["bad", "good"], "files": []},
            "/good": {
                "folders": [],
                "files": [{"path": "/good/A.dll", "content_type": "Program", "is_versioned": True}],
            },
        }[kw["folder"]]

    monkeypatch.setattr(upl, "mcp_get", flaky)
    assert [e["path"] for e in upl.walk_project("http://x")] == ["/good/A.dll"]


def test_checkout_census_is_unscoped(monkeypatch):
    """The folder-scoped form has been observed under-reporting; never use it."""
    seen: dict[str, object] = {}

    def capture(base, path, **kw):
        seen["path"] = path
        seen["kwargs"] = kw
        return {"checkouts": [{"path": "/Vanilla/1.01/Game.exe"}]}

    monkeypatch.setattr(upl, "mcp_get", capture)
    census = upl.checkout_census("http://x")
    assert census == {"/Vanilla/1.01/Game.exe": {"path": "/Vanilla/1.01/Game.exe"}}
    assert "folder" not in seen["kwargs"] and "path" not in seen["kwargs"]


def test_mcp_get_unwraps_double_encoded_envelope(monkeypatch):
    import io

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        upl.urllib.request,
        "urlopen",
        lambda url, timeout=None: FakeResponse(b'{"result": "{\\"a\\": 1}"}'),
    )
    assert upl.mcp_get("http://x", "y") == {"a": 1}


def test_mcp_get_accepts_a_path_query_parameter(monkeypatch):
    """Several endpoints take a `path=` query param.

    The endpoint argument must therefore NOT be named `path`, or every such call
    dies with "got multiple values for argument 'path'" -- which the verify pass
    then reports as `unknown` for every single program.
    """
    import io

    seen: dict[str, str] = {}

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(url, timeout=None):
        seen["url"] = url
        return FakeResponse(b'{"result": "{\\"success\\": true}"}')

    monkeypatch.setattr(upl.urllib.request, "urlopen", fake_urlopen)
    result = upl.mcp_get("http://x", "open_program", path="/Vanilla/1.01/D2Game.dll")
    assert result == {"success": True}
    assert "open_program?" in seen["url"]
    assert "path=%2FVanilla%2F1.01%2FD2Game.dll" in seen["url"]


# --------------------------------------------------------------------------- #
# Command construction
# --------------------------------------------------------------------------- #


def test_apply_passes_commit_because_that_is_what_makes_checkout_exclusive(monkeypatch, tmp_path):
    """-commit is load-bearing, not cosmetic.

    HeadlessAnalyzer does `domFile.checkout(options.commit, ...)`, so without
    -commit the checkout is NON-exclusive and the language upgrade cannot happen.
    A refactor that drops it would leave a tool that runs cleanly and upgrades
    nothing.
    """
    captured: dict[str, list[str]] = {}

    class FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        return FakeCompleted()

    support = tmp_path / "support"
    support.mkdir()
    (support / ("analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless")).touch()
    monkeypatch.setattr(upl.subprocess, "run", fake_run)

    common = dict(
        ghidra_dir=tmp_path,
        server="h:1",
        repo="r",
        folder="/Vanilla/1.01",
        user="benam",
        password="pw",
        comment="c",
        timeout=10.0,
        log_dir=tmp_path / "logs",
    )
    upl.run_folder(apply_changes=True, **common)
    assert "-commit" in captured["cmd"]
    assert "-readOnly" not in captured["cmd"]
    assert "-noanalysis" in captured["cmd"], "auto-analysis must never rewrite documentation"
    assert captured["input"] == "pw\n", "password goes over stdin, never argv"
    assert "pw" not in " ".join(captured["cmd"]), "password must not appear in argv"

    upl.run_folder(apply_changes=False, **common)
    assert "-readOnly" in captured["cmd"]
    assert "-commit" not in captured["cmd"]


def test_folder_url_has_no_double_slash_for_root(monkeypatch, tmp_path):
    captured: dict[str, list[str]] = {}

    class FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    support = tmp_path / "support"
    support.mkdir()
    (support / ("analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless")).touch()
    monkeypatch.setattr(upl.subprocess, "run", lambda cmd, **kw: (captured.__setitem__("cmd", cmd), FakeCompleted())[1])

    upl.run_folder(
        ghidra_dir=tmp_path,
        server="h:1",
        repo="diablo2",
        folder="/",
        user="u",
        password="p",
        comment="c",
        apply_changes=False,
        timeout=10.0,
        log_dir=tmp_path / "logs",
    )
    assert captured["cmd"][1] == "ghidra://h:1/diablo2"
