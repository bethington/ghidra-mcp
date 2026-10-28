"""Unit tests for tools/build_reference_index.py.

Pure Python. Every Ghidra invocation goes through `subprocess.run`, which is the
single seam these tests replace -- no `bsim`, no `analyzeHeadless`, no BSim
database is touched.

The behaviours pinned here are the ones the module's own docstrings say cost
real debugging time:

* `analyzeHeadless` EXITS 0 WHEN A SCRIPT THROWS, so every step verifies its
  ARTIFACT (the .mv.db file, a "Writing signatures" line) rather than a return
  code. A refactor that trusts `returncode` would make this script report a
  successfully built index that is empty.
* the failure-line filter is ANCHORED on purpose: a bare `Exception` also
  matches the analyzer literally named "Windows x86 PE Exception Handling",
  which fires in every single run.
* a remote backend must survive VERBATIM. `os.path.abspath` on a
  `postgresql://` URL turns it into a nonsense path relative to the cwd.
* the password comes from an ENV VAR and is fed on stdin, because argv is
  readable by every other process on the box -- and because the `bsim` prompt
  reads stdin per-child, so a shell pipe reaches the first child and nothing
  after it.
* a binary already in the index is SKIPPED: BSim keys executables by md5, and
  committing one twice grows duplicate functions that tie with each other and
  abstain forever.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from tools import build_reference_index as bri


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _isolated_module_globals(monkeypatch):
    """`GHIDRA_HOME` and `BSIM_PASSWORD` are module-level state that `main()`
    writes. Leaking either between tests makes results order-dependent."""
    monkeypatch.setattr(bri, "GHIDRA_HOME", "")
    monkeypatch.setattr(bri, "BSIM_PASSWORD", None)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("BSIM_PASSWORD", raising=False)


def _fake_ghidra(root: Path) -> Path:
    """A directory that passes the `support/bsim.bat` existence check."""
    support = root / "support"
    support.mkdir(parents=True, exist_ok=True)
    (support / "bsim.bat").touch()
    (support / "analyzeHeadless.bat").touch()
    return root


class _Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _record_runs(monkeypatch, script=None):
    """Replace subprocess.run; return the list it records calls into.

    `script` maps a substring of the joined command to the output to return.
    """
    calls: list[dict] = []

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": list(cmd), "input": kwargs.get("input"),
                      "timeout": kwargs.get("timeout")})
        joined = " ".join(cmd)
        for needle, outcome in (script or {}).items():
            if needle in joined:
                return outcome if isinstance(outcome, _Completed) else _Completed(outcome)
        return _Completed()

    monkeypatch.setattr(bri.subprocess, "run", fake_run)
    return calls


# --------------------------------------------------------------------------- #
# find_ghidra_home -- VERIFY the install, never trust a name
# --------------------------------------------------------------------------- #


def test_explicit_home_is_accepted_only_when_the_tool_actually_exists(tmp_path):
    good = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")

    assert bri.find_ghidra_home(str(good)) == str(good)


def test_a_stale_env_var_is_rejected_rather_than_trusted(tmp_path, monkeypatch):
    """GHIDRA_INSTALL_DIR is stale on at least one box in this project -- it
    names a version that is not installed. Trusting it fails deep inside a
    subprocess with a confusing error."""
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "ghidra_9.0_PUBLIC"))
    monkeypatch.setattr(bri, "_SEARCH_ROOTS", (str(tmp_path),))

    real = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")

    assert bri.find_ghidra_home("") == str(real), "the scan must win over a name that does not exist"


def test_a_valid_env_var_short_circuits_the_disk_scan(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(home))
    monkeypatch.setattr(bri, "_SEARCH_ROOTS", ("/nonexistent-root",))

    assert bri.find_ghidra_home("") == str(home)


def test_newest_install_wins_by_NUMERIC_version_not_string_order(tmp_path, monkeypatch, capsys):
    """String ordering puts ghidra_9.2 above ghidra_12.1.2, which would pick a
    three-major-versions-old install to write an index with."""
    monkeypatch.setattr(bri, "_SEARCH_ROOTS", (str(tmp_path),))
    _fake_ghidra(tmp_path / "ghidra_9.2_PUBLIC")
    _fake_ghidra(tmp_path / "ghidra_12.1_PUBLIC")
    newest = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")

    assert bri.find_ghidra_home("") == str(newest)
    assert "several Ghidra installs found" in capsys.readouterr().out


def test_a_ghidra_dir_without_bsim_is_not_a_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(bri, "_SEARCH_ROOTS", (str(tmp_path),))
    (tmp_path / "ghidra_12.1.2_PUBLIC").mkdir()  # no support/bsim.bat

    with pytest.raises(SystemExit) as excinfo:
        bri.find_ghidra_home("")
    assert "no Ghidra install found" in str(excinfo.value)


def test_unreadable_and_missing_search_roots_are_skipped_not_fatal(tmp_path, monkeypatch):
    """`os.listdir` on a root that exists but denies access raises OSError. A
    reference-index build must not die because some drive is locked."""
    monkeypatch.setattr(bri, "_SEARCH_ROOTS", (str(tmp_path / "gone"), str(tmp_path)))
    real = os.listdir

    def picky_listdir(path):
        if str(path) == str(tmp_path):
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(bri.os, "listdir", picky_listdir)

    with pytest.raises(SystemExit):
        bri.find_ghidra_home("")


def test_ghidra_tool_refuses_a_missing_helper_by_name(tmp_path, monkeypatch):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))

    assert bri.ghidra_tool("bsim.bat").endswith(os.path.join("support", "bsim.bat"))
    with pytest.raises(SystemExit, match="not found"):
        bri.ghidra_tool("nope.bat")


# --------------------------------------------------------------------------- #
# URL vs path -- a remote backend must survive verbatim
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("index", [
    "postgresql://u@h:5432/bsim_ref",
    "elastic://h:9200/idx",
    "https://h/bsim",
    "file:/C:/bsim/refindex",
])
def test_every_bsim_scheme_is_recognised_as_a_url(index):
    assert bri.is_url(index) is True
    assert bri.bsim_url(index) == index, "a URL must pass through untouched"


@pytest.mark.parametrize("index", ["C:/bsim/refindex", "refindex", "/var/lib/refindex"])
def test_a_plain_path_is_not_a_url(index):
    assert bri.is_url(index) is False


def test_a_local_path_is_wrapped_as_a_file_url_with_forward_slashes():
    """An H2 path that reaches the `bsim` CLI unwrapped fails with an
    unhelpful error, and native separators are not valid in the URL."""
    native = os.sep.join(["C:", "bsim", "refindex"])

    assert bri.bsim_url(native) == "file:/C:/bsim/refindex"


# --------------------------------------------------------------------------- #
# run() -- loud, but not crying wolf
# --------------------------------------------------------------------------- #


def test_run_surfaces_real_failures(monkeypatch, capsys):
    monkeypatch.setattr(bri.subprocess, "run", lambda cmd, **kw: _Completed(
        stdout="INFO fine\nSCRIPT ERROR: boom\n",
        stderr="java.lang.NullPointerException\n",
        returncode=3,
    ))

    out = bri.run(["bsim.bat", "x"], "doing a thing")

    printed = capsys.readouterr().out
    assert "$ doing a thing" in printed
    assert "SCRIPT ERROR: boom" in printed
    assert "exit 3" in printed
    assert "SCRIPT ERROR" in out, "the full output is returned for the caller to verify"


def test_the_pe_exception_handling_ANALYZER_is_not_reported_as_a_failure(monkeypatch, capsys):
    """A bare `Exception` match hits the analyzer named "Windows x86 PE
    Exception Handling" in every single run. A failure channel that cries wolf
    every time is one you stop reading."""
    monkeypatch.setattr(bri.subprocess, "run", lambda cmd, **kw: _Completed(
        stdout="INFO  Windows x86 PE Exception Handling   0.100 secs\n"
               "INFO  Windows x86 PE RTTI Analyzer        0.050 secs\n",
    ))

    bri.run(["analyzeHeadless.bat"], "import")

    assert "!" not in capsys.readouterr().out.replace("$ import", "")


def test_the_password_is_fed_on_stdin_to_bsim_and_to_nothing_else(monkeypatch):
    """Remote backends prompt on EVERY `bsim` invocation, and the prompt reads
    stdin -- which a subprocess does not inherit usefully, so a shell-level
    pipe reaches the first child and nothing after it."""
    monkeypatch.setattr(bri, "BSIM_PASSWORD", "hunter2")
    calls = _record_runs(monkeypatch)

    bri.run([os.path.join("s", "bsim.bat"), "listexes"], "bsim")
    bri.run([os.path.join("s", "analyzeHeadless.bat"), "proj"], "analyze")

    assert calls[0]["input"] == "hunter2\n"
    assert calls[1]["input"] is None, "only the bsim CLI prompts"
    assert not any("hunter2" in " ".join(c["cmd"]) for c in calls), "argv is world-readable"


def test_no_stdin_is_supplied_when_no_password_is_configured(monkeypatch):
    calls = _record_runs(monkeypatch)

    bri.run([os.path.join("s", "bsim.bat"), "listexes"], "bsim")

    assert calls[0]["input"] is None


# --------------------------------------------------------------------------- #
# md5 + index_exists
# --------------------------------------------------------------------------- #


def test_md5_streams_a_file_larger_than_one_chunk(tmp_path):
    """The read loop uses 1 MiB chunks; a file that spans several must hash
    identically to the whole-buffer digest."""
    payload = (b"D2Common" * 4096) * 64  # 2 MiB
    binary = tmp_path / "big.dll"
    binary.write_bytes(payload)

    assert bri.md5(str(binary)) == hashlib.md5(payload).hexdigest()


def test_index_exists_is_a_FILE_test_for_h2(tmp_path, monkeypatch):
    calls = _record_runs(monkeypatch)
    index = str(tmp_path / "refindex")

    assert bri.index_exists(index) is False
    (tmp_path / "refindex.mv.db").touch()
    assert bri.index_exists(index) is True
    assert calls == [], "an H2 probe must not shell out"


def test_index_exists_ASKS_THE_SERVER_for_a_remote_backend(tmp_path, monkeypatch):
    """There is nothing on the local disk to look at, and `getmetadata`
    succeeds only against an initialised BSim database."""
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    calls = _record_runs(monkeypatch, {"getmetadata": "BSim metadata for medium_32"})

    assert bri.index_exists("postgresql://u@h/db") is True
    assert "getmetadata" in calls[0]["cmd"]
    assert calls[0]["timeout"] == 300


def test_a_remote_probe_that_says_nothing_useful_is_not_an_index(tmp_path, monkeypatch):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    _record_runs(monkeypatch, {"getmetadata": "The server does not support SSL"})

    assert bri.index_exists("postgresql://u@h/db") is False


# --------------------------------------------------------------------------- #
# create_index -- verify the ARTIFACT, never the exit code
# --------------------------------------------------------------------------- #


def test_create_index_verifies_the_file_appeared(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    index = str(tmp_path / "nested" / "refindex")

    def creating_run(cmd, **kw):
        if "createdatabase" in cmd:
            Path(index + ".mv.db").touch()
        return _Completed()

    monkeypatch.setattr(bri.subprocess, "run", creating_run)

    bri.create_index(index, "bsim_reference_index")

    assert Path(index + ".mv.db").exists()
    assert "creating index" in capsys.readouterr().out


def test_a_createdatabase_that_exits_zero_but_creates_nothing_is_a_failure(tmp_path, monkeypatch):
    """These tools report success far too readily; the exit code is not
    evidence of anything."""
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    _record_runs(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        bri.create_index(str(tmp_path / "refindex"), "n")
    assert ".mv.db" in str(excinfo.value)


def test_a_failed_remote_create_names_ssl_and_the_password_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    _record_runs(monkeypatch)  # getmetadata returns nothing -> not created

    with pytest.raises(SystemExit) as excinfo:
        bri.create_index("postgresql://u@h/db", "n")
    message = str(excinfo.value)
    assert "SSL" in message and "password" in message
    assert ".mv.db" not in message, "a remote backend has no such file"


def test_the_template_is_medium_32(tmp_path, monkeypatch):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    index = str(tmp_path / "refindex")
    calls = _record_runs(monkeypatch)
    monkeypatch.setattr(bri, "index_exists", lambda i: True)

    bri.create_index(index, "myname")

    assert bri.TEMPLATE == "medium_32"
    assert "medium_32" in calls[0]["cmd"]
    assert calls[0]["cmd"][-2:] == ["--name", "myname"]


# --------------------------------------------------------------------------- #
# listed_md5s + add_binary
# --------------------------------------------------------------------------- #


def test_listed_md5s_extracts_only_line_leading_digests(tmp_path, monkeypatch):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    listing = (
        "d41d8cd98f00b204e9800998ecf8427e libcrypto-1_1.dll\n"
        "0123456789abcdef0123456789abcdef BH.dll\n"
        "  indented deadbeefdeadbeefdeadbeefdeadbeef not-a-record\n"
    )
    _record_runs(monkeypatch, {"listexes": listing})

    assert bri.listed_md5s("idx") == {
        "d41d8cd98f00b204e9800998ecf8427e",
        "0123456789abcdef0123456789abcdef",
    }


def test_a_missing_binary_is_skipped_loudly_and_counted_as_not_added(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    _record_runs(monkeypatch)

    added = bri.add_binary("idx", str(tmp_path / "absent.dll"), str(tmp_path), force=False)

    assert added is False
    assert "SKIP (missing)" in capsys.readouterr().out


def test_a_binary_already_in_the_index_is_skipped_unless_forced(tmp_path, monkeypatch, capsys):
    """BSim keys executables by md5; committing the same one twice grows
    duplicate functions that then tie with each other and abstain forever."""
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    binary = tmp_path / "BH.dll"
    binary.write_bytes(b"MZ...")
    digest = bri.md5(str(binary))
    _record_runs(monkeypatch, {
        "listexes": f"{digest} BH.dll\n",
        "generatesigs": "Writing signatures\n",
    })

    assert bri.add_binary("idx", str(binary), str(tmp_path), force=False) is False
    assert f"SKIP (already indexed, md5 {digest[:8]})" in capsys.readouterr().out

    assert bri.add_binary("idx", str(binary), str(tmp_path), force=True) is True


def test_add_binary_reports_whether_a_pdb_sits_beside_the_dll(tmp_path, monkeypatch, capsys):
    """Without the PDB the names are weak, and an index of weak names is worse
    than no index -- the operator has to be told which they got."""
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    binary = tmp_path / "libcrypto-1_1.dll"
    binary.write_bytes(b"MZ")
    _record_runs(monkeypatch, {"generatesigs": "Writing signatures\n"})

    bri.add_binary("idx", str(binary), str(tmp_path), force=True)
    assert "NO PDB - names will be weak" in capsys.readouterr().out

    (tmp_path / "libcrypto-1_1.pdb").write_bytes(b"pdb")
    bri.add_binary("idx", str(binary), str(tmp_path), force=True)
    assert "+PDB" in capsys.readouterr().out


def test_no_signatures_written_is_a_failure_even_though_bsim_exited_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    binary = tmp_path / "d2common.dll"
    binary.write_bytes(b"MZ")
    _record_runs(monkeypatch, {"generatesigs": "Nothing to do.\n"})

    assert bri.add_binary("idx", str(binary), str(tmp_path), force=True) is False
    assert "no signatures were written" in capsys.readouterr().out


def test_each_binary_gets_its_own_throwaway_project_keyed_on_its_md5(tmp_path, monkeypatch):
    """A shared project accumulates state across runs and makes a re-run
    non-reproducible."""
    monkeypatch.setattr(bri, "GHIDRA_HOME", str(_fake_ghidra(tmp_path)))
    binary = tmp_path / "d2client.dll"
    binary.write_bytes(b"MZ")
    calls = _record_runs(monkeypatch, {"generatesigs": "Writing signatures\n"})

    bri.add_binary("idx", str(binary), str(tmp_path), force=True)

    project = f"ref_{bri.md5(str(binary))[:8]}"
    analyze = next(c for c in calls if "analyzeHeadless.bat" in c["cmd"][0])
    assert analyze["cmd"][2] == project
    assert "-import" in analyze["cmd"]
    sigs = next(c for c in calls if "generatesigs" in c["cmd"])
    assert sigs["cmd"][2].startswith("ghidra:/")
    assert "\\" not in sigs["cmd"][2], "a ghidra:/ URL takes forward slashes"


# --------------------------------------------------------------------------- #
# main()
# --------------------------------------------------------------------------- #


def _main(monkeypatch, argv, ghidra_home):
    monkeypatch.setattr(bri.sys, "argv", ["build_reference_index.py",
                                          "--ghidra-home", str(ghidra_home), *argv])
    return bri.main()


def test_list_on_an_absent_index_returns_one_rather_than_an_empty_success(tmp_path, monkeypatch, capsys):
    home = _fake_ghidra(tmp_path / "gh")
    _record_runs(monkeypatch)

    code = _main(monkeypatch, ["--index", str(tmp_path / "refindex"), "--list"], home)

    assert code == 1
    assert "no BSim index at" in capsys.readouterr().out


def test_list_prints_the_indexed_executables(tmp_path, monkeypatch, capsys):
    home = _fake_ghidra(tmp_path / "gh")
    index = tmp_path / "refindex"
    (tmp_path / "refindex.mv.db").touch()
    _record_runs(monkeypatch, {"listexes": "d41d8cd98f00b204e9800998ecf8427e BH.dll\n"})

    code = _main(monkeypatch, ["--index", str(index), "--list"], home)

    assert code == 0
    assert "BH.dll" in capsys.readouterr().out


def test_nothing_to_do_is_an_argparse_error_not_a_silent_success(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path / "gh")
    _record_runs(monkeypatch)

    with pytest.raises(SystemExit) as excinfo:
        _main(monkeypatch, ["--index", str(tmp_path / "refindex")], home)
    assert excinfo.value.code == 2


def test_main_creates_the_index_then_adds_each_binary(tmp_path, monkeypatch, capsys):
    home = _fake_ghidra(tmp_path / "gh")
    index = tmp_path / "refindex"
    for name in ("BH.dll", "ddraw.dll"):
        (tmp_path / name).write_bytes(b"MZ" + name.encode())

    def creating_run(cmd, **kw):
        if "createdatabase" in cmd:
            Path(str(index) + ".mv.db").touch()
            return _Completed()
        if "generatesigs" in cmd:
            return _Completed("Writing signatures\n")
        return _Completed()

    monkeypatch.setattr(bri.subprocess, "run", creating_run)

    code = _main(monkeypatch, [
        "--index", str(index),
        "--add", str(tmp_path / "BH.dll"),
        "--add", str(tmp_path / "ddraw.dll"),
    ], home)

    assert code == 0
    assert "indexed 2 of 2 binaries" in capsys.readouterr().out


def test_an_owned_temp_project_dir_is_cleaned_up_even_when_a_binary_fails(tmp_path, monkeypatch):
    """The temp dir holds a full Ghidra project per binary; leaking it fills
    the disk over a corpus-sized run."""
    home = _fake_ghidra(tmp_path / "gh")
    (tmp_path / "refindex.mv.db").touch()
    (tmp_path / "BH.dll").write_bytes(b"MZ")
    made: list[str] = []

    monkeypatch.setattr(bri.tempfile, "mkdtemp",
                        lambda prefix: made.append(str(tmp_path / "tmpproj")) or str(tmp_path / "tmpproj"))
    removed: list[str] = []
    monkeypatch.setattr(bri.shutil, "rmtree", lambda p, ignore_errors=False: removed.append(str(p)))
    _record_runs(monkeypatch, {"generatesigs": "nothing\n"})

    code = _main(monkeypatch, ["--index", str(tmp_path / "refindex"),
                               "--add", str(tmp_path / "BH.dll")], home)

    assert code == 0
    assert removed == made, "the temp project dir this run created must be removed"


def test_an_operator_supplied_project_dir_is_NOT_deleted(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path / "gh")
    (tmp_path / "refindex.mv.db").touch()
    (tmp_path / "BH.dll").write_bytes(b"MZ")
    keep = tmp_path / "keepme"
    keep.mkdir()
    removed: list[str] = []
    monkeypatch.setattr(bri.shutil, "rmtree", lambda p, ignore_errors=False: removed.append(str(p)))
    _record_runs(monkeypatch, {"generatesigs": "Writing signatures\n"})

    _main(monkeypatch, ["--index", str(tmp_path / "refindex"),
                        "--add", str(tmp_path / "BH.dll"),
                        "--project-dir", str(keep)], home)

    assert removed == [], "only a temp dir this run created may be removed"
    assert keep.is_dir()


def test_a_postgres_index_is_never_run_through_abspath(tmp_path, monkeypatch, capsys):
    """abspath would turn postgresql://host/db into a nonsense path relative to
    the cwd, and the resulting URL reaches `bsim` as garbage."""
    home = _fake_ghidra(tmp_path / "gh")
    url = "postgresql://u@h:5432/bsim_ref"
    calls = _record_runs(monkeypatch, {"getmetadata": "BSim metadata\n",
                                       "listexes": "\n"})

    code = _main(monkeypatch, ["--index", url, "--list"], home)

    assert code == 0
    assert any(url in c["cmd"] for c in calls), "the URL must reach bsim character-for-character"
    assert not any(os.path.abspath(url) in c["cmd"] for c in calls)


def test_a_remote_backend_reads_its_password_from_the_named_env_var(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path / "gh")
    monkeypatch.setenv("MY_BSIM_PW", "s3cret")
    calls = _record_runs(monkeypatch, {"getmetadata": "BSim metadata\n", "listexes": "\n"})

    _main(monkeypatch, ["--index", "postgresql://u@h/db", "--list",
                        "--password-env", "MY_BSIM_PW"], home)

    assert bri.BSIM_PASSWORD == "s3cret"
    assert all(c["input"] == "s3cret\n" for c in calls), "every bsim child needs its own copy"
    assert not any("s3cret" in " ".join(c["cmd"]) for c in calls)


def test_an_unset_password_var_warns_instead_of_failing(tmp_path, monkeypatch, capsys):
    """`bsim` will prompt interactively; that is workable for a human and only
    awkward unattended, so warn rather than refuse."""
    home = _fake_ghidra(tmp_path / "gh")
    _record_runs(monkeypatch, {"getmetadata": "BSim metadata\n", "listexes": "\n"})

    _main(monkeypatch, ["--index", "postgresql://u@h/db", "--list"], home)

    assert "$BSIM_PASSWORD is unset" in capsys.readouterr().err
    assert bri.BSIM_PASSWORD is None


def test_no_password_is_read_for_a_local_h2_index(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path / "gh")
    monkeypatch.setenv("BSIM_PASSWORD", "should-not-be-used")
    (tmp_path / "refindex.mv.db").touch()
    calls = _record_runs(monkeypatch, {"listexes": "\n"})

    _main(monkeypatch, ["--index", str(tmp_path / "refindex"), "--list"], home)

    assert bri.BSIM_PASSWORD is None
    assert all(c["input"] is None for c in calls)
