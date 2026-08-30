"""Unit tests for the DRIVER half of tools/upgrade_project_language.py.

``test_upgrade_project_language.py`` covers the leaf helpers -- credentials, the
log-line regexes, headless command construction. This file covers everything
that decides whether the tool *runs*: ``main()``'s refusals, the checkout
lifecycle, the report reconciliation, and the MCP transport helpers.

No Ghidra, no server, no subprocess. ``subprocess.run``, ``urllib.request`` and
the module's own MCP helpers are the seams.

Every refusal pinned here exists because its absence produced a run that
completed cleanly having done nothing (or having done something unrecoverable):

* ``--apply`` is NOT idempotent -- HeadlessAnalyzer does ``if canSave() save()``
  then commits unconditionally, and ``canSave()`` is true for any checked-out
  file regardless of changes, so every pass writes a new server version for
  every file it touches. A whole-project re-run within 24h is refused.
* Git Bash/MSYS rewrites ``--folder /Vanilla/1.01`` into
  ``C:/Program Files/Git/Vanilla/1.01``, which matches nothing.
* a requested folder that matches nothing must abort the whole run, not be
  quietly dropped from the plan and reported as success.
* a private (unversioned) file is UNREACHABLE through a ``ghidra://`` URL. It is
  not "skipped" -- counting it as covered overstates what the pass did.
* every planned program must be reconciled as opened or blocked; one that is
  neither was never attempted.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "upgrade_project_language.py"


def _load():
    """Reuse the already-imported module when the sibling test file loaded it,
    so both files monkeypatch the same globals."""
    existing = sys.modules.get("upgrade_project_language")
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location("upgrade_project_language", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


upl = _load()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _program(path: str, versioned: bool = True) -> dict:
    return {"name": path.rsplit("/", 1)[-1], "path": path,
            "content_type": "Program", "is_versioned": versioned}


CORPUS = [
    _program("/Vanilla/1.01/D2Game.dll"),
    _program("/Vanilla/1.01/Diablo II.exe"),
    _program("/Vanilla/1.02/D2Win.dll"),
]


def _fake_ghidra(root: Path) -> Path:
    support = root / "support"
    support.mkdir(parents=True, exist_ok=True)
    (support / "analyzeHeadless.bat").touch()
    (support / "analyzeHeadless").touch()
    return root


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A fully stubbed environment for main(): a Ghidra dir, a resolved server,
    a known inventory, no checkouts, and a cwd it can write reports into."""
    ghidra = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(upl, "resolve_ghidra_dir", lambda explicit: (ghidra, "test"))
    monkeypatch.setattr(upl, "resolve_server_and_repo",
                        lambda *a, **k: ("ghidra-host:13100", "diablo2", "test"))
    monkeypatch.setattr(upl, "walk_project", lambda base, root="/": list(CORPUS))
    monkeypatch.setattr(upl, "checkout_census", lambda base: {})
    monkeypatch.setattr(upl, "resolve_password", lambda d: ("pw", "test:GHIDRA_SERVER_PASSWORD"))
    monkeypatch.setattr(upl, "resolve_user", lambda d: "benam")
    return {"ghidra": ghidra, "cwd": tmp_path}


def _main(monkeypatch, *argv) -> int:
    monkeypatch.setattr(upl.sys, "argv", ["upgrade_project_language.py", *argv])
    return upl.main()


def _result(folder, **kwargs):
    return upl.FolderResult(folder=folder, returncode=0, **kwargs)


# --------------------------------------------------------------------------- #
# Preconditions -- refuse rather than guess
# --------------------------------------------------------------------------- #


def test_a_missing_ghidra_install_is_reported_with_the_source_that_named_it(
        tmp_path, monkeypatch, capsys):
    """"not found" alone leaves the operator hunting; the SOURCE is what tells
    them which stale variable to fix."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(upl, "resolve_ghidra_dir",
                        lambda explicit: (tmp_path / "absent", "$GHIDRA_INSTALL_DIR"))

    assert _main(monkeypatch) == 2
    err = capsys.readouterr().err
    assert "Ghidra install not found" in err
    assert "$GHIDRA_INSTALL_DIR" in err


def test_an_unresolvable_server_refuses_instead_of_guessing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(upl, "resolve_ghidra_dir",
                        lambda explicit: (_fake_ghidra(tmp_path / "g"), "test"))
    monkeypatch.setattr(upl, "resolve_server_and_repo", lambda *a, **k: (None, None, "unresolved"))

    assert _main(monkeypatch) == 2
    assert "could not determine the Ghidra Server" in capsys.readouterr().err


def test_a_failed_mcp_inventory_names_the_likely_cause(env, monkeypatch, capsys):
    def boom(base, root="/"):
        raise OSError("connection refused")

    monkeypatch.setattr(upl, "walk_project", boom)

    assert _main(monkeypatch) == 2
    err = capsys.readouterr().err
    assert "MCP inventory failed" in err
    assert "8089" in err


def test_an_empty_inventory_is_refused_not_treated_as_a_clean_project(env, monkeypatch, capsys):
    """Zero programs means the walk failed or the wrong project is open. An
    upgrade pass that reports success over an empty list has proved nothing."""
    monkeypatch.setattr(upl, "walk_project", lambda base, root="/": [])

    assert _main(monkeypatch) == 2
    assert "refusing to proceed on an empty inventory" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Folder selection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("folder", ["Vanilla/1.01", "C:/Program Files/Git/Vanilla", "/C:/Git/x"])
def test_an_msys_mangled_folder_is_refused_and_explained(env, monkeypatch, capsys, folder):
    """Git Bash rewrites a leading-slash argument into a Windows path, which
    matches nothing and makes the whole run a silent no-op."""
    assert _main(monkeypatch, "--folder", folder) == 2
    err = capsys.readouterr().err
    assert "do not look like project paths" in err
    assert "MSYS2_ARG_CONV_EXCL" in err


def test_a_requested_folder_that_matches_nothing_aborts_the_whole_run(env, monkeypatch, capsys):
    """Processing the remainder would report success for work never
    attempted."""
    assert _main(monkeypatch, "--folder", "/Vanilla/1.01", "--folder", "/Vanilla/9.99") == 2
    out = capsys.readouterr()
    assert "no Programs found in /Vanilla/9.99" in out.out
    assert "refusing to run" in out.err


def test_more_folders_than_the_limit_is_refused_not_silently_truncated(env, monkeypatch, capsys):
    assert _main(monkeypatch, "--limit", "1") == 2
    assert "exceeds --limit 1" in capsys.readouterr().err


def test_the_limit_permits_exactly_its_own_count(env, monkeypatch):
    assert _main(monkeypatch, "--limit", "2") == 0, "2 folders under --limit 2 must run"


# --------------------------------------------------------------------------- #
# Dry run (the default)
# --------------------------------------------------------------------------- #


def test_the_default_is_a_dry_run_that_writes_nothing(env, monkeypatch, capsys):
    called: list[str] = []
    monkeypatch.setattr(upl, "run_folder", lambda **kw: called.append(kw["folder"]))

    assert _main(monkeypatch) == 0
    assert called == [], "a dry run must not invoke headless at all"
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "nothing will be written" in out
    assert not list(env["cwd"].glob("reports/*.json"))


def test_private_files_are_reported_as_UNREACHABLE_not_merely_skipped(env, monkeypatch, capsys):
    """A ghidra:// URL exposes only VERSIONED files. Counting a private file in
    the plan overstates what the pass covers."""
    corpus = CORPUS + [_program("/Mods/PD2/PD2_EXT.dll", versioned=False)]
    monkeypatch.setattr(upl, "walk_project", lambda base, root="/": list(corpus))

    assert _main(monkeypatch) == 0
    out = capsys.readouterr().out
    assert "3 versioned (reachable), 1 private (NOT reachable via headless)" in out
    assert "private: /Mods/PD2/PD2_EXT.dll" in out
    assert "Total: 3 versioned" in out


def test_files_already_checked_out_by_the_gui_are_named_as_blockers(env, monkeypatch, capsys):
    """Headless runs as a SEPARATE project instance and cannot take an
    exclusive checkout on these -- it will skip them."""
    monkeypatch.setattr(upl, "checkout_census",
                        lambda base: {"/Vanilla/1.01/D2Game.dll": {"path": "/Vanilla/1.01/D2Game.dll"}})

    assert _main(monkeypatch) == 0
    out = capsys.readouterr().out
    assert "1 Programs already checked out by the GUI project" in out
    assert "- /Vanilla/1.01/D2Game.dll" in out
    assert "(1 blocked by existing checkout)" in out


def test_a_long_blocker_list_is_truncated_with_a_count(env, monkeypatch, capsys):
    many = [_program(f"/Big/{i}.dll") for i in range(15)]
    monkeypatch.setattr(upl, "walk_project", lambda base, root="/": many)
    monkeypatch.setattr(upl, "checkout_census", lambda base: {e["path"]: {} for e in many})

    _main(monkeypatch)
    out = capsys.readouterr().out
    assert "15 Programs already checked out" in out
    assert "... and 5 more" in out


def test_a_failing_checkout_census_warns_and_continues(env, monkeypatch, capsys):
    """The census is advisory. Aborting the plan because it failed would make a
    read-only listing a hard dependency of a dry run."""
    def boom(base):
        raise OSError("census down")

    monkeypatch.setattr(upl, "checkout_census", boom)

    assert _main(monkeypatch) == 0
    assert "[WARN] checkout census failed: census down" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# --apply
# --------------------------------------------------------------------------- #


def test_apply_runs_every_folder_and_writes_a_report(env, monkeypatch, capsys):
    seen: list[dict] = []

    def fake_run_folder(**kw):
        seen.append(kw)
        return _result(kw["folder"],
                       processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])],
                       committed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])])

    monkeypatch.setattr(upl, "run_folder", fake_run_folder)

    assert _main(monkeypatch, "--apply") == 0

    assert [k["folder"] for k in seen] == ["/Vanilla/1.01", "/Vanilla/1.02"]
    assert all(k["apply_changes"] is True for k in seen)
    assert all(k["password"] == "pw" for k in seen)

    reports = list((env["cwd"] / "reports").glob("language_upgrade_*.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["mode"] == "APPLY"
    assert report["totals"]["committed"] == 3
    assert report["unaccounted"] == {}
    assert report["repository"] == "ghidra://ghidra-host:13100/diablo2"
    assert "Ghidra's project tree is now stale" in capsys.readouterr().out


def test_a_planned_program_that_was_never_opened_is_reported_UNACCOUNTED(env, monkeypatch, capsys):
    """Without this reconciliation the run prints a clean summary having
    quietly missed a file."""
    monkeypatch.setattr(upl, "run_folder",
                        lambda **kw: _result(kw["folder"], processed=["/Vanilla/1.01/D2Game.dll"]))

    assert _main(monkeypatch, "--apply") == 1, "an unaccounted file must fail the run"
    out = capsys.readouterr().out
    assert "UNACCOUNTED -- planned but neither opened nor reported blocked" in out
    assert "/Vanilla/1.01/Diablo II.exe" in out

    report = json.loads(next((env["cwd"] / "reports").glob("*.json")).read_text(encoding="utf-8"))
    assert report["unaccounted"]["/Vanilla/1.01"] == ["/Vanilla/1.01/Diablo II.exe"]


def test_a_checkout_blocked_file_counts_as_accounted_for(env, monkeypatch):
    """It was attempted and refused, which is a known outcome -- not a miss."""
    def fake(**kw):
        paths = [e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]
        return _result(kw["folder"], processed=paths[:1], no_exclusive_checkout=paths[1:])

    monkeypatch.setattr(upl, "run_folder", fake)

    assert _main(monkeypatch, "--apply") == 0


def test_unauthorized_aborts_before_any_further_folder_is_attempted(env, monkeypatch, capsys):
    attempts: list[str] = []

    def fake(**kw):
        attempts.append(kw["folder"])
        result = _result(kw["folder"])
        result.unauthorized = True
        return result

    monkeypatch.setattr(upl, "run_folder", fake)

    assert _main(monkeypatch, "--apply") == 1
    assert attempts == ["/Vanilla/1.01"], "the second folder must never be tried"
    assert "the server rejected the credentials" in capsys.readouterr().err


def test_save_errors_and_too_new_files_fail_the_run(env, monkeypatch):
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"],
        processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])],
        save_errors=["/Vanilla/1.01/D2Game.dll"],
    ))

    assert _main(monkeypatch, "--apply") == 1


def test_a_nonzero_headless_returncode_fails_the_run(env, monkeypatch):
    def fake(**kw):
        result = _result(kw["folder"],
                         processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])])
        result.returncode = 1
        return result

    monkeypatch.setattr(upl, "run_folder", fake)

    assert _main(monkeypatch, "--apply") == 1


def test_a_timeout_returncode_of_None_is_not_treated_as_a_process_failure(env, monkeypatch):
    """run_folder sets returncode=None on timeout and the log already carries
    the *** TIMEOUT *** marker; the reconciliation is what catches the damage."""
    def fake(**kw):
        result = _result(kw["folder"],
                         processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])])
        result.returncode = None
        return result

    monkeypatch.setattr(upl, "run_folder", fake)

    assert _main(monkeypatch, "--apply") == 0


def test_saved_but_NOT_committed_is_called_out_in_the_progress_line(env, monkeypatch, capsys):
    """On a shared project only the commit line means the work reached the
    server. A folder that saved 3 files and committed none has changed nothing
    anyone else can see, and must not read as a success."""
    paths = {"/Vanilla/1.01": ["/Vanilla/1.01/D2Game.dll", "/Vanilla/1.01/Diablo II.exe"],
             "/Vanilla/1.02": ["/Vanilla/1.02/D2Win.dll"]}
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"], processed=paths[kw["folder"]], saved=paths[kw["folder"]]))

    assert _main(monkeypatch, "--apply") == 0
    out = capsys.readouterr().out
    assert "2 opened, 2 saved (NOT committed)" in out
    assert "1 opened, 1 saved (NOT committed)" in out
    assert "committed            0" in out, "the summary must not credit an uncommitted save"
    assert "project tree is now stale" not in out, "nothing reached the server"


def test_every_blocked_bucket_is_named_in_the_progress_line(env, monkeypatch, capsys):
    """A folder that opened one file and refused four must say so on the line
    the operator actually reads, not only in the JSON report."""
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"],
        processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])],
        committed=["/x.dll"],
        needs_upgrade_blocked=["/a.dll"],
        no_exclusive_checkout=["/b.dll"],
        newer_than_ghidra=["/c.dll"],
        save_errors=["/d.dll"],
    ))

    assert _main(monkeypatch, "--apply") == 1, "save errors and too-new files fail the run"
    out = capsys.readouterr().out
    for expected in ("1 committed", "1 UPGRADE-BLOCKED", "1 checkout-blocked",
                     "1 TOO-NEW", "1 SAVE-ERRORS"):
        assert expected in out


def test_missing_credentials_refuse_the_apply_and_name_the_env_file(env, monkeypatch, capsys):
    monkeypatch.setattr(upl, "resolve_password", lambda d: (None, "unset"))

    assert _main(monkeypatch, "--apply") == 2
    err = capsys.readouterr().err
    assert "no server password" in err
    assert "GHIDRA_SERVER_PASSWORD" in err
    assert ".env" in err


def test_cmd_metacharacters_are_stripped_from_the_checkin_comment(env, monkeypatch):
    """A parenthesis in the comment kills analyzeHeadless.bat with `"" was
    unexpected at this time` before the JVM is ever launched."""
    seen: list[str] = []
    monkeypatch.setattr(upl, "run_folder",
                        lambda **kw: seen.append(kw["comment"]) or _result(kw["folder"]))

    _main(monkeypatch, "--apply", "--force",
          "--comment", 'Upgrade (12.1.2) & more <now> ^ 100% "quoted" | piped!')

    assert seen[0] == "Upgrade 12.1.2  more now  100 quoted  piped"
    assert not set(seen[0]) & set('()&|<>^%!"')


def test_the_default_comment_names_the_ghidra_version_being_matched(env, monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(upl, "run_folder",
                        lambda **kw: seen.append(kw["comment"]) or _result(kw["folder"]))

    _main(monkeypatch, "--apply")

    assert seen[0] == "Language upgrade to ghidra_12.1.2_PUBLIC"


def test_the_folder_timeout_scales_with_the_program_count_above_a_floor(env, monkeypatch):
    seen: list[float] = []
    monkeypatch.setattr(upl, "run_folder",
                        lambda **kw: seen.append(kw["timeout"]) or _result(kw["folder"]))

    _main(monkeypatch, "--apply", "--timeout-per-file", "100", "--min-timeout", "150")

    assert seen == [200.0, 150.0], "2 programs -> 200s; 1 program -> the 150s floor"


# --------------------------------------------------------------------------- #
# The 24h whole-project re-run guard
# --------------------------------------------------------------------------- #


def _prior_apply_report(cwd: Path, name="language_upgrade_20260825-120000.json", mode="APPLY"):
    reports = cwd / "reports"
    reports.mkdir(exist_ok=True)
    path = reports / name
    path.write_text(json.dumps({"mode": mode}), encoding="utf-8")
    return path


def test_a_second_whole_project_apply_within_24h_is_refused(env, monkeypatch, capsys):
    """--apply is NOT idempotent and must not be used as its own verification:
    canSave() is true for any checked-out file regardless of changes, so every
    pass writes a new server version for every file it touches."""
    _prior_apply_report(env["cwd"])
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(kw["folder"]))

    assert _main(monkeypatch, "--apply") == 2
    err = capsys.readouterr().err
    assert "already ran within 24h" in err
    assert "--verify" in err and "--force" in err


def test_force_overrides_the_24h_guard(env, monkeypatch):
    _prior_apply_report(env["cwd"])
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"], processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]))

    assert _main(monkeypatch, "--apply", "--force") == 0


def test_a_folder_scoped_apply_is_not_a_whole_project_rerun(env, monkeypatch):
    """--folder is the sanctioned way to retry a genuine subset."""
    _prior_apply_report(env["cwd"])
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"], processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]))

    assert _main(monkeypatch, "--apply", "--folder", "/Vanilla/1.01") == 0


def test_a_prior_PREFLIGHT_report_does_not_trip_the_apply_guard(env, monkeypatch):
    """A preflight writes nothing to the server, so it is not the thing the
    guard protects against."""
    _prior_apply_report(env["cwd"], mode="PREFLIGHT (read-only)")
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"], processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]))

    assert _main(monkeypatch, "--apply") == 0


def test_an_apply_report_older_than_24h_does_not_block(env, monkeypatch):
    path = _prior_apply_report(env["cwd"])
    old = upl.time.time() - 200000
    os.utime(path, (old, old))
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"], processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]))

    assert _main(monkeypatch, "--apply") == 0


# --------------------------------------------------------------------------- #
# --preflight
# --------------------------------------------------------------------------- #


def test_preflight_runs_headless_READ_ONLY(env, monkeypatch, capsys):
    seen: list[dict] = []
    monkeypatch.setattr(upl, "run_folder", lambda **kw: seen.append(kw) or _result(
        kw["folder"], processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]))

    assert _main(monkeypatch, "--preflight") == 0
    assert all(k["apply_changes"] is False for k in seen)
    out = capsys.readouterr().out
    assert "PREFLIGHT (read-only)" in out
    assert "Preflighting 2 folders" in out
    assert "project tree is now stale" not in out, "nothing was committed"


def test_a_report_path_can_be_directed_somewhere_explicit(env, monkeypatch):
    target = env["cwd"] / "out" / "custom.json"
    monkeypatch.setattr(upl, "run_folder", lambda **kw: _result(
        kw["folder"], processed=[e["path"] for e in CORPUS if e["path"].startswith(kw["folder"])]))

    _main(monkeypatch, "--preflight", "--report", str(target))

    assert json.loads(target.read_text(encoding="utf-8"))["mode"] == "PREFLIGHT (read-only)"


# --------------------------------------------------------------------------- #
# --verify
# --------------------------------------------------------------------------- #


def test_verify_samples_one_program_per_folder_by_default(env, monkeypatch, capsys):
    """The probe leaks an exclusive checkout per program, so the sample must
    stay small by default -- a 152-program probe stranded 140 checkouts."""
    probed: list[str] = []

    def fake_probe(base, path, leaked=None):
        probed.append(path)
        return "current", '{"success": true}'

    monkeypatch.setattr(upl, "probe_language_state", fake_probe)

    assert _main(monkeypatch, "--verify") == 0
    assert probed == ["/Vanilla/1.01/D2Game.dll", "/Vanilla/1.02/D2Win.dll"]
    assert "current: 2   stale: 0   unknown: 0" in capsys.readouterr().out


def test_verify_sample_zero_probes_every_program(env, monkeypatch):
    probed: list[str] = []
    monkeypatch.setattr(upl, "probe_language_state",
                        lambda b, p, leaked=None: probed.append(p) or ("current", "{}"))

    _main(monkeypatch, "--verify", "--verify-sample", "0")

    assert len(probed) == 3


def test_a_stale_program_fails_verify_and_points_at_apply(env, monkeypatch, capsys):
    monkeypatch.setattr(upl, "probe_language_state",
                        lambda b, p, leaked=None: ("stale", "Minor language change 4.6 -> 4.7"))

    assert _main(monkeypatch, "--verify") == 1
    out = capsys.readouterr().out
    assert "STALE   /Vanilla/1.01/D2Game.dll" in out
    assert "re-run with --apply" in out


def test_an_UNKNOWN_probe_is_not_reported_as_passed(env, monkeypatch, capsys):
    """An unreadable probe must never certify anything -- otherwise the
    verification step quietly certifies nothing at all."""
    monkeypatch.setattr(upl, "probe_language_state",
                        lambda b, p, leaked=None: ("unknown", "checkout failed"))

    assert _main(monkeypatch, "--verify") == 1
    assert "UNKNOWN /Vanilla/1.01/D2Game.dll" in capsys.readouterr().out


def test_leaked_checkouts_are_recorded_and_warned_about_LOUDLY(env, monkeypatch, capsys):
    """open_program registers a DomainObject consumer nothing releases, so the
    checkout survives until Ghidra restarts. Leaving the project quietly worse
    than we found it is the failure mode."""
    def leaking(base, path, leaked=None):
        leaked.append(path)
        return "current", "{}"

    monkeypatch.setattr(upl, "probe_language_state", leaking)

    assert _main(monkeypatch, "--verify") == 1, "a leak alone must fail the run"
    out = capsys.readouterr().out
    assert "exclusive checkout(s) could NOT be released" in out
    assert "restart Ghidra" in out
    assert "--release-checkouts" in out

    # NOTE: --verify always records to this fixed path; it does not honour
    # --stray-file, which only --release-checkouts reads. Pinned as-is so a
    # deliberate fix has to update this assertion rather than drift past it.
    recorded = json.loads((env["cwd"] / "reports" / "verify_stray_checkouts.json")
                          .read_text(encoding="utf-8"))
    assert recorded == ["/Vanilla/1.01/D2Game.dll", "/Vanilla/1.02/D2Win.dll"]


def test_newly_leaked_checkouts_are_merged_with_previously_recorded_ones(env, monkeypatch):
    reports = env["cwd"] / "reports"
    reports.mkdir()
    (reports / "verify_stray_checkouts.json").write_text(
        json.dumps(["/Older/leak.dll"]), encoding="utf-8")
    monkeypatch.setattr(upl, "probe_language_state",
                        lambda b, p, leaked=None: (leaked.append(p), ("current", "{}"))[1])

    _main(monkeypatch, "--verify")

    recorded = json.loads((reports / "verify_stray_checkouts.json").read_text(encoding="utf-8"))
    assert "/Older/leak.dll" in recorded, "a prior run's leaks must not be dropped"
    assert "/Vanilla/1.01/D2Game.dll" in recorded


def test_a_corrupt_stray_file_is_replaced_rather_than_crashing_the_probe(env, monkeypatch):
    reports = env["cwd"] / "reports"
    reports.mkdir()
    (reports / "verify_stray_checkouts.json").write_text("not json", encoding="utf-8")
    monkeypatch.setattr(upl, "probe_language_state",
                        lambda b, p, leaked=None: (leaked.append(p), ("current", "{}"))[1])

    _main(monkeypatch, "--verify")

    recorded = json.loads((reports / "verify_stray_checkouts.json").read_text(encoding="utf-8"))
    assert recorded == ["/Vanilla/1.01/D2Game.dll", "/Vanilla/1.02/D2Win.dll"]


# --------------------------------------------------------------------------- #
# --release-checkouts
# --------------------------------------------------------------------------- #


def _stray_file(cwd: Path, paths) -> Path:
    reports = cwd / "reports"
    reports.mkdir(exist_ok=True)
    path = reports / "verify_stray_checkouts.json"
    path.write_text(json.dumps(list(paths)), encoding="utf-8")
    return path


def test_release_with_no_recorded_strays_is_a_clean_no_op(env, monkeypatch, capsys):
    assert _main(monkeypatch, "--release-checkouts") == 0
    assert "Nothing to do" in capsys.readouterr().out


def _live_server(monkeypatch, checked_out, *, releasable=True):
    """A census backed by mutable state, so the re-poll sees what undo did.

    A call-counting stub cannot model this: main() reads the census once for
    the plan and again for the release, and the whole point of the re-poll is
    that it observes a DIFFERENT answer than the per-call results claimed.
    """
    live = {path: {} for path in checked_out}
    undone: list[str] = []

    def undo(base, path):
        undone.append(path)
        if not releasable:
            return False, f"{path.rsplit('/', 1)[-1]} is in use"
        live.pop(path, None)
        return True, "released"

    monkeypatch.setattr(upl, "checkout_census", lambda base: dict(live))
    monkeypatch.setattr(upl, "undo_checkout", undo)
    return undone, live


def test_release_only_touches_checkouts_this_tool_recorded_creating(env, monkeypatch):
    """Undoing an arbitrary checkout discards whatever local work it held."""
    _stray_file(env["cwd"], ["/Vanilla/1.01/D2Game.dll"])
    # /Vanilla/1.02/D2Win.dll is the operator's own -- it must be left alone.
    undone, live = _live_server(
        monkeypatch, ["/Vanilla/1.01/D2Game.dll", "/Vanilla/1.02/D2Win.dll"])

    assert _main(monkeypatch, "--release-checkouts") == 0
    assert undone == ["/Vanilla/1.01/D2Game.dll"]
    assert "/Vanilla/1.02/D2Win.dll" in live


def test_release_repolls_and_refuses_to_believe_its_own_success(env, monkeypatch, capsys):
    """The census lags the server: "released 140, stuck 0" was reported while
    two checkouts were still live. Silence there is what let that stand."""
    _stray_file(env["cwd"], ["/Vanilla/1.01/D2Game.dll"])
    monkeypatch.setattr(upl, "checkout_census", lambda base: {"/Vanilla/1.01/D2Game.dll": {}})
    monkeypatch.setattr(upl, "undo_checkout", lambda base, path: (True, "released"))

    assert _main(monkeypatch, "--release-checkouts") == 1, "still present on re-poll => failure"
    out = capsys.readouterr().out
    assert "STILL CHECKED OUT after re-poll: 1" in out
    assert "run this again" in out


def test_a_stuck_checkout_is_named_and_kept_in_the_stray_file(env, monkeypatch, capsys):
    path = _stray_file(env["cwd"], ["/Vanilla/1.01/D2Game.dll"])
    _live_server(monkeypatch, ["/Vanilla/1.01/D2Game.dll"], releasable=False)

    assert _main(monkeypatch, "--release-checkouts") == 1
    assert "STUCK /Vanilla/1.01/D2Game.dll: D2Game.dll is in use" in capsys.readouterr().out
    assert json.loads(path.read_text(encoding="utf-8")) == ["/Vanilla/1.01/D2Game.dll"], \
        "a stuck path must survive for the next attempt"


def test_a_successfully_released_checkout_is_dropped_from_the_stray_file(env, monkeypatch):
    path = _stray_file(env["cwd"], ["/Vanilla/1.01/D2Game.dll"])
    _live_server(monkeypatch, ["/Vanilla/1.01/D2Game.dll"])

    assert _main(monkeypatch, "--release-checkouts") == 0
    assert json.loads(path.read_text(encoding="utf-8")) == []


def test_a_baseline_report_widens_the_release_to_strays_the_census_missed(env, monkeypatch):
    """/server/checkouts reads LOCAL project data that lags the server, so a
    checkout created moments earlier can be absent from the census and never
    recorded. Anything NOT in the baseline's preexisting set is ours."""
    _stray_file(env["cwd"], [])
    baseline = env["cwd"] / "baseline.json"
    baseline.write_text(json.dumps({"preexisting_checkouts": ["/Theirs/x.dll"]}), encoding="utf-8")
    undone, live = _live_server(monkeypatch, ["/Theirs/x.dll", "/Vanilla/1.01/D2Game.dll"])

    assert _main(monkeypatch, "--release-checkouts", "--baseline", str(baseline)) == 0
    assert undone == ["/Vanilla/1.01/D2Game.dll"], "the operator's own checkout is untouched"
    assert "/Theirs/x.dll" in live


# --------------------------------------------------------------------------- #
# MCP transport helpers
# --------------------------------------------------------------------------- #


class _Resp:
    def __init__(self, raw: bytes):
        self._raw = raw

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(monkeypatch, raw: bytes, sink: dict | None = None):
    def opener(url_or_request, timeout=None):
        if sink is not None:
            if hasattr(url_or_request, "full_url"):
                sink["url"] = url_or_request.full_url
                sink["body"] = url_or_request.data
                sink["method"] = url_or_request.get_method()
                sink["headers"] = url_or_request.headers
            else:
                sink["url"] = url_or_request
            sink["timeout"] = timeout
        return _Resp(raw)

    monkeypatch.setattr(upl.urllib.request, "urlopen", opener)


def test_mcp_get_returns_a_non_json_body_verbatim(monkeypatch):
    _fake_urlopen(monkeypatch, b"plain text error")

    assert upl.mcp_get("http://h:8089", "check_connection") == "plain text error"


def test_mcp_get_passes_through_a_result_that_is_already_structured(monkeypatch):
    _fake_urlopen(monkeypatch, json.dumps({"result": {"a": 1}}).encode())

    assert upl.mcp_get("http://h:8089", "x") == {"a": 1}


def test_mcp_get_returns_an_unwrappable_result_string_as_a_string(monkeypatch):
    _fake_urlopen(monkeypatch, json.dumps({"result": "checked_out"}).encode())

    assert upl.mcp_get("http://h:8089", "x") == "checked_out"


def test_mcp_get_returns_an_unenveloped_payload_unchanged(monkeypatch):
    _fake_urlopen(monkeypatch, json.dumps({"status": "ok"}).encode())

    assert upl.mcp_get("http://h:8089", "x") == {"status": "ok"}


def test_mcp_post_sends_a_JSON_BODY_not_a_query_string(monkeypatch):
    """The version-control routes read their arguments with parseJsonParams; a
    query string reaches them as `'path' parameter required`."""
    sink: dict = {}
    _fake_urlopen(monkeypatch, json.dumps({"result": '{"status": "checkout_undone"}'}).encode(), sink)

    out = upl.mcp_post("http://h:8089/", "/server/version_control/undo_checkout",
                       path="/Vanilla/1.01/D2Game.dll")

    assert out == {"status": "checkout_undone"}
    assert sink["method"] == "POST"
    assert sink["url"] == "http://h:8089/server/version_control/undo_checkout"
    assert json.loads(sink["body"]) == {"path": "/Vanilla/1.01/D2Game.dll"}
    assert sink["headers"]["Content-type"] == "application/json"


def test_mcp_post_survives_a_non_json_response(monkeypatch):
    _fake_urlopen(monkeypatch, b"<html>500</html>")

    assert upl.mcp_post("http://h:8089", "x") == "<html>500</html>"


def test_mcp_post_unwraps_a_structured_result_and_an_unparseable_one(monkeypatch):
    _fake_urlopen(monkeypatch, json.dumps({"result": {"ok": True}}).encode())
    assert upl.mcp_post("http://h:8089", "x") == {"ok": True}

    _fake_urlopen(monkeypatch, json.dumps({"result": "raw"}).encode())
    assert upl.mcp_post("http://h:8089", "x") == "raw"

    _fake_urlopen(monkeypatch, json.dumps({"other": 1}).encode())
    assert upl.mcp_post("http://h:8089", "x") == {"other": 1}


def test_walk_project_does_not_revisit_a_folder_or_loop_forever(monkeypatch, capsys):
    """A project tree that names itself as its own child would otherwise spin."""
    listings = {
        "/": {"files": [], "folders": ["Vanilla"]},
        "/Vanilla": {"files": [_program("/Vanilla/D2Game.dll")], "folders": ["Vanilla"]},
    }
    seen: list[str] = []

    def fake_get(base, endpoint, timeout=60.0, **params):
        seen.append(params["folder"])
        return listings.get(params["folder"], {"files": [], "folders": []})

    monkeypatch.setattr(upl, "mcp_get", fake_get)

    found = upl.walk_project("http://h:8089")

    assert [e["path"] for e in found] == ["/Vanilla/D2Game.dll"]
    assert seen == ["/", "/Vanilla", "/Vanilla/Vanilla"]


def test_a_folder_queued_twice_is_listed_only_once(monkeypatch):
    """A duplicated child entry would otherwise double-count every Program
    underneath it, and the plan's totals are what the operator reconciles the
    run against."""
    listings = {
        "/": {"files": [], "folders": ["Vanilla", "Vanilla"]},
        "/Vanilla": {"files": [_program("/Vanilla/D2Game.dll")], "folders": []},
    }
    visits: list[str] = []

    def fake_get(base, endpoint, timeout=60.0, **params):
        visits.append(params["folder"])
        return listings[params["folder"]]

    monkeypatch.setattr(upl, "mcp_get", fake_get)

    found = upl.walk_project("http://h:8089")

    assert [e["path"] for e in found] == ["/Vanilla/D2Game.dll"], "no duplicate Program"
    assert visits == ["/", "/Vanilla"], "the second queue entry is dropped, not re-listed"


def test_walk_project_ignores_a_folder_listing_that_is_not_a_mapping(monkeypatch):
    monkeypatch.setattr(upl, "mcp_get", lambda base, endpoint, timeout=60.0, **p: "server error")

    assert upl.walk_project("http://h:8089") == []


# --------------------------------------------------------------------------- #
# Checkout lifecycle
# --------------------------------------------------------------------------- #


def test_undo_checkout_closes_the_program_first_then_releases(monkeypatch):
    posted: list[tuple[str, dict]] = []
    monkeypatch.setattr(upl, "mcp_post", lambda base, endpoint, **kw: (
        posted.append((endpoint, kw)), {"status": "checkout_undone"})[1])

    released, detail = upl.undo_checkout("http://h", "/Vanilla/1.01/D2Game.dll")

    assert released is True and detail == "released"
    assert [e for e, _ in posted] == ["close_program", "server/version_control/undo_checkout"]


def test_undo_checkout_never_raises_when_close_program_fails(monkeypatch):
    """close is best effort -- a failure there must not stop the release."""
    def flaky(base, endpoint, **kw):
        if endpoint == "close_program":
            raise OSError("no such program")
        return {"status": "checkout_undone"}

    monkeypatch.setattr(upl, "mcp_post", flaky)

    assert upl.undo_checkout("http://h", "/p") == (True, "released")


def test_undo_checkout_reports_a_transport_failure_rather_than_raising(monkeypatch):
    def boom(base, endpoint, **kw):
        if endpoint == "close_program":
            return {}
        raise OSError("connection reset")

    monkeypatch.setattr(upl, "mcp_post", boom)
    released, detail = upl.undo_checkout("http://h", "/p")

    assert released is False and "connection reset" in detail


def test_undo_checkout_reports_a_refusal_verbatim(monkeypatch):
    monkeypatch.setattr(upl, "mcp_post",
                        lambda base, endpoint, **kw: {"error": "D2Game.dll is in use"})

    released, detail = upl.undo_checkout("http://h", "/p")

    assert released is False
    assert "is in use" in detail


def test_undo_checkout_passes_a_plain_string_refusal_through(monkeypatch):
    monkeypatch.setattr(upl, "mcp_post", lambda base, endpoint, **kw: "not checked out")

    assert upl.undo_checkout("http://h", "/p") == (False, "not checked out")


# --------------------------------------------------------------------------- #
# probe_language_state -- the staleness oracle
# --------------------------------------------------------------------------- #


def _probe_env(monkeypatch, *, checkouts=(), checkout_ok=True, opened=None):
    posted: list[str] = []

    def fake_get(base, endpoint, timeout=60.0, **params):
        if endpoint == "server/checkouts":
            return {"checkouts": [{"path": p} for p in checkouts]}
        return opened

    def fake_post(base, endpoint, **params):
        posted.append(endpoint)
        if endpoint.endswith("checkout"):
            return {"status": "checked_out"} if checkout_ok else {"status": "denied"}
        return {"status": "checkout_undone"}

    monkeypatch.setattr(upl, "mcp_get", fake_get)
    monkeypatch.setattr(upl, "mcp_post", fake_post)
    return posted


def test_a_program_that_opens_read_write_is_current(monkeypatch):
    posted = _probe_env(monkeypatch, opened={"success": True})

    state, _ = upl.probe_language_state("http://h", "/p")

    assert state == "current"
    assert "server/version_control/checkout" in posted
    assert "server/version_control/undo_checkout" in posted, "the probe must clean up after itself"


def test_a_minor_language_change_is_reported_as_STALE(monkeypatch):
    """FrontEndProgramProvider passes okToUpgrade=false, so a stale program
    surfaces this message instead of being silently upgraded."""
    _probe_env(monkeypatch, opened={"success": False,
                                    "error": "Minor language change 4.6 -> 4.7"})

    state, detail = upl.probe_language_state("http://h", "/p")

    assert state == "stale"
    assert "4.6 -> 4.7" in detail


def test_a_major_language_change_is_also_stale(monkeypatch):
    _probe_env(monkeypatch, opened={"error": "Major language change 3.0 -> 4.7"})

    assert upl.probe_language_state("http://h", "/p")[0] == "stale"


def test_an_unrecognised_open_failure_is_unknown_not_current(monkeypatch):
    _probe_env(monkeypatch, opened={"error": "file not found"})

    assert upl.probe_language_state("http://h", "/p")[0] == "unknown"


def test_a_refused_checkout_is_unknown_and_takes_no_checkout_to_undo(monkeypatch):
    posted = _probe_env(monkeypatch, checkout_ok=False)

    state, detail = upl.probe_language_state("http://h", "/p")

    assert state == "unknown"
    assert "checkout failed" in detail
    assert "server/version_control/undo_checkout" not in posted


def test_a_preexisting_checkout_is_reused_and_NOT_released_by_the_probe(monkeypatch):
    """Releasing a checkout the operator already held would discard their
    local work."""
    posted = _probe_env(monkeypatch, checkouts=("/p",), opened={"success": True})

    assert upl.probe_language_state("http://h", "/p")[0] == "current"
    assert posted == [], "no checkout taken, so none to undo"


def test_a_checkout_the_probe_cannot_release_is_appended_to_leaked(monkeypatch):
    monkeypatch.setattr(upl, "mcp_get", lambda base, endpoint, timeout=60.0, **p:
                        {"checkouts": []} if endpoint == "server/checkouts" else {"success": True})
    monkeypatch.setattr(upl, "mcp_post", lambda base, endpoint, **p:
                        {"status": "checked_out"} if endpoint.endswith("/checkout")
                        else {"error": "is in use"})
    leaked: list[str] = []

    upl.probe_language_state("http://h", "/p", leaked)

    assert leaked == ["/p"]


def test_a_transport_failure_mid_probe_is_unknown_and_still_releases(monkeypatch):
    released: list[str] = []

    def fake_get(base, endpoint, timeout=60.0, **params):
        if endpoint == "server/checkouts":
            return {"checkouts": []}
        raise OSError("socket closed")

    monkeypatch.setattr(upl, "mcp_get", fake_get)
    monkeypatch.setattr(upl, "mcp_post", lambda base, endpoint, **p: (
        released.append(endpoint), {"status": "checked_out" if endpoint.endswith("/checkout")
                                    else "checkout_undone"})[1])

    state, detail = upl.probe_language_state("http://h", "/p")

    assert state == "unknown"
    assert "socket closed" in detail
    assert "server/version_control/undo_checkout" in released


# --------------------------------------------------------------------------- #
# run_folder -- timeout, log capture, bucketing
# --------------------------------------------------------------------------- #


def _run_folder(tmp_path, monkeypatch, runner, **overrides):
    ghidra = _fake_ghidra(tmp_path / "gh")
    monkeypatch.setattr(upl.subprocess, "run", runner)
    kwargs = dict(ghidra_dir=ghidra, server="h:1", repo="diablo2", folder="/Vanilla/1.01",
                  user="u", password="p", comment="c", apply_changes=False,
                  timeout=5.0, log_dir=tmp_path / "logs")
    kwargs.update(overrides)
    return upl.run_folder(**kwargs)


def test_run_folder_buckets_every_outcome_from_the_log(tmp_path, monkeypatch):
    log = (
        "INFO  REPORT: Processing project file: /Vanilla/1.01/D2Game.dll (HeadlessAnalyzer)\n"
        "INFO  REPORT: Save succeeded for processed file: /Vanilla/1.01/D2Game.dll (HeadlessAnalyzer)\n"
        "INFO  REPORT: Committed file changes to repository: /Vanilla/1.01/D2Game.dll (HeadlessAnalyzer)\n"
        "WARN  Skipped processing for /Vanilla/1.01/Diablo II.exe -- failed to get exclusive"
        " file checkout required for commit\n"
        "ERROR /Vanilla/1.01/Fog.dll: this file was created with an older version of Ghidra.\n"
        "ERROR /Vanilla/1.01/New.dll: this file was created with a newer version of Ghidra,"
        " and can not be processed.\n"
        "ERROR REPORT: Error trying to save changes to file: /Vanilla/1.01/Storm.dll\n"
    )

    class Done:
        stdout, stderr, returncode = log, "", 0

    result = _run_folder(tmp_path, monkeypatch, lambda cmd, **kw: Done())

    assert result.processed == ["/Vanilla/1.01/D2Game.dll"]
    assert result.saved == ["/Vanilla/1.01/D2Game.dll"]
    assert result.committed == ["/Vanilla/1.01/D2Game.dll"]
    assert result.no_exclusive_checkout == ["/Vanilla/1.01/Diablo II.exe"]
    assert result.needs_upgrade_blocked == ["/Vanilla/1.01/Fog.dll"]
    assert result.newer_than_ghidra == ["/Vanilla/1.01/New.dll"]
    assert result.save_errors == ["/Vanilla/1.01/Storm.dll"]
    assert result.unauthorized is False


def test_run_folder_writes_the_whole_log_to_a_file_named_for_the_folder(tmp_path, monkeypatch):
    class Done:
        stdout, stderr, returncode = "out\n", "err\n", 0

    result = _run_folder(tmp_path, monkeypatch, lambda cmd, **kw: Done())

    assert Path(result.log_path).name == "Vanilla_1.01.log"
    assert Path(result.log_path).read_text(encoding="utf-8") == "out\nerr\n"


def test_the_root_folder_log_is_named_root_not_an_empty_string(tmp_path, monkeypatch):
    class Done:
        stdout, stderr, returncode = "", "", 0

    result = _run_folder(tmp_path, monkeypatch, lambda cmd, **kw: Done(), folder="/")

    assert Path(result.log_path).name == "root.log"


def test_a_timeout_is_recorded_in_the_log_with_a_null_returncode(tmp_path, monkeypatch):
    """The partial output is what says how far the run got; discarding it on
    timeout leaves nothing to diagnose."""
    def timing_out(cmd, **kw):
        raise subprocess.TimeoutExpired(
            cmd, 5.0,
            output="INFO  REPORT: Processing project file: /Vanilla/1.01/D2Game.dll\n",
            stderr="")

    result = _run_folder(tmp_path, monkeypatch, timing_out)

    assert result.returncode is None
    assert result.processed == ["/Vanilla/1.01/D2Game.dll"], "partial progress is kept"
    assert "*** TIMEOUT after 5.0s ***" in Path(result.log_path).read_text(encoding="utf-8")


def test_a_timeout_with_BYTES_output_does_not_crash_the_parser(tmp_path, monkeypatch):
    """TimeoutExpired carries bytes when the child was not opened in text mode;
    concatenating those with a str raises inside the error handler itself."""
    def timing_out(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 5.0, output=b"raw", stderr=b"raw")

    result = _run_folder(tmp_path, monkeypatch, timing_out)

    assert result.returncode is None
    assert "*** TIMEOUT" in Path(result.log_path).read_text(encoding="utf-8")


def test_an_auth_rejection_sets_the_unauthorized_flag(tmp_path, monkeypatch):
    class Done:
        stdout = "ERROR NotConnectedException: Unauthorized\n"
        stderr, returncode = "", 1

    result = _run_folder(tmp_path, monkeypatch, lambda cmd, **kw: Done())

    assert result.unauthorized is True
    assert result.returncode == 1


def test_analyze_headless_is_refused_by_name_when_the_install_lacks_it(tmp_path):
    with pytest.raises(SystemExit, match="analyzeHeadless not found"):
        upl.analyze_headless_cmd(tmp_path / "not-a-ghidra")


# --------------------------------------------------------------------------- #
# Install discovery
# --------------------------------------------------------------------------- #


def test_an_explicit_ghidra_dir_wins_over_every_form_of_discovery(tmp_path):
    assert upl.resolve_ghidra_dir(str(tmp_path)) == (Path(str(tmp_path)), "--ghidra-dir")


def test_the_RUNNING_ghidra_outranks_the_environment_variable(tmp_path, monkeypatch):
    """An upgrade written by the wrong Ghidra version is not something you can
    take back, and GHIDRA_INSTALL_DIR has been observed naming a different
    install than the one running."""
    running = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    monkeypatch.setattr(upl, "running_ghidra_dir", lambda: running)

    assert upl.resolve_ghidra_dir(None) == (running, "running Ghidra process")


def test_the_env_var_is_used_only_when_it_names_a_real_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(upl, "running_ghidra_dir", lambda: None)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "absent"))
    monkeypatch.setattr(upl.Path, "glob", lambda self, pattern: iter(()))

    resolved, source = upl.resolve_ghidra_dir(None)

    assert source == "unresolved"
    assert resolved == Path(str(tmp_path / "absent"))


def test_a_valid_env_var_is_taken_before_scanning_the_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(upl, "running_ghidra_dir", lambda: None)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))

    assert upl.resolve_ghidra_dir(None) == (Path(str(tmp_path)), "$GHIDRA_INSTALL_DIR")


def test_the_filesystem_scan_takes_the_last_install_by_name(tmp_path, monkeypatch):
    monkeypatch.setattr(upl, "running_ghidra_dir", lambda: None)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    old = _fake_ghidra(tmp_path / "ghidra_11.0_PUBLIC")
    new = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")
    bare = tmp_path / "ghidra_13.0_PUBLIC"      # no support/ -- not a candidate
    bare.mkdir()

    monkeypatch.setattr(
        upl.Path, "glob",
        lambda self, pattern: iter([old, new, bare]) if pattern == "ghidra_*_PUBLIC" else iter(()))

    assert upl.resolve_ghidra_dir(None) == (new, "filesystem scan")


def test_the_running_install_probe_is_windows_only(monkeypatch):
    monkeypatch.setattr(upl.sys, "platform", "linux")

    assert upl.running_ghidra_dir() is None


def test_the_running_install_comes_from_the_class_loader_line(tmp_path, monkeypatch):
    """Keyed on `ghidra.GhidraClassLoader`, never a bare `*ghidra*` glob: this
    repo's own VSCode Java language server carries the workspace path
    `ghidra-mcp` on its command line and would match one."""
    real = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")
    listing = (
        f'"C:\\jdk\\java.exe" -cp X;{real}\\support\\lib -Dfoo '
        'com.example.LanguageServer C:\\src\\ghidra-mcp\n'
        f'"C:\\jdk\\java.exe" -cp {real}\\Ghidra\\lib;q ghidra.GhidraClassLoader '
        'ghidra.GhidraRun\n'
    )

    class Done:
        stdout, stderr, returncode = listing, "", 0

    monkeypatch.setattr(upl.sys, "platform", "win32")
    monkeypatch.setattr(upl.subprocess, "run", lambda cmd, **kw: Done())

    assert upl.running_ghidra_dir() == Path(str(real))


def test_a_class_loader_line_naming_a_dir_without_support_is_rejected(tmp_path, monkeypatch):
    class Done:
        stdout = ('"java.exe" -cp C:\\nope\\ghidra_12.1.2_PUBLIC\\lib;q '
                  'ghidra.GhidraClassLoader ghidra.GhidraRun\n')
        stderr, returncode = "", 0

    monkeypatch.setattr(upl.sys, "platform", "win32")
    monkeypatch.setattr(upl.subprocess, "run", lambda cmd, **kw: Done())

    assert upl.running_ghidra_dir() is None


def test_the_running_install_probe_survives_powershell_being_unavailable(monkeypatch):
    monkeypatch.setattr(upl.sys, "platform", "win32")

    def missing(cmd, **kw):
        raise FileNotFoundError("powershell.exe")

    monkeypatch.setattr(upl.subprocess, "run", missing)

    assert upl.running_ghidra_dir() is None


def test_the_running_install_probe_survives_a_timeout(monkeypatch):
    monkeypatch.setattr(upl.sys, "platform", "win32")

    def slow(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 60)

    monkeypatch.setattr(upl.subprocess, "run", slow)

    assert upl.running_ghidra_dir() is None


# --------------------------------------------------------------------------- #
# Credential source discovery
# --------------------------------------------------------------------------- #


#: The exact label credential_sources() gives the registry provider. Matched
#: exactly, not as a substring -- pytest bakes the test's own name into
#: tmp_path, so a substring check hits any test whose name contains the word.
REGISTRY_LABEL = "registry:HKCU\\Environment"


def test_the_registry_is_consulted_only_on_windows(tmp_path, monkeypatch):
    """A variable set after this process started is absent from os.environ; the
    user-scope registry value is current."""
    monkeypatch.setattr(upl.sys, "platform", "linux")
    labels = [label for label, _ in upl.credential_sources(tmp_path)]

    assert REGISTRY_LABEL not in labels
    assert labels[0] == "env"
    assert len(labels) == 3, "env, <ghidra_dir>/.env, <cwd>/.env"


def test_an_unreadable_registry_is_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(upl.sys, "platform", "win32")
    fake = type(sys)("winreg")
    fake.HKEY_CURRENT_USER = 0

    def open_key(*a, **k):
        raise OSError("access denied")

    fake.OpenKey = open_key
    monkeypatch.setitem(sys.modules, "winreg", fake)

    labels = [label for label, _ in upl.credential_sources(tmp_path)]

    assert REGISTRY_LABEL not in labels
    assert labels[0] == "env", "the other providers still work"


def test_registry_values_are_offered_as_a_credential_source(tmp_path, monkeypatch):
    monkeypatch.setattr(upl.sys, "platform", "win32")
    stored = {"GHIDRA_SERVER_PASSWORD": "from-registry"}

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    fake = type(sys)("winreg")
    fake.HKEY_CURRENT_USER = 0
    fake.OpenKey = lambda *a, **k: _Key()

    def query(key, name):
        if name not in stored:
            raise FileNotFoundError(name)
        return stored[name], 1

    fake.QueryValueEx = query
    monkeypatch.setitem(sys.modules, "winreg", fake)

    sources = dict(upl.credential_sources(tmp_path))

    assert sources[REGISTRY_LABEL] == {"GHIDRA_SERVER_PASSWORD": "from-registry"}


def test_no_password_anywhere_returns_unset_rather_than_an_empty_string(tmp_path, monkeypatch):
    """An empty password is a credential the server would reject; "unset" is
    what makes main() refuse instead of attempting an auth that cannot work."""
    monkeypatch.setattr(upl, "credential_sources",
                        lambda d: [("env", {"UNRELATED": "x"}), ("cwd/.env", {})])

    assert upl.resolve_password(tmp_path) == (None, "unset")


def test_the_username_falls_back_to_the_os_account(tmp_path, monkeypatch):
    monkeypatch.setattr(upl, "credential_sources", lambda d: [("env", {})])
    monkeypatch.setenv("USERNAME", "someone")

    assert upl.resolve_user(tmp_path) == "someone"


def test_the_username_has_a_last_resort_default(tmp_path, monkeypatch):
    monkeypatch.setattr(upl, "credential_sources", lambda d: [("env", {})])
    monkeypatch.delenv("USERNAME", raising=False)

    assert upl.resolve_user(tmp_path) == "benam"


def test_the_repo_alone_can_come_from_the_live_instance(tmp_path, monkeypatch):
    """`--server` without `--repo` must still consult /project/info rather than
    short-circuiting on the partial flag pair."""
    monkeypatch.setattr(upl, "mcp_get", lambda base, endpoint, timeout=60.0, **p:
                        {"project": "diablo2"})

    server, repo, origin = upl.resolve_server_and_repo("http://h", tmp_path, "h:13100", None)

    assert (server, repo) == ("h:13100", "diablo2")
    assert "live Ghidra" in origin


def test_the_server_falls_back_to_the_dotenv_host_and_port(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "GHIDRA_SERVER_HOST=ghidra-host\nGHIDRA_SERVER_PORT=13100\n", encoding="utf-8")
    monkeypatch.setattr(upl, "mcp_get", lambda *a, **k: {"project": "diablo2"})

    server, repo, origin = upl.resolve_server_and_repo("http://h", tmp_path, None, None)

    assert (server, repo) == ("ghidra-host:13100", "diablo2")
    assert ".env" in origin
