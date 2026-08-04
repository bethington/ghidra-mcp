"""Build a BSim reference index from labelled binaries.

The identification lane needs an index of binaries whose names we TRUST -- built
from source with their own PDB, or recovered from a published PDB. This script
is the repeatable version of what Phase 0 did by hand:

    for each reference binary:
        import + analyze headless   (PDB auto-applies when it sits beside the DLL)
        generate BSim signatures
        commit them to the index

BACKENDS: `--index` takes either an H2 file path or a full BSim URL.

    C:/bsim/refindex                              -> H2 file (default, zero-ops)
    postgresql://ben@10.0.10.30:5432/bsim_ref     -> shared Postgres

H2 remains the DEFAULT because a reference index is written rarely and read by
one sweep at a time, and a single file you can copy, diff or delete is easier to
reason about. Postgres is the right choice once several machines or several
concurrent sweeps need the same index.

Postgres needs SSL: Ghidra's BSim client hard-codes `sslmode=require` (plus its
own `ghidra.net.DefaultSSLSocketFactory`), so a server without SSL is rejected
outright with "The server does not support SSL". The 10.0.10.30 container was
configured for this on 2026-08-03 -- self-signed cert in PGDATA, `ssl=on` via
ALTER SYSTEM. Note `sslmode=require` ENCRYPTS BUT DOES NOT VERIFY, so a
self-signed certificate is sufficient and no CA distribution is needed.

Postgres also PROMPTS for a password on every `bsim` invocation, which makes
unattended runs awkward; pipe it on stdin, or stay on H2 for local work.

USAGE

    # one binary (its .pdb must sit beside it to get names)
    python scripts/bsim/build_reference_index.py \
        --index C:/bsim/refindex --add F:/refs/libcrypto-1_1.dll

    # several, into the same index
    python scripts/bsim/build_reference_index.py --index C:/bsim/refindex \
        --add F:/refs/BH.dll --add F:/refs/ddraw.dll

    # what is in there now
    python scripts/bsim/build_reference_index.py --index C:/bsim/refindex --list

A binary already present in the index is SKIPPED unless --force: BSim keys
executables by md5, and committing the same one twice is how an index grows
duplicate functions that then tie with each other and abstain forever.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

TEMPLATE = "medium_32"

#: Roots to scan when the environment does not name a USABLE install.
_SEARCH_ROOTS = ("F:\\", "C:\\", "D:\\", os.path.expanduser("~"))


def find_ghidra_home(explicit: str = "") -> str:
    """Resolve a Ghidra install, VERIFYING it rather than trusting a name.

    `GHIDRA_INSTALL_DIR` is stale on at least one box in this project -- it
    names a version that is not installed -- and `ghidra_health.py` already
    carries the same lesson. An unchecked env var here fails deep inside a
    subprocess call with a confusing error, so check for the actual tool.
    """
    candidates = [explicit, os.environ.get("GHIDRA_INSTALL_DIR", "")]
    for candidate in candidates:
        if candidate and os.path.exists(os.path.join(candidate, "support", "bsim.bat")):
            return candidate

    found = []
    for root in _SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for entry in entries:
            if entry.lower().startswith("ghidra_"):
                path = os.path.join(root, entry)
                if os.path.exists(os.path.join(path, "support", "bsim.bat")):
                    found.append(path)
    if not found:
        raise SystemExit(
            "no Ghidra install found (looked at $GHIDRA_INSTALL_DIR"
            f"={os.environ.get('GHIDRA_INSTALL_DIR', '')!r} and {list(_SEARCH_ROOTS)}).\n"
            "Pass --ghidra-home <dir>.")

    # Newest version wins: sort on the numeric version, not the string, so
    # ghidra_12.1.2 beats ghidra_9.x and ghidra_12.1 alike.
    def version_key(path):
        nums = re.findall(r"\d+", os.path.basename(path))
        return [int(n) for n in nums]

    best = max(found, key=version_key)
    if len(found) > 1:
        print(f"note: several Ghidra installs found, using {best}")
    return best


GHIDRA_HOME = ""


def ghidra_tool(name: str) -> str:
    path = os.path.join(GHIDRA_HOME, "support", name)
    if not os.path.exists(path):
        raise SystemExit(f"not found: {path}")
    return path


#: Password fed to `bsim` on stdin for remote backends. Set from an ENV VAR,
#: never a command-line flag: argv is visible to every other process on the box.
BSIM_PASSWORD = None


def run(cmd: list, what: str, timeout: int = 3600) -> str:
    """Run a Ghidra helper, loudly.

    `analyzeHeadless` EXITS 0 WHEN A SCRIPT THROWS, so a return code is not
    evidence of anything. Callers must verify the artifact; this function's job
    is only to make the failure visible rather than silent.

    Remote BSim backends prompt for a password on EVERY invocation, and the
    prompt reads stdin -- which a subprocess does not inherit usefully, so a
    shell-level pipe reaches the first child and nothing after it. Feed each
    child its own copy instead.
    """
    print(f"  $ {what}", flush=True)
    stdin_text = None
    if BSIM_PASSWORD is not None and os.path.basename(cmd[0]).startswith("bsim"):
        stdin_text = BSIM_PASSWORD + "\n"
    proc = subprocess.run(cmd, capture_output=True, text=True, input=stdin_text,
                          timeout=timeout, errors="replace")
    out = (proc.stdout or "") + (proc.stderr or "")
    for line in out.splitlines():
        # Anchored deliberately. A bare `Exception` also matches the ANALYZER
        # named "Windows x86 PE Exception Handling" in every single run, and a
        # failure channel that cries wolf every time is one you stop reading.
        if re.search(r"SCRIPT ERROR|^ERROR |\bERROR\s|Exception:|FAILED|"
                     r"^\s*java\.[a-z.]+Exception", line):
            print(f"    ! {line.strip()[:200]}", flush=True)
    if proc.returncode != 0:
        print(f"    ! exit {proc.returncode}", flush=True)
    return out


#: BSim URL schemes the `bsim` CLI understands. Anything else is a file path.
_URL_SCHEMES = ("postgresql://", "elastic://", "https://", "file:/")


def is_url(index: str) -> bool:
    return index.startswith(_URL_SCHEMES)


def bsim_url(index: str) -> str:
    """`--index` -> a BSim URL. Passes real URLs through, wraps paths as file:/.

    Kept in ONE place because every subcommand needs the same spelling, and an
    H2 path that reaches the CLI unwrapped fails with an unhelpful error.
    """
    if is_url(index):
        return index
    return "file:/" + index.replace(os.sep, "/")


def md5(path: str) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def index_exists(index: str) -> bool:
    """Does this index already hold a BSim schema?

    For H2 that is a file test. For a remote backend there is nothing on the
    local disk to look at, so ask the server -- `getmetadata` succeeds only
    against an initialised BSim database, which is exactly the question.
    """
    if not is_url(index):
        return os.path.exists(index + ".mv.db")
    out = run([ghidra_tool("bsim.bat"), "getmetadata", bsim_url(index)],
              "bsim getmetadata (probe)", timeout=300)
    return "BSim metadata" in out


def create_index(index: str, name: str) -> None:
    if not is_url(index):
        os.makedirs(os.path.dirname(os.path.abspath(index)) or ".", exist_ok=True)
    print(f"creating index {index} ({TEMPLATE})")
    run([ghidra_tool("bsim.bat"), "createdatabase",
         bsim_url(index), TEMPLATE, "--name", name],
        "bsim createdatabase")
    # Verify the artifact rather than the exit code -- these tools report
    # success far too readily (see `run`).
    if not index_exists(index):
        raise SystemExit(
            f"index was not created at {index}"
            + (".mv.db" if not is_url(index) else
               " (a postgresql:// backend needs SSL enabled server-side and "
               "will prompt for a password)"))


def listed_md5s(index: str) -> set:
    out = run([ghidra_tool("bsim.bat"), "listexes",
               bsim_url(index), "--includelibs"],
              "bsim listexes", timeout=300)
    return set(re.findall(r"^([0-9a-f]{32})\s", out, re.M))


def add_binary(index: str, binary: str, project_dir: str, force: bool) -> bool:
    """Import, analyze and sign one reference binary into the index."""
    binary = os.path.abspath(binary)
    if not os.path.exists(binary):
        print(f"SKIP (missing): {binary}")
        return False

    digest = md5(binary)
    if not force and digest in listed_md5s(index):
        print(f"SKIP (already indexed, md5 {digest[:8]}): {os.path.basename(binary)}")
        return False

    pdb = os.path.splitext(binary)[0] + ".pdb"
    print(f"\n== {os.path.basename(binary)}  md5 {digest[:8]}"
          f"{'  +PDB' if os.path.exists(pdb) else '  (NO PDB - names will be weak)'}")

    # A per-binary project: a shared one accumulates state across runs and makes
    # a re-run non-reproducible.
    project = f"ref_{digest[:8]}"
    run([ghidra_tool("analyzeHeadless.bat"), project_dir, project,
         "-import", binary, "-log", os.path.join(project_dir, project + ".log")],
        f"import+analyze {os.path.basename(binary)}")

    out = run([ghidra_tool("bsim.bat"), "generatesigs",
               f"ghidra:/{project_dir.replace(os.sep, '/')}/{project}",
               "--bsim", bsim_url(index)],
              "bsim generatesigs")
    if "Writing signatures" not in out:
        print("    ! no signatures were written -- check the log above")
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index", required=True,
                    help="H2 index path WITHOUT the .mv.db extension")
    ap.add_argument("--add", action="append", default=[], metavar="DLL",
                    help="reference binary to index (repeatable); put its .pdb beside it")
    ap.add_argument("--name", default="bsim_reference_index")
    ap.add_argument("--project-dir", default=None,
                    help="where to put throwaway Ghidra projects (default: temp)")
    ap.add_argument("--force", action="store_true",
                    help="re-index a binary already present (see docstring)")
    ap.add_argument("--list", action="store_true", help="list indexed executables and exit")
    ap.add_argument("--password-env", default="BSIM_PASSWORD", metavar="VAR",
                    help="env var holding the DB password for remote backends "
                         "(default BSIM_PASSWORD). Deliberately an env var and "
                         "not a flag -- argv is world-readable.")
    ap.add_argument("--ghidra-home", default="",
                    help="Ghidra install dir (default: $GHIDRA_INSTALL_DIR if it "
                         "actually exists, else the newest one found on disk)")
    args = ap.parse_args()

    global GHIDRA_HOME, BSIM_PASSWORD                    # noqa: PLW0603
    GHIDRA_HOME = find_ghidra_home(args.ghidra_home)

    if is_url(args.index):
        BSIM_PASSWORD = os.environ.get(args.password_env)
        if BSIM_PASSWORD is None:
            print(f"note: ${args.password_env} is unset; `bsim` will prompt "
                  f"interactively for each call", file=sys.stderr)

    # A URL must survive verbatim; abspath would turn postgresql://host/db into
    # a nonsense path relative to the cwd.
    index = args.index if is_url(args.index) else os.path.abspath(args.index)

    if args.list:
        if not index_exists(index):
            print(f"no BSim index at {index}"
                  + ("" if is_url(index) else ".mv.db"))
            return 1
        print(run([ghidra_tool("bsim.bat"), "listexes",
                   bsim_url(index), "--includelibs"],
                  "bsim listexes", timeout=300))
        return 0

    if not args.add:
        ap.error("nothing to do: pass --add <binary> or --list")

    if not index_exists(index):
        create_index(index, args.name)
    else:
        print(f"using existing index {index}.mv.db")

    owned_tmp = args.project_dir is None
    project_dir = args.project_dir or tempfile.mkdtemp(prefix="bsim_ref_")
    added = 0
    try:
        for binary in args.add:
            if add_binary(index, binary, project_dir, args.force):
                added += 1
    finally:
        if owned_tmp:
            shutil.rmtree(project_dir, ignore_errors=True)

    where = index if is_url(index) else index + ".mv.db"
    print(f"\nindexed {added} of {len(args.add)} binaries into {where}")
    print("verify with --list, then query with scripts/bsim/Analyze_BSimIdentifyDump.java")
    return 0


if __name__ == "__main__":
    sys.exit(main())
