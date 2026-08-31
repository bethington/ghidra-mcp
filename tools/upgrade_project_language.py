#!/usr/bin/env python3
"""Upgrade every Program in a shared Ghidra project to the running Ghidra's SLEIGH language version.

WHY THIS EXISTS
---------------
Ghidra records the SLEIGH language version a Program was built against. When the
installed Ghidra ships a newer revision of that language (e.g. x86:LE:32:default
4.6 -> 4.7), the old Program still opens **read-only**; a read-*write* open needs
an upgrade, and an upgrade needs an **exclusive checkout**.

On a shared (server) project those two conditions compound into one symptom:
every binary opens read-only and edits are silently discarded. The MCP server
cannot fix it on its own -- every GUI-side open passes ``okToUpgrade=false``
(``FrontEndProgramProvider``, ``ProgramScriptService``), so it can only ever
report the failure, never resolve it.

``analyzeHeadless`` *can*: ``HeadlessAnalyzer.processFile`` opens with
``getDomainObject(this, /*okToUpgrade*/ true, false, ...)``. But it takes an
exclusive checkout only when ``-commit`` is supplied -- ``domFile.checkout(options.commit, ...)``
-- so **without ``-commit`` the upgrade always fails**. That single coupling is
the whole reason this wrapper exists rather than a bare command line.

SAFETY
------
Only *minor* language changes are handled without a translator. Ghidra's own
``LanguageVersionException.check`` returns an upgradable exception with a null
``languageUpgradeTranslator`` for a minor bump, meaning no re-disassembly and no
re-analysis. ``-noanalysis`` is passed unconditionally so auto-analysis can never
rewrite curated documentation. A *major* language change is a different animal
and this tool reports it rather than performing it.

NOT IDEMPOTENT -- RUN IT ONCE
-----------------------------
Every ``--apply`` commits a NEW server version for every file it processes,
whether or not that file needed upgrading. ``HeadlessAnalyzer`` does::

    if (domFile.canSave()) { domFile.save(...); }
    if (options.commit)    { commitProgram(domFile); }

``canSave()`` is true for any checked-out file regardless of changes, so the
save and the commit are unconditional. Ghidra also logs nothing when it performs
a language upgrade, so the log CANNOT distinguish "upgraded" from "re-committed
unchanged" -- measured 2026-08-10, a second full pass moved all 517 files up
another version having upgraded none of them. Read the ``committed`` counter as
"files this run wrote a version for", never as "files that needed it".

Consequence: run this once after a Ghidra upgrade. Do not re-run it as a
verification step -- a whole-project ``--apply`` refuses if another ran within
24h unless ``--force`` is given.

``--verify`` is the verification step: it writes no versions. It does, however,
LEAK an exclusive checkout per probed program, because ``open_program`` registers
a ``DomainObject`` consumer that nothing releases -- so keep ``--verify-sample``
small, and clear the leftovers with a Ghidra restart followed by
``--release-checkouts``.

USAGE
-----
    # dry run (default) -- inventory + plan, writes nothing, needs no password
    python tools/upgrade_project_language.py

    # validate credentials and enumeration against the server, still writes nothing
    python tools/upgrade_project_language.py --preflight

    # do it
    python tools/upgrade_project_language.py --apply
    python tools/upgrade_project_language.py --apply --folder /Vanilla/1.01

Password comes from the environment (never argv, which is world-readable):
``GHIDRA_SERVER_PASSWORD`` then ``GHIDRA_PASS``. On Windows the user-scope
registry value is consulted too, so a variable set after this shell started is
still visible.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path

DEFAULT_MCP = "http://127.0.0.1:8089"

# No literal server host or repository name lives here. This is a public repo
# and a private destination baked into source is a leak that survives its own
# removal (see tests/unit/test_no_default_data_egress.py, which enforces it).
# Both are discovered at runtime from the Ghidra instance we are already
# talking to -- which is also what makes this tool work against any project
# rather than only the one it was written for.

# Ghidra emits exactly these, per file, on the paths we care about. Every line
# carries a trailing " (ComponentName)" that must not become part of the path.
# Paths are matched non-greedily up to a literal delimiter, never with \S+:
# "Diablo II.exe" has a SPACE, and \S+ makes the whole line fail to match, so a
# skipped file silently disappears from the tally instead of being reported.
_TAIL = r"(?:\s+\([A-Za-z]\w*\))?\s*$"
RE_PROCESSING = re.compile(r"REPORT: Processing (?:read-only )?project file: (.+?)" + _TAIL)
RE_SAVED = re.compile(r"REPORT: Save succeeded for processed file: (.+?)" + _TAIL)
RE_OLDER = re.compile(r"(/.+?): this file was created with an older version of Ghidra")
RE_NEWER = re.compile(r"(/.+?): this file was created with a newer version of Ghidra")
RE_NO_EXCLUSIVE = re.compile(
    r"Skipped processing for (.+?) -- failed to get exclusive file checkout"
)
RE_NON_EXCLUSIVE = re.compile(
    r"Skipped processing for (.+?) -- file is checked-out non-exclusive"
)
RE_READONLY_REPO = re.compile(r"Skipped processing for (.+?) within read-only repository")
RE_COMMITTED = re.compile(r"REPORT: Committed file changes to repository: (.+?)" + _TAIL)
RE_SAVE_ERROR = re.compile(r"REPORT: Error trying to save changes to file: (.+?)" + _TAIL)
RE_UNAUTHORIZED = re.compile(r"Server access denied|NotConnectedException: Unauthorized")


# --------------------------------------------------------------------------- #
# MCP inventory (read-only, no server password required)
# --------------------------------------------------------------------------- #


def mcp_get(base: str, endpoint: str, timeout: float = 60.0, **params) -> object:
    """GET an MCP endpoint and unwrap the ``{"result": "<json string>"}`` envelope.

    The endpoint parameter is NOT called ``path``: several MCP endpoints take a
    query parameter of that name, and ``mcp_get(base, "open_program", path=...)``
    then dies with "got multiple values for argument 'path'".
    """
    url = f"{base.rstrip('/')}/{endpoint.lstrip('/')}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as response:
        raw = response.read().decode("utf-8", "replace")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    # Most endpoints double-encode: {"result": "{...}"}
    if isinstance(payload, dict) and "result" in payload:
        inner = payload["result"]
        if isinstance(inner, str):
            try:
                return json.loads(inner)
            except json.JSONDecodeError:
                return inner
        return inner
    return payload


def mcp_post(base: str, endpoint: str, timeout: float = 180.0, **params) -> object:
    """POST an MCP endpoint with a JSON body.

    The version-control routes read their arguments with ``parseJsonParams``, so
    they need a JSON body -- a query string reaches them as
    ``'path' parameter required``.
    """
    url = f"{base.rstrip('/')}/{endpoint.lstrip('/')}"
    body = json.dumps(params).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", "replace")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if isinstance(payload, dict) and "result" in payload:
        inner = payload["result"]
        if isinstance(inner, str):
            try:
                return json.loads(inner)
            except json.JSONDecodeError:
                return inner
        return inner
    return payload


def walk_project(base: str, root: str = "/") -> list[dict]:
    """Recursively enumerate Program files.

    ``/list_project_files`` is FOLDER-SCOPED -- reading ``/`` returns an empty
    ``files`` list and looks like an empty project. The walk must recurse.
    """
    found: list[dict] = []
    queue = [root]
    seen: set[str] = set()
    while queue:
        folder = queue.pop(0)
        if folder in seen:
            continue
        seen.add(folder)
        try:
            data = mcp_get(base, "list_project_files", folder=folder)
        except Exception as exc:  # noqa: BLE001 - report, never abort the walk
            print(f"  [WARN] cannot list {folder}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            continue
        for entry in data.get("files") or []:
            if entry.get("content_type") == "Program":
                found.append(entry)
        prefix = "" if folder == "/" else folder.rstrip("/")
        for sub in data.get("folders") or []:
            queue.append(f"{prefix}/{sub}")
    return found


def checkout_census(base: str) -> dict[str, dict]:
    """Project-wide checkout state, keyed by path.

    Deliberately unscoped: the folder-scoped form of this endpoint has been
    observed returning an empty list for a folder that demonstrably contains a
    checked-out file (``/Vanilla/1.01`` reported 0 while ``1.01/Game.exe`` was
    checked out in the project-wide listing). Trust only the unscoped call.
    """
    data = mcp_get(base, "server/checkouts", timeout=180.0)
    out: dict[str, dict] = {}
    if isinstance(data, dict):
        for entry in data.get("checkouts") or []:
            path = entry.get("path")
            if path:
                out[path] = entry
    return out


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


CRED_NAMES = ("GHIDRA_SERVER_PASSWORD", "GHIDRA_PASS")


def read_dotenv(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE .env file. Missing file yields an empty mapping."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if value:
            values[key.strip()] = value
    return values


def credential_sources(ghidra_dir: Path) -> list[tuple[str, dict[str, str]]]:
    """Ordered credential providers.

    ``<ghidra_dir>/.env`` is the project's canonical home for Ghidra Share
    auto-login -- ``GhidraMCPAuthInitializer`` reads it at startup to suppress the
    password dialog -- so this tool reads the same file rather than inventing a
    second place for the same secret.
    """
    sources: list[tuple[str, dict[str, str]]] = [("env", dict(os.environ))]
    sources.append((f"{ghidra_dir / '.env'}", read_dotenv(ghidra_dir / ".env")))
    sources.append((f"{Path.cwd() / '.env'}", read_dotenv(Path.cwd() / ".env")))
    if sys.platform == "win32":
        # A variable set after this process started is absent from os.environ; the
        # user-scope registry value is current.
        try:
            import winreg  # noqa: PLC0415 - platform-conditional

            reg: dict[str, str] = {}
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                for name in CRED_NAMES + ("GHIDRA_SERVER_USER",):
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                    except FileNotFoundError:
                        continue
                    if value:
                        reg[name] = str(value)
            if reg:
                sources.append(("registry:HKCU\\Environment", reg))
        except OSError:
            pass
    return sources


def resolve_password(ghidra_dir: Path) -> tuple[str | None, str]:
    """Return (password, source-label). The value never appears in a message.

    Name outranks source, deliberately. ``GHIDRA_PASS`` is a general-purpose
    variable that exists in this environment holding a credential the *Ghidra
    Server* rejects; ``GHIDRA_SERVER_PASSWORD`` is the specific one. Iterating
    sources first would let the ambient wrong value beat the correct value in
    ``.env`` and present as an auth failure with no obvious cause.
    """
    sources = credential_sources(ghidra_dir)
    for name in CRED_NAMES:
        for label, mapping in sources:
            value = mapping.get(name)
            if value:
                return value, f"{label}:{name}"
    return None, "unset"


def resolve_server_and_repo(
    mcp_base: str, ghidra_dir: Path, server: str | None, repo: str | None
) -> tuple[str | None, str | None, str]:
    """Discover the Ghidra Server host:port and repository name.

    Order: explicit flags, then the live Ghidra instance (``/project/info``
    reports ``server_info`` and ``project`` for a shared project), then
    ``<ghidra_dir>/.env``. Returns (server, repo, source-label); either element
    may be None, and the caller must refuse rather than guess.
    """
    sources: list[str] = []
    if server and repo:
        return server, repo, "--server/--repo"

    if not (server and repo):
        try:
            info = mcp_get(mcp_base, "project/info", timeout=60.0)
        except Exception:  # noqa: BLE001 - fall through to .env
            info = None
        if isinstance(info, dict):
            if not server and info.get("server_info"):
                server = str(info["server_info"])
                sources.append("live Ghidra /project/info")
            if not repo and info.get("project"):
                repo = str(info["project"])
                if "live Ghidra /project/info" not in sources:
                    sources.append("live Ghidra /project/info")

    if not server:
        env = read_dotenv(ghidra_dir / ".env")
        host, port = env.get("GHIDRA_SERVER_HOST"), env.get("GHIDRA_SERVER_PORT")
        if host and port:
            server = f"{host}:{port}"
            sources.append(f"{ghidra_dir / '.env'}")

    return server, repo, ", ".join(sources) or "unresolved"


def resolve_user(ghidra_dir: Path) -> str:
    """Name outranks source, for the same reason as resolve_password."""
    sources = credential_sources(ghidra_dir)
    for name in ("GHIDRA_SERVER_USER", "GHIDRA_USER"):
        for _label, mapping in sources:
            value = mapping.get(name)
            if value:
                return value
    return os.environ.get("USERNAME") or "benam"


# --------------------------------------------------------------------------- #
# Headless invocation
# --------------------------------------------------------------------------- #


@dataclass
class FolderResult:
    folder: str
    returncode: int | None = None
    seconds: float = 0.0
    processed: list[str] = field(default_factory=list)
    saved: list[str] = field(default_factory=list)
    committed: list[str] = field(default_factory=list)
    needs_upgrade_blocked: list[str] = field(default_factory=list)
    newer_than_ghidra: list[str] = field(default_factory=list)
    no_exclusive_checkout: list[str] = field(default_factory=list)
    save_errors: list[str] = field(default_factory=list)
    unauthorized: bool = False
    log_path: str | None = None


def running_ghidra_dir() -> Path | None:
    """Installation root of the currently running Ghidra, if any.

    ``GHIDRA_INSTALL_DIR`` is unreliable here -- it has been observed pointing at
    an install that is not the one running, and an upgrade written by the wrong
    Ghidra version is not something you can take back. The running process is the
    authority, because it is the Ghidra whose language revision we are matching.

    Keys on ``ghidra.GhidraClassLoader``, never a bare ``*ghidra*`` command-line
    glob: this repo's own VSCode Java language server carries the workspace path
    ``ghidra-mcp`` and would match.
    """
    if sys.platform != "win32":
        return None
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process -Filter \"Name like '%java%'\" "
                "| Select-Object -ExpandProperty CommandLine",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (proc.stdout or "").splitlines():
        if "ghidra.GhidraClassLoader" not in line:
            continue
        for match in re.finditer(r"([A-Za-z]:\\[^\";]*?ghidra_[^\\\";]+)\\", line):
            candidate = Path(match.group(1))
            if (candidate / "support").is_dir():
                return candidate
    return None


def resolve_ghidra_dir(explicit: str | None) -> tuple[Path, str]:
    """Pick the Ghidra install, preferring the one actually running."""
    if explicit:
        return Path(explicit), "--ghidra-dir"
    running = running_ghidra_dir()
    if running:
        return running, "running Ghidra process"
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and Path(env).is_dir():
        return Path(env), "$GHIDRA_INSTALL_DIR"
    candidates = sorted(
        (p for root in ("F:/", "C:/") for p in Path(root).glob("ghidra_*_PUBLIC") if (p / "support").is_dir()),
        key=lambda p: p.name,
    )
    if candidates:
        return candidates[-1], "filesystem scan"
    return Path(env or "ghidra"), "unresolved"


RE_LANG_MISMATCH = re.compile(r"(?:Minor|Major) language change ([\d.]+) -> ([\d.]+)")


def undo_checkout(base: str, path: str) -> tuple[bool, str]:
    """Release a checkout. Returns (released, detail) -- never raises."""
    try:
        mcp_post(base, "close_program", name=path, save="false")
    except Exception:  # noqa: BLE001, S110 - close is best effort
        pass
    try:
        out = mcp_post(base, "server/version_control/undo_checkout", path=path)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    if isinstance(out, dict) and out.get("status") == "checkout_undone":
        return True, "released"
    return False, json.dumps(out) if not isinstance(out, str) else out


def probe_language_state(base: str, path: str, leaked: list[str] | None = None) -> tuple[str, str]:
    """Is this program readable READ-WRITE? Returns (state, detail).

    The only reliable staleness oracle available. A stale program opens
    read-ONLY perfectly happily, so the probe must force a read-WRITE open --
    which needs an exclusive checkout.

    ``open_program`` goes through ``FrontEndProgramProvider``, which passes
    ``okToUpgrade=false``, so a stale program surfaces as
    ``Minor language change 4.6 -> 4.7`` instead of being silently upgraded.

    LEAKS A CHECKOUT, unavoidably. ``open_program`` registers the CodeBrowser
    tool as a ``DomainObject`` consumer and nothing releases it, so afterwards
    ``undo_checkout`` fails with "<name> is in use" and keeps failing until
    Ghidra restarts -- ``close_program`` reports ``closed_count: 0,
    released_cache: false`` and cannot help. Measured 2026-08-10: a 152-program
    probe left 140 stray exclusive checkouts. Anything this function could not
    release is appended to ``leaked`` so the caller can report it LOUDLY rather
    than leave the project quietly worse than it found it.
    """
    took_checkout = False
    try:
        pre = mcp_get(base, "server/checkouts", timeout=180.0)
        already = isinstance(pre, dict) and any(
            c.get("path") == path for c in (pre.get("checkouts") or [])
        )
        if not already:
            out = mcp_post(base, "server/version_control/checkout", path=path, exclusive="true")
            if not (isinstance(out, dict) and out.get("status") == "checked_out"):
                return "unknown", f"checkout failed: {out}"
            took_checkout = True

        opened = mcp_get(base, "open_program", path=path, auto_analyze="false")
        detail = json.dumps(opened) if not isinstance(opened, str) else opened
        if isinstance(opened, dict) and opened.get("success"):
            state = "current"
        elif RE_LANG_MISMATCH.search(detail):
            state = "stale"
        else:
            state = "unknown"
        return state, detail
    except Exception as exc:  # noqa: BLE001
        return "unknown", str(exc)
    finally:
        if took_checkout:
            released, _why = undo_checkout(base, path)
            if not released and leaked is not None:
                leaked.append(path)


def analyze_headless_cmd(ghidra_dir: Path) -> Path:
    name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
    path = ghidra_dir / "support" / name
    if not path.is_file():
        raise SystemExit(f"analyzeHeadless not found at {path}")
    return path


def run_folder(
    *,
    ghidra_dir: Path,
    server: str,
    repo: str,
    folder: str,
    user: str,
    password: str,
    comment: str,
    apply_changes: bool,
    timeout: float,
    log_dir: Path,
) -> FolderResult:
    url = f"ghidra://{server}/{repo}{folder if folder != '/' else ''}"
    cmd = [
        str(analyze_headless_cmd(ghidra_dir)),
        url,
        "-process",
        "-recursive",
        "-noanalysis",  # never let auto-analysis rewrite curated documentation
        "-connect",
        user,
        "-p",
    ]
    if apply_changes:
        # -commit is not optional: it is what makes the checkout EXCLUSIVE, and
        # only an exclusive checkout permits the language upgrade.
        cmd += ["-commit", comment]
    else:
        cmd += ["-readOnly"]

    result = FolderResult(folder=folder)
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            input=password + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        result.returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or "") if isinstance(exc.stdout, str) else "") + (
            (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        )
        output += f"\n*** TIMEOUT after {timeout}s ***\n"
        result.returncode = None
    result.seconds = time.time() - started

    log_dir.mkdir(parents=True, exist_ok=True)
    safe = folder.strip("/").replace("/", "_") or "root"
    log_path = log_dir / f"{safe}.log"
    log_path.write_text(output, encoding="utf-8", errors="replace")
    result.log_path = str(log_path)

    for line in output.splitlines():
        if RE_UNAUTHORIZED.search(line):
            result.unauthorized = True
        for regex, bucket in (
            (RE_PROCESSING, result.processed),
            (RE_SAVED, result.saved),
            (RE_COMMITTED, result.committed),
            (RE_OLDER, result.needs_upgrade_blocked),
            (RE_NEWER, result.newer_than_ghidra),
            (RE_NO_EXCLUSIVE, result.no_exclusive_checkout),
            (RE_NON_EXCLUSIVE, result.no_exclusive_checkout),
            (RE_READONLY_REPO, result.no_exclusive_checkout),
            (RE_SAVE_ERROR, result.save_errors),
        ):
            match = regex.search(line)
            if match:
                bucket.append(match.group(1))
    return result


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upgrade shared-project Programs to the running Ghidra's language version",
    )
    parser.add_argument("--mcp", default=DEFAULT_MCP, help="MCP HTTP base (default: %(default)s)")
    parser.add_argument(
        "--server", default=None,
        help="Ghidra server host:port. Default: discovered from the live Ghidra instance, "
             "then <ghidra_dir>/.env.",
    )
    parser.add_argument(
        "--repo", default=None,
        help="Repository name. Default: discovered from the live Ghidra instance.",
    )
    parser.add_argument(
        "--ghidra-dir",
        default=None,
        help="Ghidra installation (default: the running Ghidra, then $GHIDRA_INSTALL_DIR)",
    )
    parser.add_argument(
        "--folder",
        action="append",
        default=None,
        help="Project folder to process; repeatable. Default: every folder holding Programs.",
    )
    parser.add_argument("--apply", action="store_true", help="Perform the upgrade (default: dry run)")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Probe whether programs open READ-WRITE. Writes no versions. "
             "Samples --verify-sample per folder.",
    )
    parser.add_argument(
        "--verify-sample",
        type=int,
        default=1,
        help="Programs to probe per folder in --verify (0 = all). Default: %(default)s",
    )
    parser.add_argument(
        "--release-checkouts",
        action="store_true",
        help="Undo exclusive checkouts recorded in --stray-file (created by --verify). "
             "Only releases paths this tool recorded; never an arbitrary checkout.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="An --apply report JSON. With --release-checkouts, anything checked out "
             "that is NOT in its preexisting_checkouts is treated as ours and released. "
             "Catches strays the recorded list missed because the census lags.",
    )
    parser.add_argument(
        "--stray-file",
        default="reports/verify_stray_checkouts.json",
        help="Where --verify records checkouts it could not release. Default: %(default)s",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Override the whole-project re-run guard. Each --apply writes a new "
             "version for EVERY file it touches, upgraded or not.",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run headless read-only to validate credentials and enumeration. Writes nothing.",
    )
    parser.add_argument(
        "--comment",
        default=None,
        help="Check-in comment (default: 'Language upgrade to Ghidra <version>')",
    )
    parser.add_argument(
        "--timeout-per-file",
        type=float,
        default=120.0,
        help="Seconds allowed per file when sizing a folder's timeout (default: %(default)s)",
    )
    parser.add_argument("--min-timeout", type=float, default=600.0, help="Floor for folder timeout")
    parser.add_argument(
        "--report",
        default=None,
        help="Write a JSON report here (default: reports/language_upgrade_<ts>.json)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Refuse (do not truncate) if more than N folders would be processed. 0 = no limit.",
    )
    args = parser.parse_args()

    ghidra_dir, ghidra_source = resolve_ghidra_dir(args.ghidra_dir)
    if not ghidra_dir.is_dir():
        print(f"ERROR: Ghidra install not found: {ghidra_dir} (via {ghidra_source})", file=sys.stderr)
        return 2

    server, repo, origin = resolve_server_and_repo(
        args.mcp, ghidra_dir, args.server, args.repo)
    if not server or not repo:
        print(
            "\nERROR: could not determine the Ghidra Server host:port and repository.\n"
            "       Pass --server host:port --repo NAME, or start Ghidra connected to\n"
            "       the shared project so /project/info can report them.",
            file=sys.stderr,
        )
        return 2
    args.server, args.repo = server, repo

    print("=" * 78)
    print("  Ghidra shared-project language upgrade")
    print(f"  Repository : ghidra://{server}/{repo}  (via {origin})")
    print(f"  Ghidra     : {ghidra_dir}  (via {ghidra_source})")
    mode = "APPLY" if args.apply else ("PREFLIGHT (read-only)" if args.preflight else "DRY RUN")
    print(f"  Mode       : {mode}")
    print("=" * 78)

    # ---- inventory -------------------------------------------------------- #
    print("\n[1/3] Enumerating project files via MCP ...")
    try:
        programs = walk_project(args.mcp)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: MCP inventory failed ({exc}).", file=sys.stderr)
        print("       Is Ghidra running with the MCP plugin on 8089?", file=sys.stderr)
        return 2
    if not programs:
        print("ERROR: no Program files found -- refusing to proceed on an empty inventory.")
        return 2

    # A ghidra:// URL exposes only VERSIONED files. A private (local-only) file is
    # invisible to headless -- it is not "skipped", it is unreachable -- so it must
    # not be counted in the plan as though this pass covers it.
    private = [e for e in programs if not e.get("is_versioned", True)]
    versioned = [e for e in programs if e.get("is_versioned", True)]

    folders: dict[str, list[dict]] = {}
    for entry in versioned:
        parent = entry["path"].rsplit("/", 1)[0] or "/"
        folders.setdefault(parent, []).append(entry)
    print(f"      {len(programs)} Programs across {len({e['path'].rsplit('/', 1)[0] for e in programs})} folders")
    print(f"      {len(versioned)} versioned (reachable), {len(private)} private (NOT reachable via headless)")
    for entry in private:
        print(f"        private: {entry['path']}")

    print("\n[2/3] Reading project-wide checkout state ...")
    try:
        checkouts = checkout_census(args.mcp)
    except Exception as exc:  # noqa: BLE001
        print(f"      [WARN] checkout census failed: {exc}")
        checkouts = {}
    blockers = sorted(p for p in checkouts if p in {e["path"] for e in versioned})
    print(f"      {len(blockers)} Programs already checked out by the GUI project")
    if blockers:
        print("      Headless runs as a SEPARATE project instance and cannot take an")
        print("      exclusive checkout on these -- it will skip them. Check them in")
        print("      (or undo the checkouts) first if they also need upgrading.")
        for path in blockers[:10]:
            print(f"        - {path}")
        if len(blockers) > 10:
            print(f"        ... and {len(blockers) - 10} more")

    if args.folder:
        mangled = [f for f in args.folder if not f.startswith("/") or re.match(r"^/[A-Za-z]:", f)]
        if mangled:
            print(
                "\nERROR: --folder value(s) do not look like project paths: "
                + ", ".join(repr(f) for f in mangled),
                file=sys.stderr,
            )
            print(
                "       Git Bash/MSYS rewrites a leading-slash argument into a Windows\n"
                "       path (/benchmark -> C:/Program Files/Git/benchmark), which would\n"
                "       otherwise match nothing and make this a silent no-op. Run from\n"
                "       PowerShell, or set MSYS2_ARG_CONV_EXCL='*' for this command.",
                file=sys.stderr,
            )
            return 2

    targets = sorted(args.folder) if args.folder else sorted(folders)
    unknown = [f for f in targets if f not in folders]
    if unknown:
        for folder in unknown:
            print(f"      [ERROR] no Programs found in {folder}")
        print(
            "\nERROR: refusing to run -- a requested folder matched nothing. "
            "Processing the remainder would report success for work never attempted.",
            file=sys.stderr,
        )
        return 2
    targets = [f for f in targets if f in folders]

    if args.limit and len(targets) > args.limit:
        print(
            f"\nERROR: {len(targets)} folders exceeds --limit {args.limit}. "
            "Refusing rather than silently truncating.",
            file=sys.stderr,
        )
        return 2

    if not (args.apply or args.preflight or args.verify or args.release_checkouts):
        print("\n[3/3] Plan (dry run -- nothing will be written):")
        for folder in targets:
            blocked = sum(1 for e in folders[folder] if e["path"] in checkouts)
            note = f"  ({blocked} blocked by existing checkout)" if blocked else ""
            print(f"      {folder:40s} {len(folders[folder]):3d} programs{note}")
        print(
            f"\n      Total: {len(versioned)} versioned, {len(blockers)} blocked, "
            f"{len(private)} private (unreachable)"
        )
        print("\n      Re-run with --preflight to validate credentials, then --apply.")
        return 0

    # ---- release leaked checkouts ------------------------------------------ #
    if args.release_checkouts:
        leak_path = Path(args.stray_file)
        if not leak_path.exists():
            print(f"\nNothing to do: {leak_path} does not exist.")
            return 0
        wanted = set(json.loads(leak_path.read_text(encoding="utf-8")))
        # A --baseline report lets this catch strays the recorded list missed.
        # /server/checkouts reads LOCAL project data that lags the server, so a
        # checkout created moments earlier can be absent from the census and
        # therefore never recorded -- measured 2026-08-10: two Game.exe
        # checkouts surfaced only after a Ghidra restart, having been reported
        # as fully released. Anything checked out that is NOT in the baseline's
        # preexisting set is ours by construction.
        if args.baseline:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            preexisting = set(baseline.get("preexisting_checkouts") or [])
            wanted |= set(checkout_census(args.mcp)) - preexisting

        live = checkout_census(args.mcp)
        # Only ever release checkouts this tool recorded creating (or that the
        # baseline proves are not the operator's). Undoing an arbitrary checkout
        # discards whatever local work it was holding.
        todo = sorted(p for p in wanted if p in live)
        print(f"\n[3/3] Releasing {len(todo)} recorded stray checkout(s) ...")
        released, stuck = [], []
        for path in todo:
            ok, why = undo_checkout(args.mcp, path)
            (released if ok else stuck).append(path)
            if not ok:
                print(f"      STUCK {path}: {why[:100]}")
        # Re-poll rather than trusting the per-call results: the census lags, so
        # "released 140, stuck 0" was reported while two checkouts were still
        # live. Silence here is what let that stand.
        after = checkout_census(args.mcp)
        lingering = sorted(p for p in wanted if p in after)
        remaining = sorted((set(wanted) - set(released)) | set(lingering))
        leak_path.write_text(json.dumps(remaining, indent=2), encoding="utf-8")
        print(f"\n      released: {len(released)}   still stuck: {len(stuck)}")
        if lingering:
            print(f"      STILL CHECKED OUT after re-poll: {len(lingering)}")
            for path in lingering[:10]:
                print(f"        {path}")
        if stuck or lingering:
            print("      Restart Ghidra, then run this again -- and re-run once more")
            print("      afterwards, because the checkout census lags the server.")
        return 1 if (stuck or lingering) else 0

    # ---- verify (no writes) ------------------------------------------------ #
    if args.verify:
        print("\n[3/3] Probing read-write openability (no versions written) ...")
        print(
            "      NOTE: probing forces a read-WRITE open, which needs an exclusive\n"
            "      checkout, and open_program leaks a DomainObject consumer so the\n"
            "      checkout cannot be released until Ghidra restarts. Any checkout\n"
            "      left behind is listed at the end. Keep --verify-sample small."
        )
        stale: list[str] = []
        current: list[str] = []
        unknown: list[tuple[str, str]] = []
        leaked: list[str] = []
        for folder in targets:
            entries = folders[folder]
            sample = entries if args.verify_sample <= 0 else entries[: args.verify_sample]
            for entry in sample:
                state, detail = probe_language_state(args.mcp, entry["path"], leaked)
                if state == "current":
                    current.append(entry["path"])
                elif state == "stale":
                    stale.append(entry["path"])
                    print(f"      STALE   {entry['path']}: {detail[:120]}")
                else:
                    unknown.append((entry["path"], detail))
                    print(f"      UNKNOWN {entry['path']}: {detail[:120]}")
        print(
            f"\n      current: {len(current)}   stale: {len(stale)}   unknown: {len(unknown)}"
        )
        if stale:
            print("      -> re-run with --apply (optionally scoped with --folder)")
        if leaked:
            leak_path = Path("reports") / "verify_stray_checkouts.json"
            leak_path.parent.mkdir(parents=True, exist_ok=True)
            existing = []
            if leak_path.exists():
                try:
                    existing = json.loads(leak_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    existing = []
            leak_path.write_text(
                json.dumps(sorted(set(existing) | set(leaked)), indent=2), encoding="utf-8"
            )
            print(
                f"\n  WARNING: {len(leaked)} exclusive checkout(s) could NOT be released.\n"
                f"  Recorded in {leak_path}. They block a future headless pass on those\n"
                "  files. To clear: restart Ghidra (which drops the leaked consumers),\n"
                "  then run:  python tools/upgrade_project_language.py --release-checkouts"
            )
        # "unknown" is not "passed": an unreadable probe must never be reported
        # as a clean result, or the verification quietly certifies nothing.
        return 1 if (stale or unknown or leaked) else 0

    # ---- credentials ------------------------------------------------------ #
    password, source = resolve_password(ghidra_dir)
    if not password:
        print(
            "\nERROR: no server password. Set GHIDRA_SERVER_PASSWORD in the "
            f"environment or in {ghidra_dir / '.env'}.",
            file=sys.stderr,
        )
        return 2
    user = resolve_user(ghidra_dir)
    print(f"\n      Credentials: user={user} password from {source}")

    version = ghidra_dir.name
    # No cmd metacharacters: analyzeHeadless.bat re-parses its arguments, and a
    # parenthesis inside the check-in comment breaks the batch `if` blocks with
    # `"" was unexpected at this time` before the JVM is ever launched.
    comment = args.comment or f"Language upgrade to {version}"
    comment = re.sub(r"[()&|<>^%!\"]", "", comment)

    # ---- run -------------------------------------------------------------- #
    if args.apply and not args.folder and not args.force:
        prior = sorted(Path("reports").glob("language_upgrade_*.json"))
        recent = [
            p for p in prior
            if time.time() - p.stat().st_mtime < 86400
            and json.loads(p.read_text(encoding="utf-8")).get("mode") == "APPLY"
        ]
        if recent:
            print(
                f"\nERROR: a whole-project --apply already ran within 24h "
                f"({recent[-1].name}).\n"
                "       Re-running commits a NEW version for every file whether or not\n"
                "       it needs upgrading -- it is not a verification step. Use\n"
                "       --verify to check the outcome, --folder to scope a genuine\n"
                "       retry, or --force to override.",
                file=sys.stderr,
            )
            return 2

    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_dir = Path("reports") / f"language_upgrade_{stamp}" / "logs"
    print(f"\n[3/3] {'Upgrading' if args.apply else 'Preflighting'} {len(targets)} folders ...")
    print(f"      Logs: {log_dir}")

    results: list[FolderResult] = []
    for index, folder in enumerate(targets, 1):
        count = len(folders[folder])
        timeout = max(args.min_timeout, count * args.timeout_per_file)
        print(f"  [{index:3d}/{len(targets)}] {folder} ({count} programs) ...", end="", flush=True)
        result = run_folder(
            ghidra_dir=ghidra_dir,
            server=args.server,
            repo=args.repo,
            folder=folder,
            user=user,
            password=password,
            comment=comment,
            apply_changes=args.apply,
            timeout=timeout,
            log_dir=log_dir,
        )
        results.append(result)
        if result.unauthorized:
            print(" UNAUTHORIZED")
            print("\nERROR: the server rejected the credentials. Aborting before", file=sys.stderr)
            print("       any further folders are attempted.", file=sys.stderr)
            break
        bits = [f"{len(result.processed)} opened"]
        if result.committed:
            bits.append(f"{len(result.committed)} committed")
        elif result.saved:
            bits.append(f"{len(result.saved)} saved (NOT committed)")
        if result.needs_upgrade_blocked:
            bits.append(f"{len(result.needs_upgrade_blocked)} UPGRADE-BLOCKED")
        if result.no_exclusive_checkout:
            bits.append(f"{len(result.no_exclusive_checkout)} checkout-blocked")
        if result.newer_than_ghidra:
            bits.append(f"{len(result.newer_than_ghidra)} TOO-NEW")
        if result.save_errors:
            bits.append(f"{len(result.save_errors)} SAVE-ERRORS")
        print(f" {', '.join(bits)} [{result.seconds:.0f}s]")

    # ---- report ----------------------------------------------------------- #
    # Reconciliation: every planned program must be accounted for as either
    # opened or blocked. A file that is neither was never attempted, and without
    # this check the run reports a clean summary having quietly missed it.
    unaccounted: dict[str, list[str]] = {}
    for result in results:
        planned = {e["path"] for e in folders.get(result.folder, [])}
        touched = set(result.processed) | set(result.no_exclusive_checkout)
        missing = sorted(planned - touched)
        if missing:
            unaccounted[result.folder] = missing
    report_unaccounted = sum(len(v) for v in unaccounted.values())

    totals = {
        "opened": sum(len(r.processed) for r in results),
        "saved": sum(len(r.saved) for r in results),
        "committed": sum(len(r.committed) for r in results),
        "upgrade_blocked": sum(len(r.needs_upgrade_blocked) for r in results),
        "checkout_blocked": sum(len(r.no_exclusive_checkout) for r in results),
        "newer_than_ghidra": sum(len(r.newer_than_ghidra) for r in results),
        "save_errors": sum(len(r.save_errors) for r in results),
    }
    report = {
        "timestamp": stamp,
        "mode": mode,
        "repository": f"ghidra://{args.server}/{args.repo}",
        "ghidra": str(ghidra_dir),
        "program_count": len(programs),
        "versioned_count": len(versioned),
        "private_unreachable": [e["path"] for e in private],
        "folders_attempted": len(results),
        "folders_planned": len(targets),
        "preexisting_checkouts": blockers,
        "totals": totals,
        "unaccounted": unaccounted,
        "folders": [asdict(r) for r in results],
    }
    report_path = Path(args.report) if args.report else Path("reports") / f"language_upgrade_{stamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + "=" * 78)
    print("  Summary")
    for key, value in totals.items():
        print(f"    {key:20s} {value}")
    print(f"    {'unaccounted':20s} {report_unaccounted}")
    print(f"    report               {report_path}")
    print("=" * 78)

    if unaccounted:
        print("\n  UNACCOUNTED -- planned but neither opened nor reported blocked:")
        for folder, paths in unaccounted.items():
            for path in paths:
                print(f"    {path}")

    if args.apply and totals["committed"]:
        print("\n  Ghidra's project tree is now stale. Refresh it (or restart Ghidra)")
        print("  before opening anything, and re-run with --apply to confirm the")
        print("  pass is idempotent -- a clean second run saves 0 files.")

    failed = report_unaccounted or totals["save_errors"] or totals["newer_than_ghidra"] or any(
        r.unauthorized or r.returncode not in (0, None) for r in results
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
