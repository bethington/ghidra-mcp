"""Resolve the launcher commands an MCP client is told to spawn.

Issue #441: an MCP client started from a systemd user service, a desktop
``.desktop`` entry, or any other GUI session inherits *that launcher's* PATH,
which routinely omits ``~/.local/bin`` and ``~/.cargo/bin``. The documented
``"command": "uv"`` then dies at process-spawn time with ``spawn uv ENOENT``
— before a single line of bridge code runs, so there is nothing in any log to
read. The fix is always the same: put the absolute path in the client config.

This module resolves those launchers and formats a report. It is deliberately
**advisory**: it resolves against the PATH of the shell running preflight, not
the PATH of the MCP client, so a "found" here is evidence, not proof. Every
report says so — a check that implied otherwise would be worse than no check,
because it would send people looking somewhere else when the spawn still fails.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

UV_INSTALL_URL = "https://docs.astral.sh/uv/getting-started/installation/"

#: The launchers the docs tell people to put in an MCP client's ``"command"``.
#: ``uv`` is the documented quick-start launcher; ``bridge-mcp-ghidra`` is the
#: console script the wheel installs, used by people who install the bridge
#: into an environment instead of running it through uv.
SPAWN_COMMANDS: tuple[str, ...] = ("uv", "bridge-mcp-ghidra")

#: ``bridge-mcp-ghidra`` is genuinely optional — the `uv run` workflow never
#: installs it onto PATH — so its absence is reported, never treated as a fault.
OPTIONAL_SPAWN_COMMANDS: frozenset[str] = frozenset({"bridge-mcp-ghidra"})


@dataclass(frozen=True)
class SpawnResolution:
    """One launcher, resolved (or not) against a concrete PATH."""

    name: str
    path: str | None
    searched: tuple[str, ...]
    pathext: tuple[str, ...] = ()
    #: Windows searches the current directory before PATH; recording it keeps
    #: the report from claiming a cwd hit came out of PATH. None elsewhere.
    current_directory: str | None = None

    @property
    def found(self) -> bool:
        return self.path is not None

    @property
    def optional(self) -> bool:
        return self.name in OPTIONAL_SPAWN_COMMANDS


def search_path_entries(env: dict[str, str] | None = None) -> tuple[str, ...]:
    """Return the PATH directories that would actually be searched.

    Empty segments are dropped and duplicates collapsed so the printed list
    matches what a lookup really walks, in order.
    """
    environ = os.environ if env is None else env
    raw = environ.get("PATH", "")
    entries: list[str] = []
    for chunk in raw.split(os.pathsep):
        entry = chunk.strip().strip('"')
        if entry and entry not in entries:
            entries.append(entry)
    return tuple(entries)


def pathext_entries(env: dict[str, str] | None = None) -> tuple[str, ...]:
    """Return the executable suffixes tried on Windows (empty elsewhere).

    On POSIX a command is a plain file with the execute bit set; on Windows the
    lookup is name x PATHEXT, and a report that omitted that would mislead a
    Windows user into thinking only the directories mattered.
    """
    if os.name != "nt":
        return ()
    environ = os.environ if env is None else env
    raw = environ.get("PATHEXT", "")
    return tuple(ext for ext in (c.strip() for c in raw.split(os.pathsep)) if ext)


def resolve_spawn_command(
    name: str, env: dict[str, str] | None = None
) -> SpawnResolution:
    """Resolve one launcher with :func:`shutil.which`, recording what was searched.

    ``shutil.which`` handles PATHEXT on Windows and the execute bit on POSIX, so
    this stays a single code path on both.
    """
    entries = search_path_entries(env)
    found = shutil.which(name, path=os.pathsep.join(entries))
    return SpawnResolution(
        name=name,
        path=os.path.abspath(found) if found else None,
        searched=entries,
        pathext=pathext_entries(env),
        current_directory=os.getcwd() if os.name == "nt" else None,
    )


def resolve_spawn_commands(
    names: tuple[str, ...] = SPAWN_COMMANDS, env: dict[str, str] | None = None
) -> list[SpawnResolution]:
    """Resolve every documented launcher."""
    return [resolve_spawn_command(name, env) for name in names]


def client_config_snippet(resolutions: list[SpawnResolution], repo_root: Path) -> str:
    """Build a ready-to-paste MCP client config with an absolute ``command``.

    Prefers ``uv`` (the documented workflow); falls back to the console script;
    falls back to a clearly-marked placeholder when neither resolved, so the
    shape of the fix is still visible to someone who has to install uv first.
    """
    by_name = {r.name: r for r in resolutions}
    uv = by_name.get("uv")
    script = by_name.get("bridge-mcp-ghidra")

    if uv is not None and uv.found:
        command = uv.path
        args = [
            "run",
            "--directory",
            str(repo_root),
            "bridge-mcp-ghidra",
            "--transport",
            "stdio",
        ]
    elif script is not None and script.found:
        command = script.path
        args = ["--transport", "stdio"]
    else:
        command = "/absolute/path/to/uv"
        args = [
            "run",
            "--directory",
            str(repo_root),
            "bridge-mcp-ghidra",
            "--transport",
            "stdio",
        ]

    config = {
        "mcpServers": {
            "ghidra-mcp": {
                "command": command,
                "args": args,
                "env": {"GHIDRA_MCP_URL": "http://127.0.0.1:8089"},
            }
        }
    }
    return json.dumps(config, indent=2)


def _remedy(name: str) -> list[str]:
    if name == "uv":
        return [
            f"Install uv ({UV_INSTALL_URL}), then put uv's ABSOLUTE path in the",
            'MCP client config as "command" instead of the bare name "uv".',
        ]
    return [
        "Only needed if your client config spawns the console script directly;",
        "`uv run bridge-mcp-ghidra` does not require it on PATH. To install it,",
        "run `uv sync`, then use the absolute path to the script under",
        '.venv/bin (POSIX) or .venv\\Scripts (Windows) as "command".',
    ]


def _describe_searched(resolution: SpawnResolution) -> list[str]:
    """The searched PATH, one entry per line, plus the Windows suffix list."""
    count = len(resolution.searched)
    noun = "entry" if count == 1 else "entries"
    lines = [f"     PATH searched ({count} {noun}):"]
    if resolution.searched:
        lines.extend(f"       {entry}" for entry in resolution.searched)
    else:
        lines.append("       (PATH is empty - nothing was searched)")
    if resolution.current_directory is not None:
        lines.append(
            "     Windows also searches the current directory first: "
            + resolution.current_directory
        )
    if resolution.pathext:
        lines.append("     Suffixes tried (PATHEXT): " + ", ".join(resolution.pathext))
    return lines


def format_spawn_report(
    resolutions: list[SpawnResolution], repo_root: Path
) -> list[str]:
    """Format the spawn-resolution report as printable lines.

    The full PATH listing is printed for a **required** launcher that did not
    resolve — that is the case the user has to act on. An optional launcher's
    absence is the normal state of the ``uv run`` workflow, so it gets one line
    (with the search size) instead of dozens; dumping 50-odd directories on
    every routine preflight would only train people to skip the block.
    """
    lines = ["MCP client spawn commands:"]
    width = max((len(r.name) for r in resolutions), default=0)

    for resolution in resolutions:
        label = resolution.name.ljust(width)
        if resolution.found:
            lines.append(f"  {label} -> {resolution.path}")
            continue

        count = len(resolution.searched)
        noun = "entry" if count == 1 else "entries"
        if resolution.optional:
            lines.append(
                f"  {label} -> not on PATH ({count} {noun} searched) - optional"
            )
        else:
            lines.append(f"  {label} -> NOT FOUND on this PATH")
            lines.extend(_describe_searched(resolution))
        for remedy_line in _remedy(resolution.name):
            lines.append(f"     {remedy_line}")

    lines.extend(
        [
            "  NOTE: this resolved against THIS shell's PATH, not the PATH your",
            "        MCP client will use. A client started by a systemd user service,",
            "        a desktop entry, or any GUI app inherits that launcher's",
            "        environment, which routinely omits ~/.local/bin and ~/.cargo/bin.",
            "        A pass here does NOT prove your client can spawn the command.",
            "        Put an absolute path in the client config and the question stops",
            "        mattering (issue #441):",
        ]
    )
    for snippet_line in client_config_snippet(resolutions, repo_root).splitlines():
        lines.append(f"    {snippet_line}")
    return lines


def report_spawn_commands(
    repo_root: Path,
    names: tuple[str, ...] = SPAWN_COMMANDS,
    env: dict[str, str] | None = None,
) -> list[SpawnResolution]:
    """Print the spawn-resolution report and return the resolutions.

    Advisory only — the caller does not fail preflight on the result. ``uv``
    being missing is already a hard failure earlier in preflight via
    ``ensure_uv_available``; the console script is legitimately absent for
    everyone using the ``uv run`` workflow.
    """
    resolutions = resolve_spawn_commands(names, env)
    for line in format_spawn_report(resolutions, repo_root):
        print(line)
    return resolutions
