# Ghidra MCP Server

[![MCP Toplist](https://mcptoplist.com/badge/glama%2Fbethington%2Fghidra-mcp.svg)](https://mcptoplist.com/server/glama%2Fbethington%2Fghidra-mcp)

[![Tests](https://img.shields.io/github/actions/workflow/status/bethington/ghidra-mcp/tests.yml?branch=main&style=for-the-badge&label=Tests&logo=github-actions&logoColor=white)](https://github.com/bethington/ghidra-mcp/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white&color=blue)](https://github.com/bethington/ghidra-mcp/releases/latest)
[![License](https://img.shields.io/github/license/bethington/ghidra-mcp?style=for-the-badge&color=green)](LICENSE)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/bethington?style=for-the-badge&logo=githubsponsors&logoColor=white&label=Sponsors&labelColor=ea4aaa&color=ea4aaa)](https://github.com/sponsors/bethington)

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Java](https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/21/)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.1.4-brightgreen?style=for-the-badge&logoColor=white)](https://ghidra-sre.org/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-6C5CE7?style=for-the-badge&logoColor=white)](https://modelcontextprotocol.io/)

[![Stars](https://img.shields.io/github/stars/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white&color=yellow)](https://github.com/bethington/ghidra-mcp/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/bethington/ghidra-mcp?style=for-the-badge&logo=git&logoColor=white)](https://github.com/bethington/ghidra-mcp/commits/main)
[![Discussions](https://img.shields.io/badge/discussions-join-7B68EE?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bethington/ghidra-mcp/discussions)
[![Issues](https://img.shields.io/github/issues/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white&color=orange)](https://github.com/bethington/ghidra-mcp/issues)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/bethington/ghidra-mcp?style=for-the-badge&logo=securityscorecard&logoColor=white&label=OpenSSF%20Scorecard)](https://scorecard.dev/viewer/?uri=github.com/bethington/ghidra-mcp)

> If you find this useful, please ⭐ star the repo — it helps others discover it!
>
> If Ghidra MCP saves you time, consider [sponsoring the project](https://github.com/sponsors/bethington). One-time and recurring support both help fund compatibility updates, production hardening, docs, and new tooling.

A production-ready Model Context Protocol (MCP) server that bridges Ghidra's powerful reverse engineering capabilities with modern AI tools and automation frameworks. **209 MCP tools**, battle-tested AI workflows, and the most comprehensive Ghidra-MCP integration available — now including P-code emulation, live debugger integration, and PCode-graph data flow analysis.

## Why Ghidra MCP?

Most Ghidra MCP implementations give you a handful of read-only tools and call it a day. This project is different — it was built by a reverse engineer who uses it daily on real binaries, not as a demo.

- **209 MCP tools** — 3x more than any competing implementation. Not just read operations — full write access for renaming, typing, commenting, structure creation, script execution, P-code emulation, and live debugging.
- **Battle-tested AI workflows** — Proven documentation workflows (V5) refined across hundreds of functions. Includes step-by-step prompts, Hungarian notation reference, batch processing guides, and orphaned code discovery.
- **Production-grade reliability** — Atomic transactions, batch operations (93% API call reduction), configurable timeouts, and graceful error handling. No silent failures.
- **Cross-binary documentation transfer** — SHA-256 function hash matching propagates documentation across binary versions automatically. Document once, apply everywhere.
- **Full Ghidra Server integration** — Connect to shared Ghidra servers, manage repositories, version control, checkout/checkin workflows, and multi-user collaboration.
- **Headless and GUI modes** — Run with or without the Ghidra GUI. Docker-ready for CI/CD pipelines and automated analysis at scale.
- **Opinionated by design** — v5.0 moves naming conventions, type safety, and documentation standards into the tool layer. AI agents and human engineers produce consistent output without style guides in every prompt.

## Convention Enforcement

You've been there: six months into a project you find `ProcessItem`, `process_items`, `handleItem`, and `ItemProc` in the same codebase — four functions doing the same thing, named by four different sessions or engineers with no shared contract. Fixing it takes longer than it should, and the problem will happen again.

v5.0 moves conventions from "things to remember" into the tool layer, where they can actually be enforced.

| Tier | Behavior | Example |
| ------ | ---------- | --------- |
| **Auto-fix** | Applied silently | `count` field on a `uint32` → auto-prefixed `dwCount` on save |
| **Warn** | Change goes through, warning returned | `processData` → "name should be PascalCase with a verb: `ProcessData`" |
| **Reject** | Change blocked with explanation | `undefined → undefined` type change → "no-op rejected, type unchanged" |

**For AI agents**, this means consistent output across every session, every model, every run — without pasting a style guide into every prompt. The tool knows the rules; the model just needs to make the call.

**For teams**, it eliminates the entire class of review comment that says "that's not our naming convention." Convention arbitration stays in the tool, not in code review.

**For solo work at scale**, `analyze_function_completeness` gives you a 0–100% score that measures honestly: structural deductions (unfixable compiler artifacts) are forgiven in your effective score, log-scaling prevents one bad category from burying everything else, and tiered plate comment quality means you know exactly what's missing and why.

## 🌟 Features

### Core MCP Integration

- **Full MCP Compatibility** — Complete implementation of Model Context Protocol
- **209 MCP tools** — Comprehensive API surface covering every aspect of binary analysis
- **Production-Ready Reliability** — Atomic transactions, batch operations, configurable timeouts
- **Real-time Analysis** — Live integration with Ghidra's analysis engine

> **Compatibility note:** MCP tool names are normalized for GitHub Copilot CLI
> and CAPI validation. Exposed tool names use lowercase letters, digits,
> underscores, and hyphens only; nested HTTP paths such as `/debugger/status`
> are advertised as names like `debugger_status_2` when needed to avoid
> collisions with static bridge tools.

### Binary Analysis Capabilities

- **Function Analysis** — Decompilation, call graphs, cross-references, completeness scoring
- **Data Flow Analysis** — PCode-graph value propagation (forward / backward) from any variable or register
- **Data Structure Discovery** — Struct/union/enum creation with field analysis and naming suggestions
- **String Extraction** — Regex search, quality filtering, and string-anchored function discovery
- **Import/Export Analysis** — Symbol tables, external locations, ordinal import resolution
- **Memory & Data Inspection** — Raw memory reads, byte pattern search, array boundary detection
- **Cross-Binary Documentation** — Function hash matching and documentation propagation across versions

### Dynamic Analysis (v5.4.0)

- **P-code Emulation** — Run any function in isolation via Ghidra's `EmulatorHelper`; brute-force API hash resolution in milliseconds
- **Live Debugger Integration** — 16 `/debugger/*` endpoints over Ghidra's TraceRmi framework (GUI plugin only; dbgeng on Windows PE, gdb/lldb otherwise): launch, interrupt/resume, step into/over/out, breakpoints, registers, memory reads, stack traces, ASLR-aware static↔dynamic address translation. The bridge can also proxy 22 `debugger_*` tools to an external debugger server; they are opt-in (see [below](#optional-connect-an-external-debugger-server))

### AI-Powered Reverse Engineering Workflows

- **Function Documentation Workflow V5** — 7-step process for complete function documentation with Hungarian notation, type auditing, and automated verification scoring
- **Batch Documentation** — Parallel subagent dispatch for documenting multiple functions simultaneously
- **Orphaned Code Discovery** — Automated scanner finds undiscovered functions in gaps between known code
- **Data Type Investigation** — Systematic workflows for structure discovery and field analysis
- **Cross-Version Matching** — Hash-based function matching across different binary versions

### Development & Automation

- **Ghidra Script Execution** — List and run Ghidra scripts, or run inline script code, via MCP (running them is opt-in: `GHIDRA_MCP_ALLOW_SCRIPTS=1`)
- **Multi-Program Support** — Switch between and compare multiple open programs
- **Batch Operations** — Bulk renaming, commenting, typing, and label management (93% fewer API calls)
- **Headless Server** — Full analysis without Ghidra GUI — Docker and CI/CD ready
- **Project & Version Control** — Create projects, manage files, Ghidra Server integration
- **Analysis Control** — List, configure, and trigger Ghidra analyzers programmatically

## 🚀 Quick Start

### Prerequisites

- **Java 21 LTS** (OpenJDK recommended)
- **Apache Maven 3.9+** for the `python -m tools.setup` commands below (Maven is their default backend). Not needed if you build with the committed Gradle wrapper instead — see step 6
- **Ghidra 12.1.4** (or compatible version)
- **Python 3.10+** with [uv](https://docs.astral.sh/uv/) (recommended) or pip + venv

> Shared Ghidra Server users: Ghidra 12.1.4 clients require a Ghidra
> Server at 12.1, 12.0.5, or a newer compatible version. Upgrade the
> server before using this plugin from a 12.1 client.
>
> Ghidra 12.1.4 ships Jython as an optional extension. Java scripts work
> by default, but `.py` scripts in `ghidra_scripts/` require installing
> the Jython extension from **File > Install Extensions** and restarting
> Ghidra.

### Installation

> Recommended for all platforms: use `python -m tools.setup` directly.
>
> `ensure-prereqs` installs runtime Python requirements plus the Ghidra JARs needed in the local Maven repository.
> `deploy` copies the build output, installs the user-profile extension, and patches Ghidra user config.

1. **Clone the repository:**

   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Recommended: run environment preflight first:**

   ```text
   python -m tools.setup preflight --ghidra-path "F:\ghidra_12.1.4_PUBLIC"
   ```

3. **Build and deploy to Ghidra:**

   ```text
   python -m tools.setup ensure-prereqs --ghidra-path "F:\ghidra_12.1.4_PUBLIC"
   python -m tools.setup build
   python -m tools.setup deploy --ghidra-path "F:\ghidra_12.1.4_PUBLIC"
   ```

   `deploy` saves/closes an already-running matching Ghidra instance when
   needed, installs the extension, starts Ghidra, waits for MCP health, and runs
   schema smoke checks.

   Prefer to click through Ghidra's own dialogs, or installing a release zip on
   a machine without the repo? Follow the illustrated
   [manual GUI install guide](docs/INSTALL_GUI.md).

4. **Optional strict/manual mode** (advanced):

   ```text
   # Skip automatic prerequisite setup
   python -m tools.setup build
   python -m tools.setup deploy --ghidra-path "F:\ghidra_12.1.4_PUBLIC"
   ```

5. **Show command help**:

   ```text
   python -m tools.setup --help
   ```

6. **Optional build-only mode** (advanced/troubleshooting):

   ```text
   python -m tools.setup build
   ```

   Two Java backends are supported. **Gradle is the default for local work** — it reads Ghidra's jars straight out of the installation, so there is no `install-file` step and nothing to install beyond a JDK. **CI builds and gates with Maven**, so Maven is a maintained peer rather than a fallback.

   ```bash
   # Gradle (default) -- the wrapper is committed, so no Gradle install is needed.
   # -PGHIDRA_INSTALL_DIR or the GHIDRA_INSTALL_DIR env var both work.
   # In Git Bash use forward slashes; a backslash path is mangled before Gradle sees it.
   ./gradlew buildExtension -PGHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

   ```bash
   # Maven (peer backend; what CI uses). Needs Ghidra's jars in the local .m2 first:
   #   python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
   mvn clean package assembly:single -DskipTests
   ```

   `python -m tools.setup build` routes to Maven by default; set `TOOLS_SETUP_BACKEND=gradle` to route it to Gradle instead.

### Installation (Linux — Ubuntu/Debian)

1. **Clone the repository:**

   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Install system prerequisites** (if not already installed):

   ```bash
   sudo apt update && sudo apt install -y openjdk-21-jdk maven python3 python3-pip python3-venv curl jq unzip
   ```

   > **Debian/Kali/Ubuntu 23.04+ note (PEP 668):** these distros mark the system
   > Python as *externally managed*, so a bare `pip install` fails with
   > `error: externally-managed-environment`. Don't work around it with
   > `--break-system-packages` — it can corrupt apt-managed tooling. Instead use
   > [uv](https://docs.astral.sh/uv/) (recommended — it creates and manages a
   > project-local `.venv` automatically, and is what this repo's commands use):
   >
   > ```bash
   > curl -LsSf https://astral.sh/uv/install.sh | sh
   > uv run bridge-mcp-ghidra    # resolves deps into .venv and starts the bridge
   > ```
   >
   > or a classic virtual environment:
   >
   > ```bash
   > python3 -m venv .venv && source .venv/bin/activate
   > pip install -e .
   > bridge-mcp-ghidra
   > ```

3. **Run environment preflight:**

   ```bash
   python -m tools.setup preflight --ghidra-path ~/ghidra_12.1.4_PUBLIC
   ```

4. **Build and deploy to Ghidra (single command):**

   ```bash
   python -m tools.setup ensure-prereqs --ghidra-path ~/ghidra_12.1.4_PUBLIC
   python -m tools.setup build
   python -m tools.setup deploy --ghidra-path ~/ghidra_12.1.4_PUBLIC
   ```

   This will:
   - Install Ghidra JAR dependencies into your local `~/.m2/repository`
   - Build `GhidraMCP-<version>.zip` with Maven
   - Extract the extension to `~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/`
   - Update `preferences` with `LastExtensionImportDirectory`
   - Install Python requirements

5. **Optional: setup only Maven dependencies:**

   ```bash
   python -m tools.setup install-ghidra-deps --ghidra-path ~/ghidra_12.1.4_PUBLIC
   ```

6. **Show command help:**

   ```bash
   python -m tools.setup --help
   ```

> **Linux paths:** The extension is installed to `$HOME/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/GhidraMCP/`.
> Ghidra config files are in `$HOME/.config/ghidra/ghidra_<version>_PUBLIC/`.

### Installation (macOS — Homebrew)

1. **Install prerequisites:**

   ```bash
   brew install openjdk@21 maven python ghidra
   ```

2. **Clone the repository:**

   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

3. **Install Ghidra JARs into local Maven:**

   ```bash
    python -m tools.setup install-ghidra-deps \
       --ghidra-path /opt/homebrew/opt/ghidra/libexec
   ```

4. **Build and deploy:**

   ```bash
    python -m tools.setup ensure-prereqs \
       --ghidra-path /opt/homebrew/opt/ghidra/libexec
    python -m tools.setup build
    python -m tools.setup deploy \
       --ghidra-path /opt/homebrew/opt/ghidra/libexec
   ```

   The extension is installed to `~/Library/ghidra/ghidra_12.1.4_PUBLIC/Extensions/GhidraMCP/`.

   > **Note:** the Homebrew path contains no version string, so `tools.setup` reads the Ghidra version from `Ghidra/application.properties` inside the installation instead.

5. **Start Ghidra and enable the plugin:**

   ```bash
   /opt/homebrew/opt/ghidra/libexec/ghidraRun
   ```

   The server starts with the plugin. Check it from the project window:
   **Tools > GhidraMCP > Server Status**

6. **Configure Cursor/Claude MCP** (`~/.cursor/mcp.json`) — use the **absolute
   path** to `uv` (`which uv`), not the bare name; GUI-launched clients do not
   inherit your shell's PATH ([#441](https://github.com/bethington/ghidra-mcp/issues/441)):

   ```json
   {
     "mcpServers": {
       "ghidra": {
         "command": "/opt/homebrew/bin/uv",
         "args": ["run", "--directory", "/path/to/ghidra-mcp", "bridge-mcp-ghidra"]
       }
     }
   }
   ```

   macOS is the sharpest case: apps launched from Finder/Dock get `launchd`'s
   PATH, which never contains `~/.local/bin` or `/opt/homebrew/bin`.

### Installation (Arch Linux — AUR)

[@Pandoriaantje](https://github.com/Pandoriaantje) maintains community AUR packages:

- [`ghidra-mcp-git`](https://aur.archlinux.org/packages/ghidra-mcp-git) — tracks `main`
- [`ghidra-mcp`](https://aur.archlinux.org/packages/ghidra-mcp) — tracks tagged releases

Install with your AUR helper of choice, e.g.:

```bash
yay -S ghidra-mcp        # or ghidra-mcp-git
```

### Basic Usage

#### Option 1: Stdio Transport (Recommended for AI tools)

```bash
uv run bridge-mcp-ghidra          # or: python -m bridge_mcp_ghidra
```

MCP client config (`.mcp.json`, `~/.cursor/mcp.json`, Claude Desktop config, …).
**Use the absolute path to `uv`** — see the note below for why:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "/home/<you>/.local/bin/uv",
      "args": ["run", "--directory", "/path/to/ghidra-mcp", "bridge-mcp-ghidra", "--transport", "stdio"],
      "env": { "GHIDRA_MCP_URL": "http://127.0.0.1:8089" }
    }
  }
}
```

On Windows the same config points at `uv.exe`, e.g.
`"command": "C:\\Users\\<you>\\.local\\bin\\uv.exe"`. Find your own path with
`which uv` (POSIX) or `where.exe uv` (Windows), or just run
`python -m tools.setup preflight`, which prints the resolved absolute path and a
ready-to-paste snippet.

> **Why absolute? `"command": "uv"` fails under service and GUI launchers.**
> The MCP client resolves `command` with **its own** PATH, not your shell's. A
> client started from a **systemd user service**, a `.desktop` entry, or any
> other GUI session inherits that launcher's environment, which routinely lacks
> `~/.local/bin` and `~/.cargo/bin` — the very directories `uv` installs into.
> The failure lands at process-spawn time as `spawn uv ENOENT`, before any
> bridge code runs, so there is nothing in any log to read. An absolute path
> makes the client's PATH irrelevant and works on the first try. The same
> applies to `python`, `python3`, and the `bridge-mcp-ghidra` console script.
> ([#441](https://github.com/bethington/ghidra-mcp/issues/441))

To add the bridge to [Autohand Code](https://github.com/autohandai/code-cli/) from a cloned checkout:

```bash
autohand mcp add ghidra /home/<you>/.local/bin/uv run --directory /path/to/ghidra-mcp bridge-mcp-ghidra
```

Add `--scope project` before `ghidra` to save the server in the current project's `.autohand` configuration instead of your user configuration.

#### Option 2: Streamable HTTP Transport (Recommended for web/HTTP clients)

```bash
uv run bridge-mcp-ghidra --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081
```

MCP client config for the HTTP transport (add to your client's MCP config file):

```json
{
  "mcpServers": {
    "ghidra-mcp-http": {
      "url": "http://127.0.0.1:8081/mcp"
    }
  }
}
```

Browser-based clients (e.g. [MCP Inspector](https://github.com/modelcontextprotocol/inspector))
work out of the box: the HTTP transports answer CORS preflight (`OPTIONS`) requests and expose
the `mcp-session-id` / `mcp-protocol-version` headers to scripts. Allowed origins mirror the
Host-header policy — loopback on any port is always permitted, plus the bind host and any
hosts listed in `GHIDRA_MCP_ALLOWED_HOSTS`.

`GHIDRA_MCP_ALLOWED_HOSTS` also supports clients that route a loopback-bound
bridge through another network namespace. For example, a container can address
the host as `host.containers.internal` without exposing the bridge on a LAN
interface:

```bash
GHIDRA_MCP_ALLOWED_HOSTS=host.containers.internal \
  uv run bridge-mcp-ghidra --transport streamable-http \
  --mcp-host 127.0.0.1 --mcp-port 8081
```

The setting extends DNS-rebinding Host/Origin validation only; it does not
change the bind address or make the listener reachable on additional interfaces.

#### Option 3: SSE Transport (Deprecated — use streamable-http instead)

```bash
uv run bridge-mcp-ghidra --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

#### Bridge advanced flags

| Flag | Default | Description |
| ------ | --------- | ------------- |
| `--transport` | `stdio` | `stdio` (AI tools), `streamable-http` (web clients), `sse` (deprecated) |
| `--mcp-host` | `127.0.0.1` | Bind host for HTTP transports |
| `--mcp-port` | — | Port for HTTP transports |
| `--lazy` | (default) | Load only the default tool groups on connect, and let the model pull in the rest with `search_tools`/`load_tool_group`. |
| `--no-lazy` | off | Load all tool groups immediately on connect. Needed only by MCP clients that ignore `tools/list_changed`; **rejected outright by the Gemini API** (see below). |
| `--default-groups` | `listing,function,program` | Comma-separated groups loaded on connect under `--lazy`. |
| `--tools-page-size` | `0` | Serve `tools/list` in pages of this size (`0` = one page). Only for a client that cannot take one large response; a client that ignores `nextCursor` sees only the first page. |
| `--json-response` | off | streamable-http: answer POSTs with plain JSON instead of an SSE stream. Server-initiated messages such as `tools/list_changed` are then not delivered. |
| `--stateless-http` | off | streamable-http: no session id and no server-initiated notifications, for running several bridge workers behind a load balancer. Pair it with `--no-lazy`, since a group loaded later can never be announced. |

To require a token from MCP clients of an HTTP transport, set
`GHIDRA_MCP_INBOUND_TOKEN=<secret>`; clients must then send
`Authorization: Bearer <secret>`. The bridge logs a warning when it binds a
non-loopback `--mcp-host` without one. Separately, when `GHIDRA_MCP_AUTH_TOKEN`
(the token the bridge sends to Ghidra) is set and the bridge binds a
non-loopback host, clients must present that same token, so the bridge cannot
be used to relay it.

#### Lazy tool loading is the default (issue #440)

Advertising all 209 endpoints in a single `tools/list` is over a hard limit for
at least one major provider. Gemini compiles function declarations into a
constrained-decoding state machine and rejects the whole request before any tool
is ever called:

```text
400 INVALID_ARGUMENT
The specified schema produces a constraint that has too many states for serving
```

That is not a degradation, it is an outright break, and no client-side setting
could work around a server that only ever offered the full set. So the bridge
now loads `listing,function,program` (68 endpoints plus the 8 static tools) on
connect and registers the rest on demand.

**If your client ignores `tools/list_changed`** it will not notice tools that
are registered later, and should turn lazy loading off:

```bash
uv run bridge-mcp-ghidra --no-lazy          # when you control the command line
export GHIDRA_MCP_LAZY=0                    # when you don't (Docker, uvx, some client configs)
```

`GHIDRA_MCP_LAZY` accepts `0/false/no/off` and `1/true/yes/on`; an explicit
`--lazy`/`--no-lazy` on the command line wins over it. Startup logs which mode
is in effect.

#### Strict program routing (multi-program safety)

Set `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` to make the bridge refuse any program-scoped
call that omits a program selector, returning a clear error instead of letting the call
ride the server's shared "current program" (the one `switch_program` and the
active GUI tab move).

```bash
export GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1
uv run bridge-mcp-ghidra
```

Without this, a call that leaves `program=` out runs against whichever program
is current, which is fine for a single-program workflow but a hazard once
several programs are open: the call can read or edit the wrong binary with no
error. The hazard is worse when more than one client shares a server, since
each one moves that current-program global out from under the others.

With strict mode on, every program-scoped call must name its target. This
covers every selector that picks an open program: plain `program=` and the
cross-program tools' `source_program`/`target_program` or `program_a`/`program_b`
(declared required, but the server still falls back to the current program when
one arrives empty). A forgotten selector surfaces as a loud error on the first
bad call instead of a silent write to the wrong binary. Tools with no program
selector (`open_program` and `close_program` take `path`/`name`) are unaffected.
Off by default: with the variable unset the bridge sends calls unchanged.

#### Reducing tool-context overhead

The bridge exposes a large catalog, so it loads only `listing,function,program`
on connect (see above) and lets the model **discover** the rest on demand
instead of registering everything:

- `search_tools("rename function")` — keyword-search the **entire** catalog,
  including tools whose group isn't loaded. Each result says whether it's
  callable now and, if not, the exact `load_tool_group(...)` call to enable it.
- `list_tool_groups()` — list all categories and their load state.
- `load_tool_group("datatype")` / `unload_tool_group("datatype")` — load or
  drop a category at runtime.
- `check_tools("rename_symbol,batch_set_comments")` — confirm specific tools
  are callable right now.

`search_tools` works in both lazy and `--no-lazy` modes, so agents that honor
`tools/list_changed` get full discovery without the upfront context cost.

#### Minimal read-only allowlist

Some MCP clients gate tools through an explicit allowlist. Cut it too far and
the agent loses **discovery** — it cannot find entry points or enumerate
functions through MCP, so it works around the allowlist by `curl`-ing the HTTP
API on `127.0.0.1:8089` directly, which defeats the point of having one. The
allowlist has to be small *and* self-sufficient.

**Minimum viable read-only set (4 tools):**

| Tool | Group | What it buys you |
| --- | --- | --- |
| `get_metadata` | `program` | Which binary is loaded — name, architecture, image base, function count. Orientation, and it confirms the bridge reached Ghidra at all. |
| `find_functions` | `listing` | Paginated function enumeration (`offset`, `limit`); with no filter it lists the whole program, and `name_pattern`/`regex` turn it into a name search. **This is the discovery tool** — without it the agent cannot answer "what is in this binary". |
| `get_entry_points` | `listing` | Where execution starts, so analysis has a root to work down from. |
| `get_functions` | `function` | The payload. Takes `function=` (name or address) **or** `functions=` (comma-separated names *or* addresses, up to 20), and `fields=` to pick what comes back: `decompiled_code`, `signature`, `callers`, `callees`, `xrefs`, `comments`, and more. |

That set is genuinely closed: `get_entry_points` and `find_functions` supply the
addresses and names that `get_functions` consumes, and its `callees` field names
the next functions to feed straight back into it.

The three tools suggested in [#441](https://github.com/bethington/ghidra-mcp/issues/441)
were `get_metadata`, `get_entry_points` and `decompile_function`. The first two
still exist under those names; `decompile_function` was folded into
`get_functions` in 7.0.0 (`fields=decompiled_code`), and
[the migration guide](docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md)
maps every other removed name. `find_functions` is the one addition worth
making: without it the agent can only reach code that is reachable by name from
something it already decompiled, so anything not referenced from an entry point
is invisible.

**Useful next additions, in order:**

| Tool | Group | Why |
| --- | --- | --- |
| `get_function_call_graph` | `xref` | A multi-level call graph (`depth`, `direction`) in one call. One level of callers and callees already comes from `get_functions`. |
| `get_xrefs_to` | `xref` | Who touches this address — the standard question about a global. Takes `addresses=` for several at once. |
| `list_strings` | `listing` | Strings are the cheapest orientation signal in an unknown binary. |
| `list_program_items` | `listing` | `kind=imports` / `kind=exports`: the binary's external surface. Other kinds list segments, classes, namespaces, data items and external locations. |

Every tool above is a `GET`; none of them writes to the Ghidra database.

**Two things to check when your allowlist is narrow:**

- **Groups, not just names.** The bridge registers tools by *group*, and the
  group is the `category` on the Java `@McpTool` annotation (which the running
  server publishes at `/mcp/schema`) — not the `category` field in
  `tests/endpoints.json`, which is a separate hand-maintained column and does
  not always agree. All four tools in the minimum set fall inside the default
  `listing,function,program` groups, so they are registered even under `--lazy`.
  Of the additions above, only the `xref` ones fall outside: under `--lazy` you
  must either allow `load_tool_group` as well, or start the bridge with
  `--default-groups listing,function,program,xref`.
- **A narrow allowlist plus `--lazy` needs the group tools.** If you allowlist
  only leaf tools and run lazily, the agent has no way to load anything else.
  Either run eagerly (`--no-lazy`; lazy is the default) or add `search_tools`,
  `list_tool_groups`, `load_tool_group`, and `check_tools` to the allowlist.

Verify any allowlist against the running server rather than against this table:
`curl http://127.0.0.1:8089/mcp/schema` lists every tool with the `category`
the bridge groups it by.

#### Optional: Connect an external debugger server

The bridge can proxy 22 `debugger_*` tools to an external dbgeng/WinDbg
debugger server speaking the bridge's debugger HTTP API. That server is **not
part of this repository**; this repo ships only the proxies. They are **off by
default** and register only when you opt in:

```bash
# point the bridge at your debugger server (loopback only)
export GHIDRA_DEBUGGER_URL=http://127.0.0.1:8099

# or force registration against the default URL (http://127.0.0.1:8099)
export GHIDRA_DEBUGGER_TOOLS=1
```

`GHIDRA_DEBUGGER_TOOLS` decides outright when set: `1`/`true`/`yes`/`on`
registers the tools, anything else (`0`, `false`, ...) keeps them off even with
a URL configured. With neither variable set the tools simply do not appear,
rather than appearing and failing. The host platform plays no part.

Ghidra's own TraceRmi debugger endpoints (`debugger_status`, `debugger_launch`,
...) are separate: they live in the GUI plugin and need no extra server.

Calls are only ever proxied to a loopback URL (`127.0.0.1`, `localhost` or
`::1`), so a non-loopback `GHIDRA_DEBUGGER_URL` does not register the tools. To
reach a debugger server on another machine, forward its port to loopback (for
example an SSH tunnel) and point `GHIDRA_DEBUGGER_URL` there.

The bridge reads these from its own process environment (the MCP client's
`env` block, or your shell); it does not read a `.env` file.

#### In Ghidra

1. Start Ghidra and open your project
2. In the **project window**, enable the plugin via **File > Configure > Utility > Configure > GhidraMCPPlugin** (this is what `deploy` does; enabling it in CodeBrowser also works, but then the server runs only while CodeBrowser is open)
3. Optional: configure a custom port via **Edit > Tool Options > GhidraMCP HTTP Server** in the same window
4. The server starts with the plugin; check it via **Tools > GhidraMCP > Server Status**
5. The server runs on `http://127.0.0.1:8089/` by default

Screenshots of every step: [docs/INSTALL_GUI.md](docs/INSTALL_GUI.md).

#### Verify It's Working

```bash
# Quick health check
curl http://127.0.0.1:8089/check_connection
# Expected: {"status": "ok", "server_kind": "gui", "version": "7.0.0", "program": "<name>"}
# ("program" appears only while a program is current)

# Fuller health: build details, uptime, open program count, HTTP pool, memory
curl http://127.0.0.1:8089/mcp/health

# Every tool the server advertises
curl -s http://127.0.0.1:8089/mcp/schema | jq '.tools | length'
```

## Support This Project

If Ghidra MCP saves you engineering or reverse-engineering time, consider [sponsoring the project](https://github.com/sponsors/bethington).

- One-time sponsorship helps fund fixes, compatibility updates, and release work.
- Recurring sponsorship helps keep maintenance, docs, and production hardening moving.
- Company support helps prioritize long-term reliability for the bridge, headless server, debugger integration, and workflow tooling.

## 🔒 Security

GhidraMCP is designed for **localhost-only development**. The default configuration — HTTP server bound to `127.0.0.1`, no authentication — is safe on a trusted single-user workstation and matches pre-v5.4.1 behavior.

**If you expose the server beyond loopback, configure these three environment variables first.** The server refuses to start on a non-loopback bind without a token.

| Env var | Effect |
| --- | --- |
| `GHIDRA_MCP_AUTH_TOKEN` | When set, every HTTP request must carry `Authorization: Bearer <token>`. Timing-safe comparison. `/mcp/health` and `/check_connection` are exempt. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Set to `1`, `true`, or `yes` to enable `/run_script_inline` and `/run_ghidra_script`. **Off by default as of v5.4.1** — these endpoints execute arbitrary Java against the Ghidra process. In headless mode this also triggers OSGi `BundleHost` initialization at server startup (Felix framework, ~hundreds of ms); leave it off if you don't need script execution. |
| `GHIDRA_MCP_FILE_ROOT` | When set to a directory path, filesystem-path endpoints (`/import_file`, `/open_project`, `/delete_file`, etc.) canonicalize the input and require it to fall under this root. Prevents path-traversal. |

Name-quality enforcement is separate from security. By default,
`rename_function` and global write endpoints reject names that fail
the built-in quality gates, and struct field writes apply the built-in field
prefix convention. Disable the built-in convention layer with **Edit > Tool
Options > GhidraMCP HTTP Server > Strict Naming Enforcement**. The same Tool
Options checkbox covers `rename_symbol` (all symbol kinds),
`set_global`, the `apply_data_type` prefix/type guard, and struct-field
Hungarian prefix auto-fixes in `create_struct`, `add_struct_field`, and
`modify_struct_field`. The setting is read when the MCP server starts or
restarts. Function/global convention warnings are still returned when
enforcement is disabled.

### Example: exposing to a private LAN with auth

```bash
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
export GHIDRA_MCP_ALLOW_SCRIPTS=1     # only if your workflow needs it
export GHIDRA_MCP_FILE_ROOT=/srv/ghidra/inputs

# Headless server (`mvn clean package -P headless -DskipTests`). The jar does not
# bundle Ghidra, so Ghidra's Framework/Features/Processors jars go on the
# classpath too -- docker/entrypoint.sh builds exactly that command.
java -cp "target/GhidraMCP-<version>.jar:<ghidra jars>" \
  com.xebyte.headless.GhidraMCPHeadlessServer --bind 0.0.0.0 --port 8089
```

The headless server serves only its Unix domain socket unless `--port` or
`--bind` is given; either one adds the TCP listener.

### Ghidra Server authentication

When connecting to a shared Ghidra Server, GhidraMCP can suppress the password dialog automatically. It resolves credentials in this order (first non-empty value wins):

Compatibility note: Ghidra 12.1.4 clients require Ghidra Server 12.1.2,
12.0.5, or a newer compatible server. Older shared servers are not safe
targets for a 12.1 client upgrade.

1. `GHIDRA_SERVER_PASSWORD` environment variable (or `.env` file in the Ghidra install directory or `~`)
2. `~/.ghidra-cred` — single-line password file in your home directory
3. `<ghidra-install-dir>/.ghidra-cred`

Username resolves similarly: `GHIDRA_SERVER_USER` env var → `user.name` system property.

If no password is found, Ghidra shows its normal GUI prompt. Set these in `.env` (see `.env.template` for the full block) to enable silent auth.

### Migration from v5.4.0 → v5.4.1

- **Script endpoints now default-off.** If you relied on `/run_script_inline` or `/run_ghidra_script`, export `GHIDRA_MCP_ALLOW_SCRIPTS=1`. This is a deliberate breaking change; the prior default was unsafe.
- **Localhost-only deployments need no changes.** Auth, bind refusal, and path-root checks are all opt-in.

## ❓ Troubleshooting

### `spawn uv ENOENT` / `spawn python ENOENT` when the client starts the server

**Cause:** the MCP client could not find the `command` on **its own** PATH. This
happens before any bridge code runs, so there is nothing in the Ghidra log or
the bridge log to look at — the process was never created.

It shows up when the client is launched by something other than a login shell:

- a **systemd user service** (`systemctl --user`), whose PATH is
  `/usr/local/bin:/usr/bin:/bin` unless you extend it;
- a desktop `.desktop` entry, dock icon, or app launcher;
- macOS apps started from Finder, which inherit `launchd`'s PATH.

None of those contain `~/.local/bin` (uv's default install location) or
`~/.cargo/bin`, so `"command": "uv"` cannot resolve even though `uv` works
perfectly in your terminal.

**Solution:** use an absolute path in the client config.

```jsonc
// before — resolves against the client's PATH, fails under a service/GUI launcher
"command": "uv"
// after — no PATH lookup at all
"command": "/home/<you>/.local/bin/uv"
```

Find yours with `which uv` (POSIX) or `where.exe uv` (Windows). Or run:

```bash
python -m tools.setup preflight
```

which prints the resolved absolute path, the PATH entries it searched when a
launcher is missing, and a ready-to-paste config snippet. Note what that check
can and cannot tell you: it resolves against **your shell's** PATH, not the
client's, so a pass there is evidence, not proof — the absolute path is what
actually removes the failure mode. ([#441](https://github.com/bethington/ghidra-mcp/issues/441))

If you must keep a bare command name, give the service manager the PATH instead
— e.g. `Environment="PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin"` in the
unit file, or `systemctl --user import-environment PATH` — but the absolute
path is the smaller and more portable fix.

### "GhidraMCP" menu not appearing in Tools

**Cause:** Plugin not enabled or installed incorrectly.

**Solution:**

1. Verify extension is installed: **File > Install Extensions** — GhidraMCP should be listed
2. Enable the plugin: **File > Configure > Utility > Configure > GhidraMCPPlugin** (check the box)
3. **Restart Ghidra** after installation/enabling

Illustrated walkthrough: [docs/INSTALL_GUI.md](docs/INSTALL_GUI.md).

### Server not responding / Connection refused

**Cause:** Server not started or wrong port.

**Solution:**

1. Check the server state: **Tools > GhidraMCP > Server Status** (it starts with the plugin; use **Restart Server** if it is stopped)
2. Check configured port: **Edit > Tool Options > GhidraMCP HTTP Server**
3. Check if port is in use:

   ```bash
   # Linux/macOS
   lsof -i :8089
   # Windows
   netstat -ano | findstr :8089
   ```

4. Look for errors in Ghidra console: **Window > Console**

### `pip install` fails with `error: externally-managed-environment`

**Cause:** PEP 668. Debian-family distros (Debian 12+, Kali, Ubuntu 23.04+)
mark the system Python as externally managed, so global `pip install` is
blocked to protect apt-managed packages.

**Solution:** Use a virtual environment — never `--break-system-packages`.
The recommended path is [uv](https://docs.astral.sh/uv/), which manages a
project-local `.venv` automatically:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
cd ghidra-mcp
uv run bridge-mcp-ghidra
```

Or a classic venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
bridge-mcp-ghidra
```

### The `debugger_*` tools do not appear

**Cause:** The 22 bridge-side debugger proxies are off by default. They register
only when `GHIDRA_DEBUGGER_URL` is set or `GHIDRA_DEBUGGER_TOOLS=1`, and they
forward to an external debugger server that is not part of this repository.

**Solution:** start your debugger server, then set the URL before launching the
bridge:

```text
export GHIDRA_DEBUGGER_URL=http://127.0.0.1:8099
```

If the tools appear but every call reports that the server is not running,
the URL is wrong or the server is down. `GHIDRA_DEBUGGER_TOOLS=0` turns them off
again even with a URL configured.

### 500 Internal Server Errors

**Cause:** Server-side exception, often due to missing program data.

**Solution:**

1. Ensure a binary is loaded in CodeBrowser
2. Run auto-analysis first: **Analysis > Auto Analyze**
3. Check Ghidra console (**Window > Console**) for Java exceptions
4. Some operations require fully analyzed binaries

### 404 Not Found Errors

**Cause:** Endpoint doesn't exist or wrong URL.

**Solution:**

1. Verify the endpoint exists: `curl -s http://127.0.0.1:8089/mcp/schema` lists every tool the server advertises
2. Check for typos in endpoint name
3. Ensure you're using correct HTTP method (GET vs POST)
4. If a script or prompt calls a tool that worked before 7.0.0 (`decompile_function`, `list_functions`, `search_functions`, `get_function_callers`, `list_imports`, ...), it was consolidated: the [7.0.0 migration guide](docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md) names the replacement for every removed tool
5. Some routes exist on only one server: `/debugger/*` and `/tool/*` are GUI-only, and `/create_project`, `/close_project`, `/delete_project` and `/list_projects` are headless-only (see the API Reference)

### Python Ghidra scripts fail with "No script provider found"

**Cause:** In Ghidra 12.1.4, Jython support is no longer enabled by
default. `.py` scripts need the bundled Jython extension; Python 3
scripts should use PyGhidra instead of the Ghidra Script Manager.

**Solution:**

1. In the Ghidra Front End, open **File > Install Extensions**.
2. Check **Jython**, restart Ghidra, then refresh Script Manager.
3. For new automation, prefer Java Ghidra scripts or PyGhidra.

### Extension not appearing in Install Extensions

**Cause:** JAR file in wrong location.

**Solution:**

1. Manual install location: `~/.config/ghidra/ghidra_12.1.4_PUBLIC/Extensions/GhidraMCP/lib/GhidraMCP.jar`
   (`%APPDATA%\ghidra\...` on Windows, `~/Library/ghidra/...` on macOS)
2. Or use: **File > Install Extensions > Add** and select the ZIP file — see the
   [illustrated guide](docs/INSTALL_GUI.md)
3. Ensure JAR/ZIP was built for your Ghidra version

### Build fails with "Ghidra dependencies not found"

**Cause:** Ghidra JARs not installed in local Maven repository (Maven backend only; Gradle reads them straight from the installation).

**Solution:**

```text
# Windows (recommended)
python -m tools.setup install-ghidra-deps --ghidra-path "C:\ghidra_12.1.4_PUBLIC"
```

Under Gradle, a wall of `package ghidra.program.model.address does not exist`
errors instead means `-PGHIDRA_INSTALL_DIR` resolved to nothing — in Git Bash,
write the path with forward slashes.

## 📊 Production Performance

- **MCP Tools**: 209 tools fully implemented (the whole catalog; the GUI plugin serves 205 of them and the headless server 190)
- **Speed**: Sub-second response for most operations
- **Efficiency**: 93% reduction in API calls via batch operations
- **Reliability**: Atomic transactions with all-or-nothing semantics
- **AI Workflows**: Proven documentation prompts refined across hundreds of real functions
- **Deployment**: Automated version-aware deployment script

## 🛠️ API Reference

<!-- BEGIN GENERATED API REFERENCE (tools/gen_readme_api_reference.py) -->

209 MCP tools backed by HTTP endpoints, grouped by catalog category. Generated from [tests/endpoints.json](tests/endpoints.json) by `python -m tools.gen_readme_api_reference --write`; the live schema at `/mcp/schema` is authoritative at runtime. Usage patterns: [docs/prompts/TOOL_USAGE_GUIDE.md](docs/prompts/TOOL_USAGE_GUIDE.md).

186 of these are served by both the GUI plugin and the standalone headless server. The rest are marked **(GUI only)** (19) or **(headless only)** (4) — calling one against the other server returns a 404, not an error message. See `python -m tools.audit_server_scope` for how the split is derived.

### Program & Session Management

- `analysis_status` - Get auto-analysis status for open programs
- `close_program` - Close an open program by project path or name
- `create_memory_block` - Create memory block, optionally initialized with byte contents (hex or base64)
- `create_property_map` - Create a user property map to store typed values keyed by address
- `delete_bookmark` - Delete bookmark
- `delete_property_map` - Delete a user property map and all values it holds
- `exit_ghidra` - Save and exit Ghidra
- `get_address_spaces` - List all physical and overlay address spaces in the program (overlays include is_overlay flag and overlayed_space name)
- `get_language_metadata` - Dump the program's language description: address spaces, registers, default symbols, endianness, pointer size (issue #192)
- `get_metadata` - Get program metadata
- `get_program_options` - Read all options in a program option group with types, current values, defaults, and descriptions
- `get_property` - Read the value stored at an address in a property map
- `import_file` - Import a binary file from disk into the current Ghidra project and open it
- `list_bookmarks` - List bookmarks
- `list_open_programs` - List open programs
- `list_project_files` - List project files
- `list_properties` - List (address, value) entries stored in a property map, with pagination
- `list_scripts` - List available Ghidra scripts
- `open_program` - Open program from project
- `read_memory` - Read raw memory
- `reanalyze` - Trigger full auto-analysis on a program
- `remove_program_option` - Remove an option from a program option group
- `remove_property` - Remove the value stored at a single address in a property map
- `run_ghidra_script` - Run script with output capture
- `run_script_inline` - Run inline script code
- `save_all_programs` - Save all open programs
- `save_program` - Save current program
- `set_bookmark` - Set bookmark
- `set_image_base` - Set the base address of the program (rebases all addresses)
- `set_memory_block` - Change an existing memory block's permissions or volatility
- `set_program_option` - Set a typed program option
- `set_property` - Set a value at an address in a property map
- `switch_program` - Switch current program

### Project Organization

- `archive_project` - Archive the currently open project to a Ghidra-native .gar file
- `create_folder` - Create a folder in the project
- `delete_file` - Delete a file from the project
- `delete_project` - Delete a Ghidra project **(headless only)**
- `export_program` - Export an open or project-resident program to a Ghidra Zip File (.gzf)
- `get_project_info` - Get info about the currently open project
- `import_program` - Import a Ghidra Zip File (.gzf) into the currently open project as a new DomainFile under target_folder (default '/')
- `list_projects` - List available Ghidra projects **(headless only)**
- `move_file` - Move a program file to a different folder in the project, preserving analysis and documentation
- `move_folder` - Move a project folder and everything under it into another folder
- `restore_project` - Restore a Ghidra .gar archive into a fresh on-disk project at `parent_dir/project_name`

### Headless Project & Program Lifecycle

Available on the standalone headless server (`GhidraMCPHeadlessServer`).

- `close_project` - Close the currently open project **(headless only)**
- `create_project` - Create a new Ghidra project **(headless only)**
- `open_project` - Open an existing Ghidra project (.gpr file or directory)

### Listing & Enumeration

- `convert_number` - Convert number between bases
- `find_functions` - Find functions: every filter is optional, so with none it lists the whole program a page at a time
- `get_entry_points` - Get program entry points
- `get_external_location` - Get external location details
- `get_function_count` - Return the number of functions in the loaded program
- `list_calling_conventions` - List available calling conventions
- `list_data_items_by_xrefs` - List data sorted by xref count
- `list_globals` - List global variables
- `list_program_items` - List one kind of program inventory with pagination
- `list_shadowed_globals` - List named global DATA symbols that have NO type of their own because a larger data unit starting at an earlier address covers them
- `list_strings` - List defined strings
- `search_strings` - Search defined strings by a regex/substring pattern

### Current GUI Context

- `get_ui_cursor` - What the analyst is looking at right now: cursor address, the function under it, the listing selection, and the focused program — one call instead of four

### Functions: Decompile, Rename, Prototypes & Variables

- `add_function_tag` - Attach tags to ONE function (function + tags) OR MANY in one transaction (assignments=[{function,tags}, ...])
- `batch_rename_function_components` - Batch rename function components
- `clear_flow_and_repair` - Run Ghidra's GUI 'Clear Flow and Repair' action on a seed range: clears instruction flow reachable from the seed, then repairs function bodies and re-disassembles retained flow (ClearFlowAndRepairCmd with clear_data=false, clear_labels=false, repair=true)
- `clear_instruction_flow_override` - Clear flow override
- `create_function` - Create function at address
- `delete_function` - Delete function at address
- `delete_function_tag` - Delete a program-wide function tag definition
- `disassemble_bytes` - Disassemble byte range
- `disassemble_function` - Disassemble function
- `force_decompile` - Force fresh decompilation
- `get_functions` - Everything about one or many functions in a single call
- `list_class_members` - List the member functions of a C++ class
- `list_function_tags` - List all program-wide function tag definitions with their use counts
- `remove_function_tag` - Detach one or more tags from a function
- `rename_function` - Rename function by name
- `rename_variables` - Batch rename variables
- `set_function_no_return` - Set no-return attribute
- `set_function_prototype` - Set function prototype (return type, param types, calling convention)
- `set_function_tag_comment` - Update the comment/description on an existing program-wide function tag
- `set_function_this_type` - Set the decompiler/database type of the implicit 'this' pointer (ECX on x86 __thiscall/__fastcall)
- `set_variable_storage` - Set variable storage
- `set_variable_type` - Set the data type of a function variable (local OR parameter) by name at the decompiler (high-level) layer
- `set_variables` - Set types and names for multiple variables atomically

### Symbols, Labels & Globals

- `can_rename_at_address` - Check if address can be renamed
- `create_label` - Create label
- `delete_label` - Delete label at address
- `rename_symbol` - Rename a symbol of any kind

### Cross-References & Call Graphs

- `add_memory_reference` - Create a user-defined cross-reference between two memory addresses that the auto-analyzer can't infer (runtime-populated pointer tables, vtables, late-bound function pointers, missed jump/switch tables)
- `analyze_call_graph` - Analyze function call graph patterns
- `get_assembly_context` - Get assembly context
- `get_full_call_graph` - Get full call graph
- `get_function_call_graph` - Get call graph
- `get_xrefs_from` - Get references from address
- `get_xrefs_to` - Get references to address
- `remove_reference` - Remove memory cross-reference(s) from one address to another — the inverse of add_memory_reference

### Data Types & Structures

- `add_struct_field` - Add struct field
- `analyze_global_completeness` - Score a global variable's documentation completeness on a budgeted 0-100 scale — the data-address analog of analyze_function_completeness
- `analyze_struct_field_usage` - Analyze struct field usage
- `apply_data_classification` - Apply data classification
- `apply_data_type` - Apply data type
- `audit_global` - Audit a global variable's documentation state
- `audit_globals_in_function` - Audit every global variable referenced from within a function in one call
- `clone_data_type` - Clone data type
- `create_data_type_category` - Create data type category
- `create_derived_type` - Create a type built on another: a typedef alias, an array or a pointer
- `create_enum` - Create enumeration
- `create_function_signature` - Create function signature type
- `create_struct` - Create structure
- `create_union` - Create union
- `delete_data_type` - Delete data type
- `find_data_types` - Find data types by name or path pattern, category and kind, one record per type (name, kind, category, size, path)
- `get_enum_values` - Get enumeration values
- `get_struct_layout` - Get structure layout
- `get_type_size` - Get data type size and info
- `get_valid_data_types` - Get valid data type names
- `import_data_types` - Import data types from GDT
- `modify_struct_field` - Modify a field in a structure: retype it (new_type, which also embeds a struct by value, e.g
- `move_data_type_to_category` - Move data type to category
- `recreate_struct` - Replace a structure in one step: optionally remove an existing same-named type, then create with fields JSON (same shape as create_struct)
- `remove_struct_field` - Remove struct field
- `rename_data_type` - Rename a data type (struct, union, enum, typedef) in place, preserving existing applications of it
- `resize_struct` - Grow or shrink an existing structure by total byte size
- `resolve_duplicate_type` - Find duplicate data types by simple name; delete unused /Demangler size-1 stubs when a larger canonical type exists
- `set_global` - Atomically apply name + type + plate-comment + array length to a global variable
- `suggest_field_names` - Suggest field names
- `validate_data_type` - Validate data type syntax
- `validate_function_prototype` - Validate function prototype

### Comments

- `batch_set_comments` - Set multiple comments
- `clear_function_comments` - Clear all comments for a function
- `get_comment` - Get listing comments (plate/pre/eol/post/repeatable) at ANY address, including data addresses (works on functions and data globals alike), for ONE address (address=) or MANY in one call (addresses=a,b,c)
- `set_comment` - Set a listing comment of a given kind (plate/pre/eol/post/repeatable) at ANY address, including data addresses

### Analysis

- `analyze_control_flow` - Analyze control flow
- `analyze_data_region` - Analyze data region
- `analyze_dataflow` - Trace value propagation through a function (PCode graph, forward/backward)
- `analyze_for_documentation` - Composite RE documentation analysis (decompile + classify + variables + completeness)
- `analyze_function_complete` - Comprehensive single-call function analysis
- `analyze_function_completeness` - Analyze documentation completeness
- `apply_documentation` - Apply documentation to ONE function (fields at the top level) OR MANY (entries=[{address, ...}, ...])
- `configure_analyzer` - Configure an analysis plugin
- `detect_array_bounds` - Detect array bounds
- `find_code_gaps` - Find gaps of undefined bytes between functions in executable memory
- `find_dead_code` - Find dead code
- `find_next_undefined_function` - Find next undefined function
- `find_similar_functions` - Find similar functions
- `get_field_access_context` - Get field access context
- `get_function_pcode` - Dump raw P-code for a function (issue #192)
- `inspect_memory_content` - Inspect memory bytes
- `list_analyzers` - List available analysis plugins
- `run_analysis` - Run auto-analysis on the current program
- `search_byte_patterns` - Search for byte patterns
- `search_instructions` - Search for instructions by mnemonic and/or operand substring

### Malware & Anti-Analysis

- `analyze_api_call_chains` - Analyze API call chains
- `detect_crypto_constants` - Detect crypto constants
- `detect_malware_behaviors` - Detect malware behaviors
- `extract_iocs_with_context` - Extract IOCs with context
- `find_anti_analysis_techniques` - Find anti-analysis techniques

### Cross-Binary Documentation & Archive

- `archive_ingest_function` - Ingest a single function's documentation into the cross-version archive (the doc archive service configured via GHIDRA_MCP_ARCHIVE_URL)
- `archive_ingest_program` - Bulk-ingest every function in a program into the cross-version documentation archive
- `batch_string_anchor_report` - Report of source file strings and their FUN_* functions
- `bulk_fuzzy_match` - Bulk cross-binary function matching
- `compare_programs_documentation` - Compare documentation across programs
- `diff_functions` - Diff two functions
- `find_similar_functions_fuzzy` - Cross-binary fuzzy function matching
- `find_undocumented_by_string` - Find undocumented functions referencing string
- `get_function_documentation` - Export function documentation
- `get_function_hash` - Compute the normalized opcode hash of ONE function (function=), or of MANY in one call by omitting it: every function, paged, optionally only the documented or undocumented ones (filter=)
- `merge_program_documentation` - Bulk merge: copy all RE documentation (function names, signatures, plate comments, instruction comments at EOL/PRE/POST, non-default labels & global symbols) from one program to another at matching addresses

### Health, Schema & Tool Control

- `check_connection` - Liveness probe: {status, server_kind (gui/headless), version, program when one is current}
- `mcp_health` - Server health: kind (gui/headless), build, current program, uptime, HTTP pool, memory, endpoint count
- `mcp_schema` - Machine-readable API schema with endpoint metadata
- `tool_goto_address` - Navigate CodeBrowser listing and decompiler to a specific address **(GUI only)**
- `tool_running_tools` - List all running Ghidra tool windows **(GUI only)**

### Emulation

- `emulate_function` - Emulate a single function with controlled register/memory inputs
- `emulate_hash_batch` - Brute-force API hash resolution

### Ghidra Server & Version Control

- `checkin_program` - Check an open program back in to the shared Ghidra Server as a new version
- `server_admin_set_permissions` - Set user permissions on a repository
- `server_admin_terminate_all_checkouts` - Terminate all checkouts in a folder recursively
- `server_admin_terminate_checkout` - Terminate all checkouts on a single file
- `server_admin_users` - List all users on the server
- `server_authenticate` - Register server credentials for programmatic authentication
- `server_checkouts` - List all checked-out files in a folder, including server-side checkouts
- `server_connect` - Report/establish the Ghidra server connection
- `server_disconnect` - Disconnect from the Ghidra server
- `server_repositories` - List repositories on the connected server
- `server_repository_create` - Create a new repository on the server
- `server_repository_file` - Get file info from a server repository
- `server_repository_files` - List files in a server repository folder
- `server_status` - Check headless server connection status
- `server_version_control_add` - Add a file to version control
- `server_version_control_checkout` - Check out a version-controlled file
- `server_version_control_undo_checkout` - Undo a file checkout
- `server_version_history` - Get version history for a file

### Debugger (Ghidra TraceRmi)

When the bridge's opt-in WinDbg debugger proxies are enabled (`GHIDRA_DEBUGGER_URL` or `GHIDRA_DEBUGGER_TOOLS=1`), a TraceRmi tool below that shares a proxy's name gets a `_2` suffix (e.g. `debugger_status_2`), so both stay reachable.

- `debugger_dynamic_to_static` - Translate a runtime dynamic address from the current trace back to a static Ghidra program address **(GUI only)**
- `debugger_interrupt` - Interrupt (break into) the running target **(GUI only)**
- `debugger_launch` - Launch an executable through Ghidra's Trace RMI debugger launcher **(GUI only)**
- `debugger_launch_offers` - List available debugger launch/attach options for the current program **(GUI only)**
- `debugger_list_breakpoints` - List all breakpoints in the current trace **(GUI only)**
- `debugger_modules` - List modules (DLLs/EXEs) loaded in the debugged process **(GUI only)**
- `debugger_read_memory` - Read memory from the debugged process **(GUI only)**
- `debugger_registers` - Read CPU registers from the current debug trace snapshot **(GUI only)**
- `debugger_remove_breakpoint` - Remove a breakpoint at an address **(GUI only)**
- `debugger_resume` - Resume execution of the debugged process **(GUI only)**
- `debugger_set_breakpoint` - Set a software execution breakpoint at an address in the trace **(GUI only)**
- `debugger_stack_trace` - Get the call stack backtrace for the current thread **(GUI only)**
- `debugger_static_to_dynamic` - Translate a static Ghidra program address to a runtime dynamic address in the current trace **(GUI only)**
- `debugger_status` - Get debugger status: active trace, thread, execution state, module count **(GUI only)**
- `debugger_step` - Single-step the debugged process: into the next instruction (follows calls), over it (does not follow calls), or out of the current function (run to return) **(GUI only)**
- `debugger_traces` - List all open debug traces **(GUI only)**

### System

- `prompt_policy` - Temporarily enable, disable, or query scoped automation prompt handling **(GUI only)**

### Bridge Static Tools

Defined in the Python bridge itself (instance discovery, tool-group management); always available even before a Ghidra connection. The bridge can also proxy 22 `debugger_*` WinDbg tools to an external debugger server; they are off by default and register only when `GHIDRA_DEBUGGER_URL` is set or `GHIDRA_DEBUGGER_TOOLS=1`.

- `check_tools` - Report which tools are currently registered and callable
- `connect_instance` - Connect the bridge to a specific Ghidra instance
- `import_file` - Import a binary from disk into the current project and open it
- `list_instances` - Discover running Ghidra MCP instances (UDS + TCP port scan)
- `list_tool_groups` - List tool groups and their load state
- `load_tool_group` - Register a tool group's dynamic tools with the MCP client
- `search_tools` - Search the full tool catalog by keyword
- `unload_tool_group` - Unregister a tool group's dynamic tools

<!-- END GENERATED API REFERENCE -->

See [CHANGELOG.md](CHANGELOG.md) for version history.

## 🏗️ Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI/Automation │◄──►│   MCP Bridge    │◄──►│  Ghidra Plugin  │
│     Tools       │    │ (bridge_mcp_    │    │ (GhidraMCP.jar) │
│  (Claude, etc.) │    │  ghidra/)       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
   MCP Protocol            HTTP REST              Ghidra API
(stdio/streamable-http) (localhost:8089)      (Program, Listing)
```

### Components

- **python/bridge_mcp_ghidra/** — Python MCP server package (ships as the `ghidra-mcp-bridge` wheel; `bridge-mcp-ghidra` console script) that translates MCP protocol to HTTP calls (209 catalog entries)
- **GhidraMCP.jar** — Ghidra plugin that exposes analysis capabilities via HTTP (205 endpoints)
- **GhidraMCPHeadlessServer** — Standalone headless server — 190 endpoints, no GUI required
- **ghidra_scripts/** — Collection of automation scripts for common tasks

## 🔧 Development

### Building from Source

```bash
# Recommended: direct Python-first workflow
python -m tools.setup ensure-prereqs --ghidra-path "C:\ghidra_12.1.4_PUBLIC"
python -m tools.setup build
python -m tools.setup deploy --ghidra-path "C:\ghidra_12.1.4_PUBLIC"

# Version bump (updates all maintained version references atomically)
python -m tools.setup bump-version --new X.Y.Z
```

Both Java backends are maintained. Gradle (`./gradlew`, wrapper committed) is the default for local work and writes to `build/`; CI builds and gates with Maven, which writes to `target/`. `tools.setup` routes through Maven unless `TOOLS_SETUP_BACKEND=gradle`. Three things exist only under Maven: regenerating `tests/endpoints.json` (`mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`), the JaCoCo coverage gate, and the `headless`/`docker` build profiles.

### Command Reference

| Command | What it does |
| --------- | ------------- |
| `ensure-prereqs` | Install Python deps + Ghidra Maven JARs in one shot. Start here on a new machine. |
| `preflight` | Validate Python, build tool, Ghidra path, and JAR availability without making changes. Add `--strict` to also check network reachability. |
| `build` | Build the plugin JAR and extension ZIP via Maven (or Gradle when `TOOLS_SETUP_BACKEND=gradle`). |
| `deploy` | Copy the built extension into the Ghidra profile and patch `FrontEndTool.xml` for auto-activation. |
| `start-ghidra` | Launch the configured Ghidra installation. |
| `clean` | Remove the selected backend's build output (`target/`, or `build/` under Gradle). |
| `clean-all` | Remove build outputs plus local cache artifacts (`.m2` Ghidra JARs, etc.). |
| `install-ghidra-deps` | Install only the Ghidra JARs into `~/.m2`. Useful when the build environment changes. |
| `install-python-deps` | Install the Python dependency groups via `uv sync`. |
| `run-tests` | Run the backend's whole Java `test` task (`mvn test`, or `gradlew test` under Gradle). The integration classes in it need a live Ghidra on port 8089. |
| `verify-version` | Check `pom.xml`'s Ghidra version against the `--ghidra-path` installation (same major.minor series passes). |
| `bump-version --new X.Y.Z` | Atomically update all version references. Pass `--tag` to create a git tag. |

Common flags accepted by most commands:

| Flag | Description |
| ------ | ------------- |
| `--ghidra-path PATH` | Ghidra installation directory. Defaults to `GHIDRA_PATH` from `.env`. |
| `--dry-run` | Print actions without executing them. |
| `--force` | Reinstall Ghidra JARs even if already present (`install-ghidra-deps`, `ensure-prereqs`). |
| `--with-debugger` | Force-install debugger Python requirements (Windows only). |
| `--use-debugger-toggle` | Read `INSTALL_DEBUGGER_DEPS` from `.env` to decide whether to install debugger deps. |
| `--test TIER` | (`deploy` only) Opt into live deploy regression tiers such as `release` or `debugger-live`. |
| `--strict` | (`preflight` only) Also check network reachability for Maven Central and PyPI. |

Deploy test tiers are opt-in because benchmark tiers can import/reset
`Benchmark.dll` and `BenchmarkDebug.exe` in the active Ghidra project. Use
`--test release` before cutting releases, or set
`GHIDRA_MCP_DEPLOY_TESTS=release` in a local `.env` when you want every deploy
on your machine to run the live benchmark regression. The value is validated
against the same tier list `--test` accepts, and an unknown tier is refused
rather than skipped. See [Testing and Release Regression](docs/TESTING.md).

```text
# Standard first-time setup and deploy
python -m tools.setup ensure-prereqs --ghidra-path "C:\ghidra_12.1.4_PUBLIC"
python -m tools.setup build
python -m tools.setup deploy --ghidra-path "C:\ghidra_12.1.4_PUBLIC"

# Preflight check before deploying
python -m tools.setup preflight --strict --ghidra-path "C:\ghidra_12.1.4_PUBLIC"

# Version bump and tag
python -m tools.setup bump-version --new X.Y.Z --tag

# Run the Java test suite (integration classes need a live Ghidra)
python -m tools.setup run-tests

# Show full help
python -m tools.setup --help
```

### Project Structure

```text
ghidra-mcp/
├── pyproject.toml           # uv project (ghidra-mcp-bridge wheel + dependency groups)
├── python/bridge_mcp_ghidra/ # MCP server package (Python, 209 catalog entries)
├── src/main/java/           # Ghidra plugin + headless server (Java)
│   └── com/xebyte/
│       ├── GhidraMCPPlugin.java         # GUI plugin (205 endpoints)
│       ├── headless/                    # Headless server (190 endpoints)
│       └── core/                        # Shared service layer (`*Service.java`, `@McpTool`-annotated)
├── ghidra_scripts/          # Automation scripts for batch workflows
├── tests/                   # Python unit tests + endpoint catalog
│   ├── unit/               # Catalog consistency, schema, tool function tests
│   └── endpoints.json      # Endpoint catalog (the authoritative tool list)
├── docs/                    # Documentation
│   ├── prompts/            # AI workflow prompts (V5 documentation workflows)
│   ├── releases/           # Version release notes
│   └── project-management/ # Contributor planning docs (Gradle migration, etc.)
├── tools/setup/             # Build and deployment CLI (python -m tools.setup)
├── docker/                  # Headless server + bridge containers
└── .github/workflows/      # CI/CD pipelines
```

### Library Dependencies

Under the Maven backend, Ghidra JARs must be installed into your local Maven repository (`~/.m2/repository`) before compilation.
This is a one-time setup per machine, and again when your Ghidra version changes.
`ensure-prereqs` does it for you; Gradle needs no such step, because it reads the jars from the installation.

The tool enforces version consistency between:

- `pom.xml` (`ghidra.version`)
- `--ghidra-path` version segment (e.g., `ghidra_12.1.4_PUBLIC`)

If they are not in the same major.minor series, deployment fails fast with a clear error (a different patch release of the same series is accepted).

### Troubleshooting: Version Mismatch

If you see a version mismatch error, align both values:

1. `pom.xml` → `ghidra.version`
2. `--ghidra-path` version segment (`ghidra_X.Y.Z_PUBLIC`)

Then rerun:

```text
python -m tools.setup preflight --ghidra-path "C:\ghidra_12.1.4_PUBLIC"
```

```text
# Windows
python -m tools.setup install-ghidra-deps --ghidra-path "C:\path\to\ghidra_12.1.4_PUBLIC"
```

**Required Libraries (18 JARs, as listed in `tools/setup/ghidra.py`):**

| Library | Source Path | Purpose |
| --------- | ------------ | --------- |
| **Base.jar** | `Features/Base/lib/` | Core Ghidra functionality |
| **Decompiler.jar** | `Features/Decompiler/lib/` | Decompilation engine |
| **PDB.jar** | `Features/PDB/lib/` | Microsoft PDB symbol support |
| **FunctionID.jar** | `Features/FunctionID/lib/` | Function identification |
| **SoftwareModeling.jar** | `Framework/SoftwareModeling/lib/` | Program model API |
| **Project.jar** | `Framework/Project/lib/` | Project management |
| **Docking.jar** | `Framework/Docking/lib/` | UI docking framework |
| **Generic.jar** | `Framework/Generic/lib/` | Generic utilities |
| **Utility.jar** | `Framework/Utility/lib/` | Core utilities |
| **Gui.jar** | `Framework/Gui/lib/` | GUI components |
| **FileSystem.jar** | `Framework/FileSystem/lib/` | File system support |
| **Graph.jar** | `Framework/Graph/lib/` | Graph/call graph analysis |
| **DB.jar** | `Framework/DB/lib/` | Database operations |
| **Emulation.jar** | `Framework/Emulation/lib/` | P-code emulation |
| **Help.jar** | `Framework/Help/lib/` | Help system |
| **Debugger-api.jar** | `Debug/Debugger-api/lib/` | Debugger service API |
| **Framework-TraceModeling.jar** | `Debug/Framework-TraceModeling/lib/` | Debug trace model |
| **Debugger-rmi-trace.jar** | `Debug/Debugger-rmi-trace/lib/` | Trace RMI debugger connection |

> **Note**: Libraries are NOT included in the repository (see `.gitignore`). You must install them from your Ghidra installation before building.

<!-- two separate call-outs, not one blockquote (MD028) -->

> **Automation entry point**:
>
> - `python -m tools.setup` is the supported setup/build/deploy/versioning interface
> - use `ensure-prereqs`, `build`, `deploy`, `preflight`, `clean-all`, and `bump-version` directly
> - these commands use Maven unless `TOOLS_SETUP_BACKEND=gradle` is set

### Development Features

- **Automated Deployment**: Version-aware deployment script
- **Batch Operations**: Reduces API calls by 93%
- **Atomic Transactions**: All-or-nothing semantics
- **Comprehensive Logging**: Debug and trace capabilities

## 📚 Documentation

### Core Documentation

- [Documentation Index](docs/README.md) - Complete documentation navigation
- [Project Structure](docs/PROJECT_STRUCTURE.md) - Project organization guide
- [Testing and Release Regression](docs/TESTING.md) - Local tests, CI, live Ghidra regression, and release gates
- [Naming Conventions](docs/NAMING_CONVENTIONS.md) - Code naming standards
- [Hungarian Notation](docs/HUNGARIAN_NOTATION.md) - Variable naming guide

### AI Workflow Prompts

- [Function Documentation V5](docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md) — Primary workflow: 7-step process with Hungarian notation, type auditing, and verification scoring
- [Batch Documentation V5](docs/prompts/FUNCTION_DOC_WORKFLOW_V5_BATCH.md) — Parallel subagent dispatch for multi-function processing
- [Orphaned Code Discovery](docs/prompts/ORPHANED_CODE_DISCOVERY_WORKFLOW.md) — Automated scanner for undiscovered functions
- [Data Type Investigation](docs/prompts/DATA_TYPE_INVESTIGATION_QUICK.md) — Structure discovery and field analysis
- [Global Data Analysis](docs/prompts/GLOBAL_DATA_ANALYSIS_WORKFLOW.md) — Global naming and analysis
- [Quick Start Prompt](docs/prompts/QUICK_START_PROMPT.md) — Simplified beginner workflow
- [All Prompts](docs/prompts/README.md) — Complete prompt index

### Release History

- [Complete Changelog](CHANGELOG.md) - All version release notes
- [Release Notes](docs/releases/) - Detailed release documentation

## 🐳 Headless Server (Docker)

GhidraMCP includes a headless server mode for automated analysis without the Ghidra GUI.

### Quick Start with Docker

```bash
# Build and run (the compose files live in docker/). The token is required:
# the container binds 0.0.0.0, and the server refuses a non-loopback bind
# without one.
cd docker
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
docker compose up -d --build

# Test connection (/check_connection and /mcp/health need no token)
curl http://localhost:8089/check_connection
# {"status": "ok", "server_kind": "headless", "version": "7.0.0"}
```

This starts the headless server on `:8089` and the MCP bridge on `:8081`
(streamable-http at `/mcp`). See [docker/README.md](docker/README.md) for the
full deployment guide.

### Headless API Workflow

```bash
AUTH="Authorization: Bearer $GHIDRA_MCP_AUTH_TOKEN"

# 1. Import a binary into the open project (auto-analysis runs by default)
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
     -d '{"file_path": "/data/program.exe"}' http://localhost:8089/import_file

# 2. Re-run auto-analysis later if needed
curl -X POST -H "$AUTH" http://localhost:8089/run_analysis

# 3. List discovered functions
curl -H "$AUTH" "http://localhost:8089/find_functions?limit=20"

# 4. Decompile a function
curl -H "$AUTH" "http://localhost:8089/get_functions?function=0x401000&fields=decompiled_code"

# 5. Get metadata
curl -H "$AUTH" http://localhost:8089/get_metadata
```

### Key Headless Endpoints

| Endpoint | Method | Description |
| ---------- | -------- | ------------- |
| `/import_file` | POST | Import a binary into the project and open it |
| `/open_program` | POST | Open a program already in the project (any `program=` also opens on demand) |
| `/run_analysis` | POST | Run Ghidra auto-analysis |
| `/find_functions` | GET | List or filter discovered functions |
| `/list_program_items` | GET | `kind=imports`, `exports`, `segments`, `classes`, `namespaces`, `data_items` or `external_locations` |
| `/get_functions` | GET | Decompiled code, signature, callers, callees and more for one or many functions (`fields=` picks) |
| `/create_function` | POST | Create function at address |
| `/get_metadata` | GET | Get program metadata |
| `/create_project` | POST | Create a Ghidra project (headless only) |
| `/list_analyzers` | GET | List available analyzers |
| `/server/status` | GET | Check Ghidra Server connection |

### Configuration

Environment variables for Docker:

- `GHIDRA_MCP_AUTH_TOKEN` - Bearer token, **required** by the compose files (see above)
- `GHIDRA_MCP_PORT` - Server port (default: 8089)
- `GHIDRA_MCP_BIND_ADDRESS` - Bind address (default: 0.0.0.0 in Docker)
- `JAVA_OPTS` - JVM options (default: -Xmx4g -XX:+UseG1GC)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

### Quick Start

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Build and test your changes (`./gradlew buildExtension -PGHIDRA_INSTALL_DIR=/path/to/ghidra`, or `mvn clean package assembly:single -DskipTests` under the Maven backend)
4. Update documentation as needed
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏆 Production Status

| Metric | Value |
| -------- | ------- |
| **Version** | 7.0.0 |
| **MCP Tools** | 209 fully implemented |
| **GUI Endpoints** | 205 (GhidraMCPPlugin) |
| **Headless Endpoints** | 190 (GhidraMCPHeadlessServer) |
| **Compilation** | ✅ 100% success |
| **Batch Efficiency** | 93% API call reduction |
| **AI Workflows** | 7 proven documentation workflows |
| **Ghidra Scripts** | Automation scripts included |
| **Documentation** | Comprehensive with AI prompts |

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## 🙏 Acknowledgments

This project was originally derived from [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) in August 2025 and has since been substantially rewritten and extended. We acknowledge LaurieWired's original work as the starting point. See [NOTICE](NOTICE) for license attribution.

### Powered by

[![JetBrains logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg)](https://jb.gg/OpenSource)

Tooling provided by JetBrains through their [Open Source Support Program](https://jb.gg/OpenSource).

## 👥 Contributors

This project has benefited from the work of dedicated contributors:

### Core Contributors

**[@heeen](https://github.com/heeen)** — Significant contributions including:

- Fuzzy function matching and structured diff for cross-binary comparison (#13)
- Script execution improvements and bug fixes (#12)
- New API endpoints: `save_program`, `exit_ghidra`, `delete_function`, `create_memory_block`, `run_script_inline` (#11)
- Architectural vision: annotation-driven design, UDS transport, Python bridge optimization proposals

**[@huehuehuehueing](https://github.com/huehuehuehueing)** — Significant contributions including:

- Address-space prefix support — added `<space>:<hex>` syntax (e.g., `mem:1000`, `code:ff00`) to address parsing across the entire endpoint surface, unlocking multi-space targets like embedded firmware (#84, closes #65)
- Optional `program` parameter + required-param schema fixes — made `program` optional on every endpoint with a sane currentProgram fallback, and fixed several required-vs-optional schema bugs the catalog had inherited (#92)
- Seeded #44 (data-type / enum tools) — the issue that motivated the v5.0 enum + struct enforcement layer

- **Ghidra Team** - For the incredible reverse engineering platform
- **Model Context Protocol** - For the standardized AI integration framework
- **Contributors** - For testing, feedback, and improvements

---

## 🔗 Related Projects

- [re-universe](https://github.com/bethington/re-universe) — Ghidra BSim PostgreSQL platform for large-scale binary similarity analysis. Pairs perfectly with GhidraMCP for AI-driven reverse engineering workflows.
- [cheat-engine-server-python](https://github.com/bethington/cheat-engine-server-python) — MCP server for dynamic memory analysis and debugging.

---

**Ready for production deployment with enterprise-grade reliability and comprehensive binary analysis capabilities.**
