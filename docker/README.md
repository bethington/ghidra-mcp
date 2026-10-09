# GhidraMCP - Docker Deployment

Run GhidraMCP in Docker: the headless REST API server on `:8089`, and the
MCP bridge on `:8081` for MCP clients.

> **⚠️ `GHIDRA_MCP_AUTH_TOKEN` is required to run this stack at all.**
> `entrypoint.sh` binds `0.0.0.0` by default and
> `SecurityConfig.requireAuthForNonLoopbackBind` **refuses a non-loopback bind
> without this token**, so an unset token is not a weaker deployment — it is a
> container that starts and dies. The API exposes file import, project mutation
> and — if `GHIDRA_MCP_ALLOW_SCRIPTS=1` — arbitrary code, so that refusal is
> the right default.
>
> ```bash
> export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
> # compose passes it to BOTH containers; send it as
> #   Authorization: Bearer <token>   on every request
> ```
>
> The compose files take it with `${GHIDRA_MCP_AUTH_TOKEN:?...}`, so forgetting
> it is a one-line compose error rather than a failure you have to read a
> container log to find. Both images run as non-root (`ghidra`, `bridge`).

## Quick Start

### Single Instance

`GHIDRA_MCP_AUTH_TOKEN` is **required**, not optional — see the box above. The
compose file uses the `${VAR:?}` form, so a missing token is one line at the
prompt rather than a container that builds, starts and dies in its own log.

```bash
cd docker
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
docker compose up -d --build

# Ghidra REST API. /check_connection and /mcp/health need no token;
# every other route does.
curl http://localhost:8089/check_connection
curl -H "Authorization: Bearer $GHIDRA_MCP_AUTH_TOKEN" \
  http://localhost:8089/get_metadata
```

That brings up **two** containers:

| Container | Port | Speaks |
| --- | --- | --- |
| `ghidra-mcp` | 8089 | the plugin's plain HTTP API |
| `ghidra-mcp-bridge` | 8081 | MCP over streamable-http, at `/mcp` |

### Connecting an MCP client

Point the client at `http://localhost:8081/mcp`. Every client request must
carry the same token the stack was started with — the bridge rejects anything
else with `401`:

```text
Authorization: Bearer <GHIDRA_MCP_AUTH_TOKEN>
```

That is not belt-and-braces. The bridge binds `0.0.0.0` inside the container
(a published port cannot reach a loopback bind) and it holds a token it
forwards to Ghidra — an unauthenticated bridge in that position is a confused
deputy: anyone who can reach `:8081` drives Ghidra with the bridge's
credentials.

### Why the bridge has no `ports:` and no `networks:`

`validate_server_url()` in `python/bridge_mcp_ghidra/validation.py` refuses any
Ghidra URL whose host is not loopback, so the obvious Compose spelling —
`http://ghidra-mcp:8089` — is rejected by the bridge before a socket is opened.
The bridge speaks plain HTTP with no TLS and forwards a bearer token, so it is
deliberately not allowed to send either across a network.

The bridge therefore runs with `network_mode: "service:ghidra-mcp"`, sharing
the Ghidra container's network namespace, which is what makes `127.0.0.1:8089`
mean the Ghidra server. A container in someone else's namespace has no network
stack to publish from, so **its port is published on the `ghidra-mcp` service**
instead. `docker compose config` does not catch a `ports:` entry on such a
service — it validates cleanly and fails at `up`.

`tests/unit/test_docker_compose_bridge.py` pins all of this, including
asserting the configured `GHIDRA_MCP_URL` against the real
`validate_server_url()` rather than a restatement of its rule. It needs no
Docker daemon, which is the point: the daemon is exactly what CI does not have.

### Multiple Instances with Load Balancer

```bash
# Start 3 instances with nginx load balancer
docker compose -f docker-compose.multi.yml up -d --scale ghidra-mcp=3
```

This topology has **no bridge**, deliberately. `network_mode: "service:X"`
names one container and cannot target a scaled service, and `nginx.conf`
balances with `least_conn` and no session affinity — so a bridge in front of it
would hand consecutive MCP tool calls to different Ghidra instances holding
different projects, with a `decompile` and the `rename` that follows it not
talking about the same program. Serving MCP from a scaled deployment needs a
topology decision, not a service block copied from the single-instance file.

## Building

### Build Docker Image

```bash
# From project root
docker build -t ghidra-mcp-headless:latest -f docker/Dockerfile .
docker build -t ghidra-mcp-bridge:latest   -f docker/Dockerfile.bridge .
```

Both build from the repository root as context. `Dockerfile.bridge` copies
`pyproject.toml`, `README.md` and `python/`, then `pip install .` — the
top-level `README.md` is not decoration, hatchling reads it and the wheel build
fails without it.

### Build with Maven

These two are **Maven-only**: `headless` and `docker` are `pom.xml` profiles and
`build.gradle` registers no equivalent task. Gradle's `buildExtension` produces
the GUI extension zip, not the headless assembly or the container image — so
even though Gradle is the default backend for ordinary builds, these need Maven.

```bash
# Build headless JAR
mvn clean package -P headless -DskipTests

# Build Docker image via Maven
mvn clean package -P docker -DskipTests
```

## Configuration

### Environment Variables

| Variable | Default | Description |
| ---------- | --------- | ------------- |
| `GHIDRA_MCP_AUTH_TOKEN` | - (required) | Bearer token for every route except `/check_connection` and `/mcp/health` |
| `GHIDRA_MCP_PORT` | `8089` | HTTP server port |
| `GHIDRA_MCP_BIND_ADDRESS` | `0.0.0.0` | Bind address |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | unset | `1` enables `/run_script_inline` and `/run_ghidra_script` (arbitrary code) |
| `GHIDRA_MCP_FILE_ROOT` | unset | Confine filesystem-path endpoints such as `/import_file` to this directory |
| `JAVA_OPTS` | `-Xmx4g -XX:+UseG1GC` | JVM options |
| `PROGRAM_FILE` | - | Path to binary file to load on startup |
| `PROJECT_PATH` | - | Path to Ghidra project directory |
| `GHIDRA_USER` | - | Passed as `-Duser.name`, to open a project owned by that user |
| `GHIDRA_SERVER_HOST` / `GHIDRA_SERVER_PORT` / `GHIDRA_SERVER_USER` | - | Shared Ghidra Server connection (port defaults to 13100) |

### Volumes

| Volume | Container Path | Description |
| -------- | --------------- | ------------- |
| `ghidra-data` | `/data` | Persistent data storage |
| `ghidra-projects` | `/projects` | Ghidra project files |

## API Endpoints

The headless server serves the catalog in `tests/endpoints.json` except for the
GUI-only routes (`/debugger/*`, `/tool/*`, `/prompt_policy`), plus a few
project-lifecycle routes of its own (`/create_project`, `/close_project`,
`/delete_project`, `/list_projects`). The full list, marked per server, is the
API Reference in the [root README](../README.md); the running server's
`/mcp/schema` is authoritative. A starting set:

### Health & Metadata

- `GET /check_connection` - Liveness: `{status, server_kind, version}`, plus `program` when one is current
- `GET /mcp/health` - Build, uptime, HTTP pool, memory, endpoint count
- `GET /get_metadata` - Program metadata

### Listing

- `GET /find_functions` - List functions a page at a time, or filter by name, xrefs, tag, calling convention
- `GET /list_program_items?kind=...` - `imports`, `exports`, `segments`, `classes`, `methods`, `namespaces`, `data_items` or `external_locations`
- `GET /list_strings` - List defined strings
- `GET /find_data_types` - List or search data types

### Analysis

- `GET /get_functions` - One or many functions: decompiled code, signature, callers, callees, comments (`fields=` picks)
- `GET /disassemble_function` - Disassemble function
- `GET /get_xrefs_to` - Get cross-references to an address (`addresses=` for several)
- `GET /get_xrefs_from` - Get cross-references from address

### Modification (POST)

- `POST /rename_function` - Rename a function (`function=` takes a name or an address)
- `POST /rename_symbol` - Rename data label
- `POST /rename_variables` - Rename variables
- `POST /set_comment` - Set a comment; `type=` is `plate`, `pre`, `post`, `eol` or `repeatable`

### Program Management

- `GET /list_open_programs` - List loaded programs
- `GET /get_project_info` - Info about the currently open project
- `POST /switch_program` - Switch active program
- `POST /import_file` - Import a binary into the project and open it
- `POST /open_program` - Open a program from the project (any `program=` also opens on demand)
- `POST /close_program` - Close a program (`save=false` discards its unsaved edits)

## Testing

### Run Integration Tests

```bash
# Install test requirements (the `test` dependency group in pyproject.toml)
uv sync --group test

# Run integration tests against a server
uv run python tests/run_tests.py --integration --server http://localhost:8089

# Endpoint registration tests only
uv run pytest tests/integration/test_all_endpoints.py -v
```

The integration suite does not send a bearer token, so against this compose
stack (which requires one) every route other than `/check_connection` and
`/mcp/health` answers `401`. Run it against a server started without
`GHIDRA_MCP_AUTH_TOKEN` on a loopback bind instead.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     Docker Container                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              GhidraMCPHeadlessServer                    │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐ │ │
│  │  │ HeadlessProgram  │  │ AnnotationScanner services  │ │ │
│  │  │    Provider      │  │   (/mcp/schema lists them)  │ │ │
│  │  └──────────────────┘  └─────────────────────────────┘ │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐ │ │
│  │  │ DirectThreading  │  │     Ghidra Headless         │ │ │
│  │  │    Strategy      │  │    (Analysis Engine)        │ │ │
│  │  └──────────────────┘  └─────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
│              Port 8089 ─────────────────────────────────────┼──▶ HTTP API
└─────────────────────────────────────────────────────────────┘

Multi-Instance Setup:
┌─────────────┐     ┌─────────────────────────────────────────┐
│   Client    │────▶│  Nginx Load Balancer (Port 8089)        │
└─────────────┘     └──────┬──────────┬──────────┬────────────┘
                           │          │          │
                    ┌──────▼───┐┌─────▼────┐┌────▼─────┐
                    │Instance 1││Instance 2││Instance 3│
                    │ (8089)   ││ (8089)   ││ (8089)   │
                    └──────────┘└──────────┘└──────────┘
```

## Troubleshooting

### Server won't start

1. Check if port 8089 is in use: `netstat -an | grep 8089`
2. Check Docker logs: `docker logs ghidra-mcp`
3. Verify Ghidra home: `docker exec ghidra-mcp ls /opt/ghidra`

### No program loaded

1. Import a program via API: `curl -X POST -H "Authorization: Bearer $GHIDRA_MCP_AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"file_path": "/data/binary.exe"}' http://localhost:8089/import_file`
2. Or set `PROGRAM_FILE` environment variable

### Memory issues

1. Increase Java heap: `JAVA_OPTS=-Xmx8g`
2. Monitor usage: `docker stats ghidra-mcp`

## License

Apache License 2.0 - See LICENSE file
