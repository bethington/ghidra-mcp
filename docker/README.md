# GhidraMCP Docker - Full MCP Server

Run GhidraMCP as a fully functional MCP server in Docker. The container includes both the Ghidra headless analysis engine and the MCP protocol bridge, allowing LLM clients to connect directly and perform binary analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Container                             │
│                                                                     │
│  ┌───────────────────────────┐    ┌──────────────────────────────┐  │
│  │   bridge_mcp_ghidra.py    │    │  GhidraMCPHeadlessServer     │  │
│  │   (MCP Protocol Bridge)   │───▶│  (Ghidra Analysis Engine)    │  │
│  │                           │    │                              │  │
│  │  - 193 MCP tools          │    │  - Program/project mgmt     │  │
│  │  - SSE transport          │    │  - Auto-analysis             │  │
│  │  - Tool validation        │    │  - Decompilation             │  │
│  └───────────┬───────────────┘    └──────────────────────────────┘  │
│              │                              │                       │
│        Port 8081 (MCP SSE)           Port 8089 (HTTP API)          │
└──────────────┼──────────────────────────────┼───────────────────────┘
               │                              │
          LLM Clients                   Debug/Direct Access
```

## Quick Start

### Single Instance

```bash
# Build and start
cd docker
docker-compose up -d

# Verify the server is running
curl http://localhost:8089/check_connection
```

The MCP server is available at `http://localhost:8081/sse`.

### Connect an MCP Client

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8081/sse"
    }
  }
}
```

**Claude Code** (`.mcp.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8081/sse"
    }
  }
}
```

### Multiple Instances with Load Balancer

```bash
# Start 3 instances with nginx load balancer
docker-compose -f docker-compose.multi.yml up -d --scale ghidra-mcp=3
```

## Usage Workflow

Once connected, the LLM can perform the full reverse engineering workflow through MCP tools:

1. **Create a project**: `create_project` - Create a Ghidra project for organizing binaries
2. **Import a binary**: `load_program` - Import a binary file for analysis (mount binaries via volumes)
3. **Auto-analyze**: Analysis runs automatically on import
4. **Explore**: `list_functions`, `list_strings`, `list_imports`, `list_exports`
5. **Analyze**: `decompile_function`, `disassemble_function`, `get_xrefs_to`
6. **Annotate**: `rename_function`, `rename_variable`, `set_decompiler_comment`
7. **Deep analysis**: `analyze_control_flow`, `find_anti_analysis`, `extract_iocs`

All 193 MCP tools are available. See the main project README for the complete tool reference.

### Mounting Binaries

To analyze local binaries, mount them into the container:

```yaml
# In docker-compose.yml
volumes:
  - ./my-binaries:/binaries:ro
```

Then use the `load_program` tool to import `/binaries/target.exe`.

## Building

### Build Docker Image

```bash
# From project root
docker build -t ghidra-mcp:latest -f docker/Dockerfile .
```

### Build with Maven

```bash
# Build headless JAR only
mvn clean package -P headless -DskipTests

# Build Docker image via Maven
mvn clean package -P docker -DskipTests
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_PORT` | `8089` | Ghidra HTTP server port (internal) |
| `JAVA_OPTS` | `-Xmx4g -XX:+UseG1GC` | JVM options |
| `MCP_TRANSPORT` | `sse` | MCP transport: `sse` or `stdio` |
| `MCP_HOST` | `0.0.0.0` | MCP SSE listen address |
| `MCP_PORT` | `8081` | MCP SSE listen port |
| `ENABLE_MCP_BRIDGE` | `true` | Set `false` for HTTP-only mode (no MCP) |
| `PROGRAM_FILE` | - | Path to binary file to load on startup |
| `PROJECT_PATH` | - | Path to Ghidra project directory |
| `GHIDRA_USER` | - | Override user for project ownership |

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| `8081` | MCP SSE | Primary interface for LLM clients |
| `8089` | HTTP | Ghidra REST API (debugging/direct access) |

### Volumes

| Volume | Container Path | Description |
|--------|---------------|-------------|
| `ghidra-data` | `/data` | Persistent data storage |
| `ghidra-projects` | `/projects` | Ghidra project files |

## HTTP-Only Mode

To run without the MCP bridge (original behavior, REST API only):

```bash
docker run -p 8089:8089 -e ENABLE_MCP_BRIDGE=false ghidra-mcp:latest
```

## Troubleshooting

### Server won't start

1. Check Docker logs: `docker logs ghidra-mcp`
2. Check if ports are in use: `netstat -an | grep -E '8081|8089'`
3. Verify Ghidra installation inside container: `docker exec ghidra-mcp ls /opt/ghidra`

### MCP bridge won't connect

1. The bridge waits up to 120 seconds for the Ghidra server to start
2. Check that port 8089 isn't blocked inside the container
3. Verify bridge logs: `docker logs ghidra-mcp 2>&1 | grep -i bridge`

### No program loaded

1. Mount binaries and use `load_program` tool: mount a directory to `/binaries`
2. Or set `PROGRAM_FILE` environment variable for auto-loading
3. Use `create_project` to organize binaries into Ghidra projects

### Memory issues

1. Increase Java heap: `JAVA_OPTS=-Xmx8g`
2. Monitor usage: `docker stats ghidra-mcp`
3. Container default limit is 6GB; increase in docker-compose if needed

## License

Apache License 2.0 - See LICENSE file
