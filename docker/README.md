# GhidraMCP Headless Server - Docker Deployment

Run GhidraMCP as a headless REST API server in Docker containers.

## Quick Start

### Single Instance

```bash
# Build and start
cd docker
docker-compose up -d

# Check status
curl http://localhost:8089/check_connection
```

### Multiple Instances with Load Balancer

```bash
# Start 3 instances with nginx load balancer
docker-compose -f docker-compose.multi.yml up -d --scale ghidra-mcp=3
```

## Building

### Build Docker Image

```bash
# From project root
docker build -t ghidra-mcp-headless:latest -f docker/Dockerfile .
```

### Build with Maven

```bash
# Build headless JAR
mvn clean package -P headless -DskipTests

# Build Docker image via Maven
mvn clean package -P docker -DskipTests
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_PORT` | `8089` | HTTP server port |
| `JAVA_OPTS` | `-Xmx4g -XX:+UseG1GC` | JVM options |
| `PROGRAM_FILE` | - | Path to binary file to load on startup |
| `PROJECT_PATH` | - | Path to Ghidra project directory |

### Volumes

| Volume | Container Path | Description |
|--------|---------------|-------------|
| `ghidra-data` | `/data` | Persistent data storage |
| `ghidra-projects` | `/projects` | Ghidra project files |

## API Endpoints

The headless server exposes the same REST API as the GUI plugin. Currently implemented:

### Health & Metadata
- `GET /check_connection` - Health check
- `GET /get_version` - Server version
- `GET /get_metadata` - Program metadata

### Listing
- `GET /list_methods` - List function names
- `GET /list_functions` - List functions with addresses
- `GET /list_classes` - List namespaces
- `GET /list_segments` - List memory segments
- `GET /list_imports` - List imports
- `GET /list_exports` - List exports
- `GET /list_data_items` - List defined data
- `GET /list_strings` - List defined strings
- `GET /list_data_types` - List data types

### Analysis
- `GET /decompile_function` - Decompile function
- `GET /disassemble_function` - Disassemble function
- `GET /get_function_by_address` - Get function info
- `GET /get_xrefs_to` - Get cross-references to address
- `GET /get_xrefs_from` - Get cross-references from address
- `GET /search_functions` - Search functions by name

### Modification (POST)
- `POST /rename_function` - Rename function by name
- `POST /rename_function_by_address` - Rename function by address
- `POST /rename_data` - Rename data label
- `POST /rename_variable` - Rename variable
- `POST /set_decompiler_comment` - Set PRE_COMMENT
- `POST /set_disassembly_comment` - Set EOL_COMMENT

### Program Management
- `GET /list_open_programs` - List loaded programs
- `GET /get_current_program_info` - Current program info
- `POST /switch_program` - Switch active program
- `POST /load_program` - Load program from file (headless only)
- `POST /close_program` - Close a program (headless only)

## Testing

### Run Integration Tests

```bash
# Install test requirements
pip install -r tests/requirements.txt

# Run tests against local server
python tests/run_tests.py --integration --server http://localhost:8089

# Run all tests with verbose output
python tests/run_tests.py --all -v
```

### Test Endpoint Coverage

```bash
# Run endpoint registration tests
pytest tests/integration/test_all_endpoints.py -v
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Container                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              GhidraMCPHeadlessServer                    │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐ │ │
│  │  │ HeadlessProgram  │  │ HeadlessEndpointHandler     │ │ │
│  │  │    Provider      │  │   (127 REST endpoints)      │ │ │
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

1. Load a program via API: `curl -X POST -d "file=/data/binary.exe" http://localhost:8089/load_program`
2. Or set `PROGRAM_FILE` environment variable

### Memory issues

1. Increase Java heap: `JAVA_OPTS=-Xmx8g`
2. Monitor usage: `docker stats ghidra-mcp`

## License

Apache License 2.0 - See LICENSE file
