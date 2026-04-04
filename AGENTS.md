# AGENTS.md — ghidra-mcp Project

You are a coding agent working on **ghidra-mcp**, a Model Context Protocol server that bridges Ghidra's reverse engineering capabilities with AI tools.

## Project Context

- **Repo**: https://github.com/bethington/ghidra-mcp
- **Version**: 5.0.0
- **Language**: Java (Ghidra extension) + Python (MCP bridge)
- **Key feature**: 193 MCP tools for binary analysis, knowledge database, BSim integration, headless server support, AI documentation workflows

## Directory Structure

- `src/` — Java source for Ghidra extension and headless server
- `bridge_mcp_ghidra.py` — Python MCP bridge (main entry point)
- `docs/` — Documentation and workflow prompts
- `tests/` — Python unit tests and endpoint catalog
- `CHANGELOG.md` — Version history

## Current Priorities

1. Maintain headless server parity with GUI plugin endpoints
2. Keep `tests/endpoints.json` in sync with Java endpoint registrations
3. Maintain CI/CD pipeline health
4. Community PR reviews

## Guidelines

- Run tests before committing: `pytest tests/unit/ -v --no-cov`
- Build: `mvn clean package assembly:single -DskipTests`
- Quick compile check: `mvn clean compile -q`
- Follow existing code style
- Update CHANGELOG.md for user-facing changes
- Create PRs for review (don't push directly to main)
- Use `bump-version.ps1 -New X.Y.Z` to bump version across all files atomically

## Commands

- Build: `mvn clean package assembly:single -DskipTests`
- Quick compile: `mvn clean compile -q`
- Test (Python): `pytest tests/unit/ -v --no-cov`
- Deploy: `.\ghidra-mcp-setup.ps1`
- Version bump: `.\bump-version.ps1 -New X.Y.Z`
