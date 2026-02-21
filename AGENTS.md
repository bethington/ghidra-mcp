# AGENTS.md — ghidra-mcp Project

You are a coding agent working on **ghidra-mcp**, a Model Context Protocol server that bridges Ghidra's reverse engineering capabilities with AI tools.

## Project Context

- **Repo**: https://github.com/bethington/ghidra-mcp
- **Version**: 2.0.2
- **Stars**: 877+ ⭐
- **Language**: Java (Ghidra extension) + Python (MCP bridge)
- **Key feature**: 110 MCP tools for binary analysis

## Directory Structure

- `src/` — Java source for Ghidra extension
- `scripts/` — Python MCP bridge and utilities  
- `docker/` — Container configurations
- `docs/` — Documentation
- `CHANGELOG.md` — Version history

## Current Priorities

1. Address Issue #9 — MCP bridge tools referencing non-existent endpoints
2. Address Issue #14 — Ghidra 12.0.3 compatibility (may be upstream)
3. Maintain CI/CD pipeline health
4. Community PR reviews

## Guidelines

- Run tests before committing: `./gradlew test`
- Follow existing code style
- Update CHANGELOG.md for user-facing changes
- Create PRs for review (don't push directly to main)

## Commands

- Build: `./gradlew build`
- Test: `./gradlew test`
- Docker: `docker compose up -d`
