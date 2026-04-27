# RFC: Opt-in Ghidra Recovery and Relaunch

**Status**: Draft for community review  
**Audience**: Ghidra MCP users, contributors, and automation workflow authors  
**Scope**: Python MCP bridge recovery orchestration plus Java health/status detail

## Summary

Ghidra MCP currently reports failures cleanly when the bridge cannot reach Ghidra, but unattended workflows can get stuck in repeated `ghidra_offline` results until a human restarts Ghidra and reconnects the bridge.

This RFC proposes an opt-in recovery system that can detect when Ghidra is unavailable, retry transient failures, restart the bridge connection path, gracefully shut down and relaunch Ghidra when configured to do so, and reopen the last known project/program or explicit project/program settings.

The default behavior should remain conservative: no automatic Ghidra restart unless the user explicitly enables it.

## Problem

Long-running documentation, decompilation, and batch-analysis jobs can fail repeatedly when:

- Ghidra is closed.
- Ghidra is running but the MCP endpoint is unreachable.
- The Java MCP server or HTTP transport is wedged.
- A previous decompile or analysis request times out and leaves the workflow in an offline loop.

Typical symptoms look like:

```text
Complete: ghidra_offline
Complete: ghidra_offline
Complete: decompile_timeout
Complete: ghidra_offline
```

For interactive users, automatic restarts can be dangerous because Ghidra may have unsaved GUI state. For unattended users, not restarting can waste hours of runtime. The recovery behavior needs to be opt-in, configurable, and careful about process ownership.

## Goals

- Detect Ghidra accessibility using the real MCP/Ghidra health path.
- Use OS process detection only to decide whether to launch, reconnect, or shut down.
- Retry briefly before taking disruptive action.
- Restart or reconnect the Python bridge path before restarting Ghidra.
- Gracefully ask Ghidra to exit before force-killing anything.
- Reopen the last known project/program, with explicit overrides available.
- Fail the current MCP call quickly with `ghidra_offline` and recover in the background.
- Keep automatic recovery disabled by default.
- Preserve GUI/headless parity where practical.

## Non-goals

- Do not hide long restart delays inside one MCP tool call.
- Do not queue and replay arbitrary failed MCP calls.
- Do not force-kill unrelated Ghidra sessions by default.
- Do not require recovery features for normal interactive use.

## Proposed Defaults

```text
auto recovery: disabled
watchdog mode: confirm-failures
process ownership: launched-only
force kill: allowed only for bridge-launched Ghidra by default
failure threshold: 3 ghidra_offline failures in 60 seconds
watchdog interval: 15 seconds
graceful shutdown timeout: 20 seconds
```

## Proposed Configuration

Add bridge CLI flags and matching environment variables where appropriate:

```text
--auto-recover-ghidra
--ghidra-path PATH
--project PATH_OR_NAME
--program PROJECT_FILE_PATH
--recovery-state PATH
--recovery-failure-threshold 3
--recovery-failure-window-seconds 60
--watchdog-mode observe-only|confirm-failures|active-recover
--watchdog-interval-seconds 15
--process-ownership launched-only|matching-command|any-ghidra
--graceful-shutdown-timeout-seconds 20
--force-kill-after-timeout
```

Recommended environment variable names:

```text
GHIDRA_MCP_AUTO_RECOVER
GHIDRA_MCP_GHIDRA_PATH
GHIDRA_MCP_PROJECT
GHIDRA_MCP_PROGRAM
GHIDRA_MCP_RECOVERY_STATE
GHIDRA_MCP_WATCHDOG_MODE
GHIDRA_MCP_PROCESS_OWNERSHIP
```

## Health Model

Recovery should use two independent signals:

```text
accessibility = /mcp/health or /mcp/instance_info responds quickly
process state = OS process detection says whether a Ghidra process exists
```

Accessibility is the source of truth. A running process does not prove Ghidra MCP is usable.

Useful existing hooks:

- Python bridge UDS/TCP routing in `bridge_mcp_ghidra.py`
- Python `discover_instances()`
- Python `_try_reconnect()`
- Python `dispatch_get()` and `dispatch_post()`
- Java `/mcp/health`
- Java `/mcp/instance_info`
- Java `/exit_ghidra`

## Last Known Project and Program

Java should report the authoritative active project/program while Ghidra is healthy. The Python bridge should persist that state so recovery still has enough context after Ghidra goes offline.

Example recovery state:

```json
{
  "updated_at": "2026-04-25T22:30:00Z",
  "transport": "uds",
  "pid": 12345,
  "launched_by_bridge": true,
  "ghidra_path": "F:/ghidra_12.0.4_PUBLIC",
  "project": "MyProject",
  "project_path": "C:/Users/benam/ghidra/projects/MyProject.gpr",
  "program": "/Mods/PD2-S12/D2Common.dll",
  "socket": "...",
  "tcp_url": "http://127.0.0.1:8089"
}
```

Explicit `--project` and `--program` settings should override persisted state.

## Recovery Flow

When a tool call fails because Ghidra is unreachable:

```text
1. Record a ghidra_offline event.
2. If the threshold is reached, schedule background recovery.
3. Return the current MCP response immediately:
   {"error": "ghidra_offline", "recovering": true}
4. Let the caller retry after recovery completes.
```

Background recovery:

```text
1. Try to reconnect to an existing Ghidra MCP instance.
2. Probe known UDS/TCP instances.
3. If configured and policy allows, POST /exit_ghidra.
4. Wait for graceful shutdown.
5. If still alive and policy allows, terminate or kill the process.
6. Launch Ghidra using:
   - explicit --ghidra-path first
   - PATH lookup second
   - optional auto-discovery third
7. Wait for /mcp/health or /mcp/instance_info.
8. Fetch /mcp/schema and reconnect the bridge.
9. Reopen the explicit or last-known project/program.
```

## Watchdog Modes

```text
observe-only
  Health check and log, but never recover automatically.

confirm-failures
  Recover only when the watchdog sees unhealthy Ghidra and recent tool calls
  have crossed the configured failure threshold.

active-recover
  Recover whenever watchdog health checks fail.
```

Recommended default: `confirm-failures`.

## Process Ownership Policies

```text
launched-only
  The bridge only restarts a Ghidra process that it launched and recorded.

matching-command
  The bridge may restart a process whose command line matches configured
  project/program or launch markers.

any-ghidra
  The bridge may restart any detected Ghidra process.
```

Recommended default: `launched-only`.

## Java Health/Status Additions

Enhance `/mcp/instance_info` or `/mcp/health` to include richer recovery state:

```json
{
  "status": "ok",
  "mode": "gui",
  "project": "MyProject",
  "project_path": "...",
  "open_programs": [
    {
      "name": "D2Common.dll",
      "project_path": "/Mods/PD2-S12/D2Common.dll",
      "language_id": "x86:LE:32:default"
    }
  ],
  "current_program": "/Mods/PD2-S12/D2Common.dll",
  "busy": false,
  "active_requests": 0
}
```

## Proposed Implementation Shape

Keep recovery code isolated instead of growing the bridge dispatch functions:

```text
bridge_mcp_ghidra.py
recovery/
  config.py
  state.py
  health.py
  process.py
  manager.py
```

Bridge integration points:

```text
dispatch_get() / dispatch_post()
  Record offline failures and maybe schedule recovery.

connect_instance() / successful health check
  Persist last-known-good state.

main()
  Parse recovery config and start watchdog if enabled.
```

## Testing Plan

Unit tests should not require a live Ghidra instance.

Suggested files:

```text
tests/unit/test_recovery_config.py
tests/unit/test_recovery_state.py
tests/unit/test_recovery_manager.py
tests/unit/test_recovery_process.py
```

Core cases:

- Threshold triggers after N failures in the configured window.
- A single transient failure does not restart Ghidra.
- Watchdog `observe-only` never recovers.
- Watchdog `confirm-failures` requires recent failures.
- `launched-only` never kills unrelated Ghidra processes.
- Explicit project/program config overrides state-file values.
- The current MCP call returns `ghidra_offline` without blocking on restart.
- Successful Java health updates the recovery state.

## Open Questions for Review

1. Should the first implementation support GUI relaunch only, or GUI and headless together?
2. What is the safest cross-platform way to identify Ghidra processes without surprising users?
3. Should `--force-kill-after-timeout` default to true only for bridge-launched processes?
4. Should active recovery ever be enabled by default in headless mode?
5. Which endpoint should own the richer state: `/mcp/health`, `/mcp/instance_info`, or a new `/mcp/recovery_state`?
6. How should Ghidra project reopening work across platforms and Ghidra versions?
7. Should read-only MCP tools get an optional one-time retry after recovery in a later phase?
8. What telemetry/log messages would make this understandable without becoming noisy?

## Suggested Review Prompt

Use this text when opening a GitHub Discussion or issue:

```markdown
We are considering an opt-in recovery system for Ghidra MCP when Ghidra becomes unreachable during long-running automation.

The proposed design keeps recovery disabled by default, uses MCP health endpoints as the source of truth, retries briefly, reconnects the bridge first, gracefully shuts down Ghidra before any force-kill, and relaunches/reopens the last known project/program only when configured.

Please review the RFC and comment especially on:

- Whether the defaults are conservative enough for GUI users.
- Whether the process ownership policies cover your workflows.
- How you would expect project/program reopening to work.
- Whether headless mode should share the same recovery path.
- Any failure modes you have seen in real Ghidra MCP usage.
```

## Phased Rollout

### Phase 1: RFC and Feedback

- Publish this document.
- Open a GitHub Discussion for user feedback.
- Collect real workflow examples and failure modes.

### Phase 2: Python Recovery Skeleton

- Add config parsing, state file, failure tracking, and watchdog modes.
- Implement reconnect-first behavior.
- Keep Ghidra launch/restart behind explicit opt-in.

### Phase 3: Java Health Detail

- Add richer project/program fields to Java health or instance info.
- Keep GUI/headless fields aligned where practical.

### Phase 4: Relaunch and Reopen

- Add launch path resolution.
- Add process ownership enforcement.
- Add graceful shutdown and timeout handling.
- Reopen explicit or persisted project/program.

### Phase 5: Hardening

- Add platform-specific process tests.
- Add docs and examples.
- Consider optional one-time retry for read-only tools.

