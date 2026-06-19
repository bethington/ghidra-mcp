# VulnAnalysisService Phase 2 — `find_taint_path` (backward inter-procedural taint)

**Date:** 2026-06-19
**Status:** Approved
**Branch:** `feature/vuln-analysis-service` (fork-only)
**Predecessors:** `2026-06-17-vuln-analysis-service-design.md`, `2026-06-18-vuln-phase-1.5-design.md`

## Problem

Phase 1 detectors flag intra-function candidates (e.g. `unbounded_copy` at
`dnp_modbus.Initial::00015df4`, 2 hops from `recv`). The SEVR triage question
is: **does the dangerous argument actually trace back to attacker-controlled
input?** Phase 1's `PcodeQuery` walks stop at CALL boundaries, so it cannot
answer that. Phase 2 adds a backward inter-procedural taint tracer.

**Live driver (Application1.elf):** after Phase 1.5, `scope=attack_surface`
returns one candidate — `memcpy(dst, src, n)` at `00015df4` where `n` is
`UNNAMED (non-constant, no observed bound check)`. Phase 2 answers whether
`n` reaches `recv`'s output buffer.

## Decisions (from brainstorming)

1. **Entry point:** backward triage from a sink call-site argument. New
   `/find_taint_path(address, arg_role)` tool + opt-in `taint=true` on
   `detect_vuln_patterns`.
2. **Memory propagation:** value-flow (SSA) **plus** "LOAD from tainted
   buffer" — a LOAD whose address derives intra-function from a catalog
   source's `out_arg` buffer (or `return:true` return value) is tainted.
   STORE→LOAD pairing and inter-function buffer aliasing are out of scope.
3. **Auto-taint:** opt-in via `detect_vuln_patterns(taint=true,
   taint_max_depth=N)`. Off by default; standalone `find_taint_path` for
   ad-hoc triage.
4. **Architecture:** approach A — stateful `TaintTracer` class owning a
   `HighFunction` cache, used by `VulnAnalysisService`.

## Architecture

```
com.xebyte.core.vuln/
├── TaintTracer.java     backward inter-proc walk; owns DecompInterface +
│                         Map<Function, HighFunction> cache
├── TaintResult.java     record(CatalogEntry source|null, List<TaintStep> path,
│                                String terminalReason, int functionsVisited)
├── TaintStep.java       record(String function, String address, String kind,
│                                String detail)
└── VulnAnalysisService  + taint param on detect_vuln_patterns
                         + /find_taint_path endpoint
```

`TaintTracer` is constructed per scan (when `taint=true` or for a single
`/find_taint_path` call) with a `Program` and a `SinkCatalog`. It opens one
`DecompInterface` and disposes it in `close()` (`TaintTracer implements
AutoCloseable`). The `HighFunction` cache is a simple `Map<Function,
HighFunction>` keyed by `Function` identity.

## Algorithm — `TaintTracer.trace(PcodeOp sinkCall, int argIdx, int maxCallDepth, int maxFunctions)`

Worklist of frames `(HighFunction hf, Varnode v, int callDepth,
List<TaintStep> path, Set<Function> onPath)`. Seed with the sink call's
`argVarnode(sinkCall, argIdx)`. For each frame popped:

1. **Intra-function backward walk** on `v` via `getDef()` — transparent
   through `COPY`/`CAST`/`INT_ZEXT`/`INT_SEXT`/`INDIRECT(input 0)`/
   `PTRADD`/`PTRSUB`/`INT_ADD`/`INT_SUB`/`INT_MULT`/`MULTIEQUAL`. Record a
   `TaintStep{kind:"op", ...}` per traversed op (capped at 64 steps/frame).

2. **At a `CALL`/`CALLIND` output (return value):** resolve callee
   (`input(0).getAddress()` or `ReferenceManager` for CALLIND, follow thunk).
   - If callee is a **catalog source** → return
     `TaintResult{source=entry, path+step, terminal="source"}`.
   - Else if `callDepth < maxCallDepth` and callee not in `onPath` and
     cache size < `maxFunctions`: decompile callee (cache), for each
     `RETURN` op enqueue `(calleeHF, RETURN.input(1), callDepth+1,
     path+step, onPath+callee)`.
   - Else: branch terminal `"call_depth"` / `"recursion"` / `"budget"`.

3. **At a `LOAD`:** compute the LOAD's address varnode (`input(1)`). Check
   `taintedBufferRoots(hf)` — the set of varnodes in this function that are
   either (a) `argVarnode(call, out_arg)` for any catalog-source call site
   in `hf`, or (b) the output varnode of a catalog-source call with
   `returnIsOutput=true`. If the address varnode's intra-function
   `definingOps` chain contains a `PTRADD`/`PTRSUB`/`INT_ADD` whose base
   input COPY/CAST-derives from any root → return
   `TaintResult{source=that entry, path+step, terminal="tainted_load"}`.
   Else: branch terminal `"load_unknown_provenance"` (continue other
   worklist frames).

4. **At a HighParam (no-def varnode whose `getHigh()` is a `HighParam`):**
   read its slot index `i`. If `callDepth < maxCallDepth`: enumerate callers
   via `ReferenceManager.getReferencesTo(hf.getFunction().getEntryPoint())`
   filtered by `isCall()`, capped at the first 16. For each: decompile
   caller (cache), find the `CALL` op at the ref's `fromAddress`, take
   `argVarnode(call, i)`, enqueue `(callerHF, that, callDepth+1, path+step,
   onPath+caller)`.

5. **Any other terminal** (constant, no-def non-param, unhandled op): branch
   terminal with the reason; continue other worklist frames.

Return the **first** frame that reaches a source (greedy/BFS by call-depth so
shortest cross-function path wins). If the worklist drains with no source:
`TaintResult{source=null, path=<longest path explored>,
terminal=<aggregated reasons>, functionsVisited}`.

`taintedBufferRoots(hf)` is computed once per `HighFunction` and cached.

## Endpoints

### `/find_taint_path` (GET, category `security`)

| Param | Type | Default | Notes |
| --- | --- | --- | --- |
| `address` | string | — | Sink call-site address (overlay-aware). Required. |
| `arg_role` | string | `""` | One of `size_arg`/`fmt_arg`/`cmd_arg`/`dst_arg`. Resolved against the callee's catalog entry. |
| `arg_index` | int | `-1` | Raw 0-based arg index; used when `arg_role` is empty or callee isn't in the catalog. |
| `max_call_depth` | int | `5` | Clamped `[1,10]`. |
| `max_functions` | int | `64` | Clamped `[1,256]`. |
| `program` | string | `""` | Standard. |

Returns `TaintResult.toJson()`: `{source: {id, class, kind}|null, path:
[{function, address, kind, detail}, …], terminal_reason, functions_visited,
call_depth_reached}`.

### `detect_vuln_patterns` — two new body params

| Param | Type | Default | Notes |
| --- | --- | --- | --- |
| `taint` | boolean | `false` | When true, run `TaintTracer` on each emitted finding. |
| `taint_max_depth` | int | `5` | Clamped `[1,10]`. `max_functions` fixed at 64. |

When `taint=true`, the service constructs one `TaintTracer` (shares the
existing scan's `DecompInterface` if the multi-function path is active; else
opens its own). For each finding, the arg index is taken from the finding's
catalog entry (`size_arg` for `copy`/`alloc`, `fmt_arg` for `format`,
`cmd_arg` for `exec`). Each finding's JSON gains:
- `taint_source` — catalog entry id or `null`
- `taint_terminal` — `"source"` | `"tainted_load"` | `"load_unknown_provenance"` | `"budget"` | `"call_depth"` | `"recursion"` | `"constant"` | `"decompile_failed"`
- `taint_path` — list of steps (truncated to 32 for response size)

Findings with a non-null `taint_source` are **bumped to `confidence: "high"`**
(regardless of the detector's original tier).

## Bounds & error handling

- `maxCallDepth` clamped `[1,10]`; `maxFunctions` clamped `[1,256]`; caller
  fan-out per param boundary capped at 16; intra-function step cap 64.
- `Set<Function> onPath` per frame prevents recursion; the cache prevents
  re-decompiling but does NOT prevent re-visiting (a function may be entered
  from multiple paths at different varnodes — that's correct).
- Decompile failure → branch terminal `"decompile_failed"`, continue.
- `TaintTracer.close()` disposes the `DecompInterface`; `VulnAnalysisService`
  uses try-with-resources.

## Testing

- **Offline (`TaintTracerTest`):** mock 3-function chain (Sink ← Mid ←
  Source) with the existing `HighFunction`/`PcodeOp`/`ReferenceManager` mock
  harness. Cases:
  - param-chain to source (`Sink.n = param0` → `Mid` calls `Sink(len)` where
    `len = param0` → `Source` calls `Mid(recv_ret)`)
  - CALL-return to source (`n = recv(...)`)
  - LOAD-from-tainted-buffer (`recv(buf); n = *(buf+8)`)
  - budget exhaustion → `terminal="budget"`
  - no source → `source=null`, terminal aggregated
- **Offline (`VulnAnalysisServiceTest`):** `detect_vuln_patterns(taint=true)`
  on a mock that yields one finding → asserts `taint_source`/`taint_path`
  fields present.
- **Live (`Application1.elf`):**
  `find_taint_path(address="dnp_modbus.Initial::00015df4", arg_role="size_arg")`
  → either traces to `recv`/`read` (real) or terminates with reason.
- **Catalog parity:** `endpoints.json` gains `/find_taint_path` and the two
  new `detect_vuln_patterns` params.

## Out of scope

Inter-function buffer aliasing; STORE→LOAD pairing within a function; forward
taint from sources; field-sensitive struct tracking; CFG dominance (#4 from
the Phase-1.5 list — still separate).

## Files

| File | Change |
| --- | --- |
| `src/main/java/com/xebyte/core/vuln/TaintStep.java` | new record |
| `src/main/java/com/xebyte/core/vuln/TaintResult.java` | new record + `toJson()` |
| `src/main/java/com/xebyte/core/vuln/TaintTracer.java` | new — the walker + cache |
| `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java` | `+/find_taint_path`; `+taint`/`taint_max_depth` params; per-finding trace; confidence bump |
| `src/main/java/com/xebyte/core/vuln/Finding.java` | `+taintSource`, `+taintTerminal`, `+taintPath` optional fields (or a sibling `TaintedFinding` wrapper to keep `Finding` immutable — implementation choice) |
| `src/test/java/com/xebyte/offline/vuln/TaintTracerTest.java` | new |
| `src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java` | `+taint` test |
| `tests/endpoints.json` | `+/find_taint_path`; `detect_vuln_patterns` params |
