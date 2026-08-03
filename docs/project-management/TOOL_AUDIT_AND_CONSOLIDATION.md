# Tool Audit, Behavior Testing & Consolidation Proposal

**Status:** implemented — see [§6 Execution status](#6-execution-status). Merges, bug
fixes, and call-site migration are done and the offline suites are green; live
verification against a running server is the open item.
**Date:** 2026-07-25 · **Baseline:** v6.0.0 (272 endpoint-backed tools + 8 bridge static + 22 WinDbg proxy)
**Target for approved changes:** **7.0.0** (see [Versioning](#5-versioning) — an
earlier plan to amend the published 6.0.0 in place was superseded 2026-08-03).

This document backs a request to (1) verify the README lists every tool the server
provides, (2) manually verify each tool behaves as its name/description claims,
(3) find and close test-coverage gaps, and (4) propose consolidating redundant
tools without losing functionality.

---

## 1. Documentation parity audit — RESULT: CLEAN

The README API Reference is **auto-generated** from [`tests/endpoints.json`](../../tests/endpoints.json)
by [`tools/gen_readme_api_reference.py`](../../tools/gen_readme_api_reference.py), and
[`tests/unit/test_project_consistency.py`](../../tests/unit/test_project_consistency.py)
fails CI on any drift. Verified against the live server:

| Comparison | Result |
| --- | --- |
| Live `/mcp/schema` (running GUI server) | 256 tools |
| `tests/endpoints.json` / README | 272 tools |
| Live-schema tools **missing** from README | **0** |
| Java `@McpTool` tools **missing** from README | **0** |
| README generator drift check | up to date |

- The 272 − 256 = 16 gap is the **headless-only** lifecycle tools; each verified present
  in [`src/main/java/com/xebyte/headless/`](../../src/main/java/com/xebyte/headless/) and
  correctly labeled "Available on the standalone headless server."
- 8 bridge static tools and 22 WinDbg-proxy `debugger_*` tools are correctly represented
  (the proxy tools in aggregate).

**Conclusion:** zero missing tools, zero phantom tools. No README edits required for parity.

**Optional enhancement:** the 22 WinDbg-proxy `debugger_*` tools are described in aggregate
rather than listed individually. Low priority; they are platform+env conditional.

**Minor internal nit:** `CLAUDE.md` says the bridge has "7" static tools; it is actually 8
(`search_tools` was added). One-line fix.

---

## 2. Behavior testing — headed (GUI) server

Target: **BenchmarkDebug.exe** (x86 32-bit, 663 functions) — confirmed disposable, so
mutating tools were exercised for real. Harnesses: `scratchpad/harness.py` (read-only sweep)
and `scratchpad/harness_mut.py` (mutating round-trips). These will be ported into the
integration suite (see §4).

### 2a. Read-only sweep — 132 GET tools
**116/132 clean.** All 16 "flags" were false positives: heuristic substring matches
(`"exception"`/`"invalid "` appearing inside legitimate output) or intentionally-wrong
inputs where the tool **correctly** returned "not found" (good input validation). **Zero
read-only defects.**

### 2b. Mutating round-trips — confirmed behaviors & merge evidence
| Test | Result |
| --- | --- |
| `set_comment(type=plate/pre/eol/post)` vs `set_plate/decompiler/disassembly_comment` | ✅ identical effect; `get_comment` returns all kinds in one JSON `{plate,pre,eol,post}` |
| `add_function_tag` vs `batch_add_function_tags(1)` | ✅ identical; verified via `get_function_tags` + `search_functions_by_tag` |
| `create_label`/`delete_label` vs batch variants | ✅ all succeed (tool also enforces snake_case) |
| `get_data_type_size` vs `get_type_size` | ✅ same sizes; `get_type_size` is a strict superset (adds alignment + path) |
| `rename_function` vs `rename_function_by_address` | ✅ both work |
| `decompile_function` vs `batch_decompile(1)` | ✅ both produce code |
| `analyze_function_completeness` vs `batch_analyze_completeness(1)` | ✅ both return scores |
| `set_bookmark`/`list_bookmarks`/`delete_bookmark` | ✅ full lifecycle |
| `create_struct`→`get_struct_layout`→`add_struct_field`→`delete_data_type` | ✅ (but see BUG-2) |
| `check_connection` vs `mcp_health` | ✅ both healthy (text vs rich JSON) |

### 2c. BUGS & footguns found
- **BUG-1 — `validate_data_type_exists` is broken for bare names.** It calls
  `DataTypeManager.getDataType(name)` ([`DataTypeService.java:432`](../../src/main/java/com/xebyte/core/DataTypeService.java#L432)),
  which needs a full path. `int`→`{"exists":false}`, `/int`→`{"exists":true}`. Every natural
  LLM input (`int`, `DWORD`, `char *`) returns a false negative. `get_type_size` resolves bare
  names fine — so the fix is to reuse that resolver.
- **BUG-2 — struct-field mutators don't accept the name you created the field with.**
  `create_struct` auto-Hungarian-prefixes fields (`a`→`nA`, `b`→`cB`), but
  `remove_struct_field`/`modify_struct_field` require the *transformed* name, so removing `"b"`
  fails "Field 'b' not found." Callers must re-read the layout to learn the mangled name.
  Fix: resolve by original stem as a fallback, or return the final field names from `create_struct`.
- **NIT — `get_function_labels` requires a function *name*** (param `name`), rejecting an
  address, while sibling tools accept name-or-address. Returns a confusing `Function not found: null`
  when the param is absent. Fix: accept address too; clearer missing-param error.

---

## 3. Test-coverage gap analysis

Cross-referenced all 291 tool names against `tests/` and `src/test/`.
**107 / 291 (37%) have ZERO automated test reference.** By category:

| Category | Zero-coverage | Testability |
| --- | --- | --- |
| analysis | 19 | **Easy** — live GUI (malware/crypto/dataflow/control-flow) |
| debugger (TraceRmi) | 17 | Hard — needs a debug session |
| server (VCS/admin) | 17 | Hard — needs a Ghidra Server fixture |
| debugger-proxy (WinDbg) | 11 | Hard — needs WinDbg + `GHIDRA_DEBUGGER_URL` |
| datatype | 9 | **Easy** — several are merge targets |
| program | 7 | Mixed — some session-destructive |
| utility | 6 | **Easy** |
| comment | 5 | **Easy** — core, and merge targets (`set_comment`,`get_comment`,`set_bookmark`,…) |
| headless | 5 | Medium — needs headless-server fixture |
| others | 11 | mixed |

### Proposed test-extension plan (prioritized)
- **P0 — port the §2b harness into `tests/integration/`** as durable round-trip tests:
  comment family, bookmark lifecycle, struct lifecycle, tag family, label family, type-size,
  validators, rename-by-name-vs-address. Closes the most embarrassing gaps (core mutators) and
  guards the consolidation refactor.
- **P1 — analysis-tool smoke/shape tests** (19 tools): assert 200 + expected top-level JSON keys
  against BenchmarkDebug.exe (which has real crypto/CRC + anti-analysis surface — 42 findings seen).
- **P2 — environment-gated fixtures:** headless-server fixture (5 tools), a throwaway local
  Ghidra Server fixture (17 server tools), and a debugger-session fixture (28 tools). Bigger lift;
  propose as a follow-up once P0/P1 land. **This is the current maximal-coverage frontier.**
- **Regression guard:** add a test asserting `validate_data_type_exists`/`get_type_size` agree on
  bare names (locks BUG-1's fix).

---

## 4. Consolidation proposal — Moderate tier

Principle: **one tool that does one-or-many**, plus fold true duplicates. No functionality is
removed — every capability remains reachable. Net surface reduction ≈ **15–17 tools**
(272 → ~255) with per-call schema savings on the hottest write paths.

> Tool-context note: `load_tool_group`/`unload_tool_group` already lazy-load tools, so the win
> here is **API cleanliness + fewer near-duplicate schemas the model must disambiguate**, not raw
> context size.

### Group 1 — Comments (evidence: §2b, proven)
| Remove | Into | Notes |
| --- | --- | --- |
| `set_plate_comment` | `set_comment(type="plate")` | proven identical |
| `set_decompiler_comment` | `set_comment(type="pre")` | proven identical |
| `set_disassembly_comment` | `set_comment(type="eol")` | proven identical |
| `get_plate_comment` | `get_comment` | `get_comment` already returns `{plate,pre,eol,post}` |

**−4 tools.** (Optional: also fold `batch_set_comments`' per-function multi-comment shape into a
variadic `set_comment`; different payload shape, so listed as opt-in, not baseline.)

### Group 2 — Single/batch → one variadic tool ("one or many")
| Merge pair | New tool |
| --- | --- |
| `add_function_tag` + `batch_add_function_tags` | `add_function_tags` (accepts `function`+`tags` **or** `assignments[]`) |
| `remove_function_tag` + `batch_remove_function_tags` | `remove_function_tags` |
| `create_label` + `batch_create_labels` | `create_labels` |
| `delete_label` + `batch_delete_labels` | `delete_labels` |
| `decompile_function` + `batch_decompile` | `decompile_functions` |
| `analyze_function_completeness` + `batch_analyze_completeness` | `analyze_completeness` |
| `rename_variable` + `rename_variables` | `rename_variables` |
| `batch_set_variable_types` → `set_variables` | (subset; `set_variables` already does names+types) |

**−8 tools.**

### Group 3 — True duplicates
| Remove | Into | Notes |
| --- | --- | --- |
| `get_data_type_size` | `get_type_size` | superset (proven) |
| `check_connection` | `mcp_health` (or vice-versa) | keep one; richer JSON survives |
| `validate_data_type_exists` | `validate_data_type` (make `address` optional) | **+ fix BUG-1** |
| `rename_function` | `rename_function_by_address` → unified `rename_function(target=name\|address)` | both proven |

**−4 tools.**

### Deliberately NOT merged (kept granular on purpose)
- `set_local_variable_type` / `set_parameter_type` / `set_decompiler_variable_type` — real merge
  candidates but Tier-3 (semantic mode-tool); flagged as **opt-in** below, not baseline.
- `rename_data` / `rename_global_variable` / `rename_label` / `rename_or_label` /
  `rename_external_location` — operate on distinct symbol kinds; unifying risks a confusing mode
  matrix. Tier-3 opt-in.
- Analysis/malware tools — distinct outputs; merging would hurt tool selection.

### Tier-3 opt-in (only if you want them)
- `set_variable_type` unifying local/param/decompiler var-type setters (**−2**).
- `rename_symbol(kind=)` unifying the 5-way rename family (**−4**), higher misuse risk.

### Independent fixes (recommend regardless of consolidation)
- Fix **BUG-1** (validate_data_type_exists bare-name resolution).
- Fix **BUG-2** (struct-field mutators accept original field stem / create_struct returns final names).
- **NIT**: `get_function_labels` accept address; better missing-param message.

---

## 5. Versioning

**These changes ship as v7.0.0.** No backward-compat aliases are needed —
consolidation is a clean break, and the major bump is what advertises it.

### Superseded plan (2026-07-25 → 2026-08-03)

This section originally proposed folding the breaking changes into an **amended
6.0.0**. The reasoning was that v6.0.0 had been tagged, pushed and released only
hours earlier, and the bridge wheel is not on PyPI — so retagging looked cheap.

That is no longer the plan, and the amend-in-place idea was worse than it looked:

- **It rewrites the meaning of a published tag.** Anyone who pulled v6.0.0 in the
  interim would hold a `6.0.0` that behaves differently from a later `6.0.0`,
  with no version string to tell the two apart. A caveat in the release notes
  does not give a consumer a way to *detect* which one they have.
- **It spends the signal that exists for exactly this.** Semantic versioning's
  major bump is the mechanism for "this breaks you"; declining to use it on the
  largest breaking change in the project's history saves nothing.
- **The boundary claim leaks everywhere.** ~70 comments, docstrings and doc lines
  across 34 files were written asserting the boundary was 6.0.0. Every one was
  wrong for a reader running released 6.0.0, and all were retargeted to 7.0.0
  when the decision changed. (A handful of `6.0.0` references that are *genuinely*
  about the released tag — the audit baseline, the schema-vs-catalog diff, the
  `/run_script` deletion, which really did ship in 6.0.0 — were deliberately left
  alone. `v6.0.0` with the `v` prefix marks those.)

Released **6.0.0 keeps the old behaviour**: 272 tools, prose responses. The
consolidated 251-tool surface and the JSON response contract are **7.0.0 and
later**.

---

## 6. Execution status

### Done
- [x] **Merges implemented** — all of Groups 1–3 plus both Tier-3 unifications.
      Advertised surface **272 → 251**. Java `@McpTool` methods extended/removed,
      `ManualToolDescriptors` + headless manual-route lists pruned of the deleted
      routes, `tests/endpoints.json` regenerated, README API reference regenerated.
- [x] **BUG-1 / BUG-2 / NIT fixed** (bare-name type resolver; struct-field stem
      fallback; `get_function_labels` accepts an address).
- [x] **`mcp_health` resolved** — kept, verified not a duplicate of
      `check_connection` (see the migration contract for the rationale).
- [x] **Call sites migrated** across fun-doc (workers, prompts, provider tool
      allowlists, benchmark harness), the Python bridge, `tools/setup` deploy
      smoke tests, `ghidra_scripts/`, the test suites, and the operator docs.
      Residual references survive only in history (CHANGELOG, `docs/archive/`,
      `docs/releases/`) and in survivor descriptions that name what they replaced.
- [x] **Java-side guidance strings migrated.** `AnalysisService`'s
      `recommendations` / `actions` payloads named removed tools and shipped
      `params_template`s with their old parameter names — every one of those was
      a tool call the model would have made and had 404 or rejected.
- [x] **Suites green:** offline Java (390 tests), unit (`tests/unit/`), offline
      Python (`tests/performance/` minus the four live-Ghidra files).

### Remaining
- [ ] **Live verification** — deploy the JAR, confirm `/mcp/schema` reports 251,
      then run the integration tiers (`pytest tests/ -m readonly`, `-m safe_write`,
      the Java `EndpointRegistrationTest`) and the four live-Ghidra performance
      files. The migrated integration tests have been rewritten against the
      survivors but not yet executed against a running server.
- [ ] **fun-doc benchmark** (`--mock --tier fast --compare`) — the prompt and
      allowlist edits touch documentation quality, so a before/after run belongs
      with this change.
- [ ] **P0 — port the §2b harness into `tests/integration/`** as durable
      round-trip tests (comment family, bookmark/struct/tag/label lifecycles,
      type-size, validators, rename-by-name-vs-address). This is what would have
      caught the migration gaps mechanically instead of by grep.
- [ ] **P1 — analysis-tool smoke/shape tests** (19 zero-coverage tools).
- [ ] **P2 — environment-gated fixtures:** headless server (5 tools), Ghidra
      Server (17 tools), debugger session (28 tools). Still the maximal-coverage
      frontier.
