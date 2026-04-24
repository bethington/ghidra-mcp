# Fun-Doc Benchmark

Reproducible regression harness for fun-doc's documentation quality. Answers "did my change improve things or make them worse?" by re-documenting a fixed set of functions against a ground-truth answer key and scoring the result.

## Why this exists

Prompt changes, scoring tweaks, provider routing edits, and service-layer changes all silently affect documentation quality. Without a fixed benchmark, "I think this got better" is the entire regression story. This harness replaces intuition with a scored, diffable report.

## The shape

The benchmark is a dedicated C project compiled into a throwaway `Benchmark.dll` that lives entirely inside `fun-doc/benchmark/`. Its source is handcrafted C — some archetypal patterns authored from scratch (fast tier), some reconstructed from real D2 bytecode we already understand (core + stretch tiers). We own the source, so we own the answer key.

Each run:

1. Restores a pristine `Benchmark.gzf` in Ghidra (wipes any prior documentation).
2. Invokes fun-doc's real `process_function` on each baseline function, per suite.
3. Scrapes Ghidra for the resulting name / plate / signature / locals.
4. Scores the result against ground truth via a multi-level rubric (exact → prefix → embedding → LLM-as-judge → miss) plus structural exactness for signatures and types.
5. Captures guardrail metrics (tool-call count, duplicate-tool-call ratio, tool-calls-per-quality-point, wall clock).
6. Writes `runs/YYYY-MM-DD_HHMMSS.json` + updates `runs/latest.json`.

Comparing two runs is a terminal diff of these JSON files.

## Tiers

| Tier    | Functions | Target runtime | Status   | When to run |
| ------- | --------- | -------------- | -------- | ----------- |
| fast    | 5         | ≤ 3 min        | **complete** — CRC-16, state machine, strlen, struct mutator, recursion | Quick sanity check while iterating on prompt / scoring / tool behavior |
| core    | 15        | ~15 min        | pending — D2-derived reconstructions | Before committing changes that affect documentation quality |
| stretch | 30        | ~30–60 min     | pending  | Periodically, or when you want the full picture |

Fast tier's 5 functions cover the archetype spectrum deliberately:

| Function | Archetype | Pattern exercised |
| -------- | --------- | ----------------- |
| `calc_crc16` | CRC / bit-twiddling | loop, shift, conditional XOR with polynomial constant |
| `advance_parser_state` | State machine | switch-ladder, enum dispatch, fall-through-to-default |
| `compute_str_len` | Pointer walk | null-terminated loop, pointer arithmetic, `ptr - base` subtraction |
| `stat_list_add` | Struct mutator | struct field access, magic-number validation, bounded-array append |
| `compute_gcd` | Recursion | self-call, base case, modulo reduction |

## Suites

Related functions are grouped into **suites** — small clusters that share struct definitions or cross-call. Inside a suite, state bleeds between functions intentionally (that models how real fun-doc work flows). Between suites, Ghidra is reset to pristine. Solo functions are one-function suites.

Suite definitions live in `suites/*.yaml`.

## Scoring

Per-function quality score is a weighted combination of:

- **name**: function name — rubric cascade (exact → prefix → embedding → Haiku judge → miss)
- **plate**: plate comment — Haiku judge against canonical plate in `truth.yaml`
- **signature**: return type + param types — structural exact match, no wiggle room
- **locals**: local variable names + types — rubric cascade for names, structural for types
- **algorithm**: whether the plate mentions the algorithm tag — structural

Guardrails (reported separately, block regressions on their own):

- `tool_calls_per_quality_point` — lower is better
- `duplicate_tool_call_ratio` — same (tool, args) inside one run; stays near 0

## Ground truth

Hybrid — the C source is authoritative for structural data (names, types, signatures, locals, struct layouts) via libclang. A small `truth.yaml` per function carries the semantic data the parser can't infer (accepted name synonyms, canonical plate text, algorithm tag, per-dimension weights). Both files are version-controlled and either's drift shows up in git diff.

## Toolchain

Empirically matched to D2 1.13d's `D2Common.dll`:

- Compiler (cl.exe): **Visual C++ 6.0 SP6** (Rich header confirms build 6030)
- Linker (link.exe): VC 7.1 (OptionalHeader linker version 7.10) — mixed toolchain per Blizzard's known pattern
- CRT: static (`/MT`) — no MSVCRT import
- Flags: `/O2 /GF`, x86 Win32 subsystem

Walking skeleton uses modern MSVC 2022 as a placeholder so the pipeline can be proven before we install VC6. Once proven, `build.py` takes a `--toolchain vc6sp6` flag and swaps in `cl.exe` + `link.exe` from a pinned VC6 SP6 install.

## Running

```text
# Default: minimax only, fast tier, compare to runs/latest.json
python fun-doc/benchmark/run_benchmark.py --tier fast --compare

# Core tier against a specific commit's model config
python fun-doc/benchmark/run_benchmark.py --tier core

# Cross-provider matrix (runs every provider in provider_models config)
python fun-doc/benchmark/run_benchmark.py --tier core --full

# Diff two specific runs
python fun-doc/benchmark/compare_runs.py runs/<before>.json runs/<after>.json
```

## Adding a baseline function

1. Pick a real D2 function whose documentation you already have high confidence in.
2. Write `src/<name>.c` containing plausible C that would compile to similar bytecode.
3. Write `truth/<name>.truth.yaml` with synonyms, canonical plate, algorithm tag, weights.
4. Add the function to the appropriate suite in `suites/*.yaml`.
5. Run `build.py` — if the decompile output of our binary diverges from the real D2 function in a way that matters, iterate on the C source.
6. Add to the appropriate tier in `suites/*.yaml` (fast / core / stretch).
7. Re-run the benchmark and commit the resulting `runs/latest.json`.

## When to run

See CLAUDE.md § Benchmark for the list of paths that — when modified — should trigger a benchmark run. Core tier before the commit; compare against `runs/latest.json`.
