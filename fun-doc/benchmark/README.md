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

- **name**: function name — rubric cascade (exact → prefix → embedding → LLM judge → miss)
- **plate**: plate comment — Haiku 4.5 judge against canonical plate in `truth.yaml`, with Jaccard word-overlap fallback when the LLM is unavailable
- **signature**: return type + param types — structural exact match, no wiggle room
- **locals**: local variable names + types — rubric cascade for names, structural for types
- **algorithm**: whether the plate mentions the algorithm tag — structural

### LLM judge for plate scoring

The plate dimension's scorer invokes Haiku 4.5 via the Anthropic SDK by default. The judge prompt is small (~200 token system + ~2× the plate length user content), capped at 16 tokens output — a full fast-tier run calls the judge 5 times; core tier 4 times. Expected cost per call ≈ $0.00005 on Haiku 4.5.

Configuration:

| Env var | Default | Effect |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | (unset) | When set, real Haiku is invoked. When unset, Jaccard fallback fires. |
| `FUNDOC_BENCHMARK_JUDGE_MODEL` | `claude-haiku-4-5` | Swap in a different judge model (e.g. `claude-sonnet-4-6`) |
| `FUNDOC_BENCHMARK_NO_LLM` | (unset) | Set to `1` to force Jaccard fallback even with an API key set — useful for deterministic test runs. |

The Jaccard fallback is coarse but monotonic — high word-overlap means high similarity. It's what offline tests use and what runs before you've set the API key. The scorer's output `dimensions.plate.tier` tells you which path fired: `llm_haiku` (real Haiku), `jaccard` (fallback), `miss` (worker wrote no plate), or `no_canonical` (truth yaml has no canonical_plate).

Failures in the Haiku call (network, rate limit, malformed response) silently fall through to the Jaccard path — a benchmark run shouldn't abort on a transient API hiccup.

### Guardrails

Reported separately, block regressions on their own:

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

Two modes: `--mock` (reads pre-captured worker output fixtures — fast, deterministic, offline) and `--real` (drives the actual fun-doc pipeline against Ghidra — slower, exercises the full runtime).

### Mock mode — fast-iterating on the scorer

```text
# Default: fast tier, baseline variant, compare to runs/latest.json
python fun-doc/benchmark/run_benchmark.py --mock --tier fast --compare

# Regress check: run poor variant, see what scoring flags
python fun-doc/benchmark/run_benchmark.py --mock --tier fast --variant poor --compare

# Diff two specific runs
python fun-doc/benchmark/compare_runs.py runs/<before>.json runs/<after>.json
```

### Real mode — actual fun-doc-against-Ghidra regression harness

Real mode requires Ghidra running with `Benchmark.dll` imported, and whichever provider you're benchmarking reachable. First-time setup:

```text
# 1. Build the binary (produces build/Benchmark.dll)
python fun-doc/benchmark/build.py

# 2. Import it into the running Ghidra instance. Idempotent — re-running
#    is a no-op if already imported. Goes to /testing/benchmark/Benchmark.dll by
#    default; override with FUNDOC_BENCHMARK_PROGRAM.
python fun-doc/benchmark/setup_ghidra_benchmark.py

# 3. Run the benchmark. Default provider is minimax, default tier is fast.
python fun-doc/benchmark/run_benchmark.py --tier fast --compare

# Cross-provider matrix (every provider listed in priority_queue config)
python fun-doc/benchmark/run_benchmark.py --tier fast --full --compare
```

Real mode captures a **pristine snapshot** of each baseline function's current Ghidra state before the first run and restores it between function invocations. This avoids the complexity of a `.gzf` export/restore cycle at the cost of not unrolling struct definitions that fun-doc creates mid-run (they persist until manually cleaned up).

The real-mode invocation:
1. Resolves the target function's address in the benchmark program via `/search_functions`
2. Captures pristine state on first encounter (name, prototype, plate, locals)
3. Invokes `fun_doc.process_function` against the target with a **temp state file** so production state is never polluted
4. Subscribes to bus events to collect the tool-call stream
5. Scrapes Ghidra post-run for the resulting name / prototype / plate / locals
6. Scores via the same rubric as mock mode
7. Restores the pristine snapshot before moving to the next function

If Ghidra isn't running or `Benchmark.dll` isn't imported, `--real` fails early with a clear message pointing you at `setup_ghidra_benchmark.py`.

## Adding a core-tier function (D2-derived)

The workflow is scaffolded — start with `tools/add_core_function.py` to pull the reference material from Ghidra:

```text
python fun-doc/benchmark/tools/add_core_function.py \
    --program /Mods/PD2-S12/D2Common.dll \
    --address 6fd7f3a0 \
    --name CalcDamageBonus
```

This fetches the function's current decompilation and plate comment from the running Ghidra, pastes them into a new `src/<name>.c` as reference blocks, and creates a matching `truth/<name>.truth.yaml` with TODOs you fill in.

Then:

1. Read the DECOMPILATION + EXISTING PLATE blocks at the top of the scaffolded `.c` file. These are your starting reference.
2. Below them, reconstruct the function in plausible C that would compile to similar bytecode. Use mid-2000s MSVC-compatible idioms (no C99 features, explicit types, structs lifted from `memory/structs.md`).
3. Fill out the TODOs in `truth/<name>.truth.yaml`: accepted synonyms, canonical plate, algorithm tag.
4. Run `python build.py` and check the compiled output decompiles similarly to the real D2 function in Ghidra. Iterate if it doesn't.
5. Add the function to `suites/core.yaml` (either a solo suite or grouped with related struct-affinity functions).
6. Author a baseline fixture at `fixtures/<name>.baseline.capture.json` — copy from an existing one and adapt.
7. `python run_benchmark.py --mock --tier core --variant baseline` to verify scoring is in the 0.7–0.9 band.

## Adding a fast-tier or stretch-tier function (archetype)

Simpler workflow — these are authored from scratch to exercise a specific pattern, not reconstructed from D2:

1. Write `src/<name>.c` with the archetype you want to cover (e.g. bit-twiddling, switch ladder, recursion).
2. Write `truth/<name>.truth.yaml` with synonyms, canonical plate, algorithm tag.
3. Author two fixtures: `fixtures/<name>.baseline.capture.json` and `fixtures/<name>.poor.capture.json`.
4. Add to `suites/fast.yaml` (or `stretch.yaml`).
5. Run `python build.py && python extract_truth.py && python run_benchmark.py --mock --tier fast` to validate.

## When to run

See CLAUDE.md § Benchmark for the list of paths that — when modified — should trigger a benchmark run. Core tier before the commit; compare against `runs/latest.json`.
