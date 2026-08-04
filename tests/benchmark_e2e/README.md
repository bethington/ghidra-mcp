# Undocumented → documented, measured

The quality gate for fun-doc's documentation pipeline. It takes
`Benchmark.dll` — the one binary in this project with a known answer key —
and asks two different questions with two different kinds of rigour.

## The split that makes it trustworthy

**Mechanical floors are absolutes.** A correct fun-doc produces them on
every run regardless of which model answered or how well it did: a name was
applied, it follows the naming convention, the plate carries its required
sections, parameters are typed, no run ended in a timeout, and no
hand-authored function was claimed as library code. If one of these fails,
fun-doc is *broken*, not unlucky.

**Semantic quality is a delta.** `scorer.score_function` compares generated
documentation against `ground_truth.json`, and that number moves with model
temperature, provider load and prompt phrasing. An absolute bar is either so
low it never fires or so tight it cries wolf. It is gated against the
committed `runs/latest.json` instead — on both the mean and the worst single
function, because a mean over nine functions absorbs one of them collapsing.

Conflating the two is what makes a quality gate produce red runs nobody
believes.

## Tiers

| Tier | Needs | Runs in CI | What it proves |
| --- | --- | --- | --- |
| `test_floors.py` | nothing | yes | the rules themselves — each is exercised on clean *and* defective input |
| `test_mock_pipeline.py` | nothing | yes | the plumbing: real runner + real scorer over committed fixtures |
| `test_full_pass.py` (Ghidra half) | a dedicated Ghidra | no | the clean-room precondition + the library controls, **no tokens** |
| `test_full_pass.py` (`--real-provider`) | Ghidra + tokens | no | documentation quality |

```bash
# offline — the CI tier
python -m pytest tests/benchmark_e2e -q --no-cov

# add the Ghidra-backed controls (no tokens spent)
python -m pytest tests/benchmark_e2e -q --no-cov \
    --benchmark-ghidra-url http://127.0.0.1:8189

# the full pass — spends real provider tokens
python -m pytest tests/benchmark_e2e -q --no-cov \
    --benchmark-ghidra-url http://127.0.0.1:8189 --real-provider
```

## Why a dedicated Ghidra, and why port 8189

This tier **renames functions, writes plates, applies tags and saves the
program**. Pointed at the working instance it would do all of that inside
whichever project happens to be open, and the damage would be
indistinguishable from a bad documentation run.

`reset_benchmark_fixture` is not a safe substitute for isolation either: it
deletes and re-imports, and the delete is known to fail with `Benchmark.dll
is in use` against a long-running instance — including when
`/list_open_programs` does not report the holder and `/close_program`
returns `closed_count: 0`.

The default is 8189 rather than 8089 for the same reason a seatbelt is not
optional: a typo, a stale env var or a forgotten export must not silently
land on the real one. `require_dedicated_instance` **fails outright** on
8089 rather than skipping — a skip there would read as "not configured"
when it actually means "about to overwrite your corpus".

## The corpus is the whole binary

Not the nine authored functions. A pinned per-function run never exercises
the selector, `library_code_detector`, `crt_identify` or the FID tier-0
lane — and those are precisely the subsystems that silently mislabel real
code when they break.

`Benchmark.dll` statically links a CRT, so the run has ~140 library
functions to get right alongside the 9 to document.

## The library control, and its mirror

`LIB_CRT` makes the selector skip a function **permanently**. A false
positive does not degrade a score — it removes the function from the corpus
silently, forever, with no error and no signal. `Benchmark.dll` is the only
binary here with ground truth about which functions are hand-written, so it
is the only place this can be *measured* rather than believed.

Two tests, and the second is the one that keeps the first honest:

- `test_byte_exact_crt_identification_never_claims_an_authored_function` —
  zero of the nine, ever.
- `test_crt_identification_actually_claims_the_linked_runtime` — because a
  detector that claims **nothing** also passes the test above. Zero matches
  in a binary that statically links the CRT means the index or the masking
  broke, and without this check that failure goes quietly green.

## Setting up the dedicated instance

1. Build the fixture: `python fun-doc/benchmark/build.py`
2. Start a second Ghidra with the MCP plugin bound to 8189, on a throwaway
   project.
3. Import `fun-doc/benchmark/build/Benchmark.dll` and let auto-analysis
   finish. Do **not** document it.
4. `test_the_baseline_really_is_undocumented` verifies the clean room for
   you — it fails if anything already carries a fun-doc-style PascalCase
   name.

## Notes

- The mock tier redirects `runs/` into `tmp_path`. `runs/latest.json` is the
  committed baseline that `git blame` ties to a specific commit; a test that
  rewrote it would destroy the one artifact that tells you which change
  moved a score. `test_the_runner_did_not_touch_the_committed_run_history`
  enforces that.
- Convention floors are **skipped on the mock tier**
  (`floors.CONVENTION_CHECKS`). The `--mock` captures are hand-authored
  artifacts, not fun-doc output — their plates are prose paragraphs with no
  Algorithm/Parameters/Returns headings. Asserting fun-doc's conventions
  against them would test the fixture author, and the only way to make it
  pass would be to rewrite the very files `--compare` uses as its baseline.
- `extract_truth.py` derives the answer key from the **C sources**, not the
  compiled binary, so swapping toolchains does not move it.
  `test_the_authored_functions_are_all_present` catches the drift that
  matters: a source function the compiler inlined away is otherwise scored
  forever against something that is not in the binary.
