# Benchmark Regression YAML Schema

Every file here is consumed by `tools.setup.ghidra.run_benchmark_yaml_regression`
during `python -m tools.setup deploy --test release`. One YAML per binary; the
runner iterates the directory and reports every failure from a whole pass at
once rather than stopping at the first.

These assertions are the only part of the release tier that checks an *answer*
rather than checking that an endpoint answered at all. Everything else the tier
does is liveness.

## File layout

```text
tests/fixtures/benchmark/regression/
  __schema__.md            (this file)
  Benchmark.dll.yaml       (assertions for /testing/benchmark/Benchmark.dll)
  BenchmarkDebug.exe.yaml  (assertions for /testing/benchmark/BenchmarkDebug.exe)
```

## Top-level keys

```yaml
program:           # binary-level assertions (single dict)
functions:         # list of per-function assertions
endpoint_smoke:    # list of endpoint connectivity + structural assertions
skipped:           # list of {endpoint, reason} pairs documenting coverage gaps
```

**Only those four keys exist.** The predecessor of this document also described
a `data:` block and a `program.symbol_count_min` field, and the shipped baseline
used `symbol_count_min: 700`. Neither has ever been implemented: the runner
reads `program`, `functions`, `endpoint_smoke` and `skipped`, and silently drops
anything else. An assertion the runner cannot see is worse than a missing one,
because the file reads as though it covers something it does not. If you want a
new field, add it to `_bench_assert_*` in `tools/setup/ghidra.py` first.

### `program` — binary-level

| Field | Compared against | Form |
| --- | --- | --- |
| `path` | required; the project path passed to every request | — |
| `architecture` | `/get_metadata.architecture` | exact |
| `language` | `/get_metadata.language` | exact |
| `compiler` | `/get_metadata.compiler` | exact |
| `function_count_min` | `/get_function_count.function_count` | `>=` |
| `string_count_min` | number of items from `/list_strings` | `>=` |
| `segments` | names from `/list_segments` | each must be present |
| `must_contain_strings` | raw text of `/list_strings` | each must be a substring |

`name` is accepted and ignored; it is there so a reader can see which binary the
file is about without decoding the path.

`/list_strings` defaults to `limit=100`, so a `string_count_min` above 100 can
never pass however many strings the binary has.

### `functions` — per-function

```yaml
functions:
  - address: "0x10001000"            # required; hex with 0x prefix
    name: "calc_crc16"               # exact; /get_function_by_address.name
    signature_contains: ["uint"]     # all substrings; .signature
    return_type_contains: "uint"     # substring; .signature
    param_count: 2                   # exact; /get_function_signature
    basic_block_count: 10            # exact; /get_function_signature
    cyclomatic_complexity: 5         # exact; edge_count - block_count + 2
    instruction_count_min: 30        # >=
    xref_count_to_min: 2             # >=; item count from /get_xrefs_to
    is_thunk: false                  # only `false` is checked, as "did it resolve"
    decompile_must_be_nonempty: true
    decompile_contains: ["0x1021"]   # all substrings of /decompile_function
    immediate_values_contains: [4129, 65535]
    string_constants_contains: []
    callee_names_contains: ["compute_gcd"]
```

`immediate_values` is collected by `BinaryComparisonService` from scalar
operands with `0 < |value| < 0x10000`, so a constant of 0, or one at or above
65536, will never appear there however plainly it is written in the code.

`basic_block_count` comes from `BasicBlockModel.getCodeBlocksContaining(body)`.
Pinning it exactly is safe *if the number was measured*; deriving it by reading
the source is not.

### `endpoint_smoke` — one per endpoint category

```yaml
endpoint_smoke:
  - endpoint: "/list_segments"
    method: "GET"                    # default GET; POST sends `body` as JSON
    params: { address: "0x10001000" }
    body: {}
    assert:
      type: "lines"                  # nonempty | lines | text | json
      min_lines: 4
      max_lines: 40
      contains: [".text"]            # for `lines`, matched per line; for `text`, whole body
      contains_keys: ["count"]       # `json` only
```

`program=` is added automatically except for the genuinely program-less
endpoints listed in `_bench_assert_endpoint_smoke`.

**`type: nonempty` is nearly always vacuous post-7.0.0.** Every list endpoint now
returns a JSON envelope, and `{"classes": [], "count": 0}` is non-empty text, so
the assertion passes on an empty result. Prefer `lines` with `min_lines`, or
`json` with `contains_keys`. Where neither is possible, move the endpoint into
`skipped` with a reason instead of leaving a check that cannot fail.

### `skipped`

```yaml
skipped:
  - endpoint: "/exit_ghidra"
    reason: "Terminates Ghidra; obviously cannot run during a regression"
```

Counted and printed at the end of the run. A reason is not optional: the entry
exists to make a coverage gap visible, and an unexplained skip is just a gap.
