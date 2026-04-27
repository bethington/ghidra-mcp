# Benchmark Regression YAML Schema

This directory holds tool-output regression assertions for the benchmark binaries
shipped under `fun-doc/benchmark/build/`. Every file here is consumed by
`tools.setup.ghidra.run_benchmark_regression` during `python -m tools.setup deploy --test release`.

The goal is to verify that **every** category of MCP endpoint produces the
expected output shape and content against a known, deterministic binary.

## File layout

```
fun-doc/benchmark/regression/
  __schema__.md            (this file)
  Benchmark.dll.yaml       (assertions for /testing/benchmark/Benchmark.dll)
  BenchmarkDebug.exe.yaml  (assertions for /testing/benchmark/BenchmarkDebug.exe)
```

One YAML per binary. The runner iterates each file and runs the assertions in it.

## Top-level keys

```yaml
program:           # binary-level assertions (single dict)
functions:         # list of per-function assertions
data:              # (optional) list of per-data-item assertions
endpoint_smoke:    # list of endpoint connectivity + structural assertions
skipped:           # list of {endpoint, reason} pairs documenting coverage gaps
```

### `program` — binary-level

```yaml
program:
  name: "Benchmark.dll"                 # displayed in /get_metadata
  path: "/testing/benchmark/Benchmark.dll"
  architecture: "x86"
  language: "x86:LE:32:default"
  compiler: "windows"
  function_count_min: 500               # tolerate analyzer drift; assert >=
  symbol_count_min: 2000
  string_count_min: 100
  segments:                             # ordered list, names match /list_segments
    - name: "Headers"
    - name: ".text"
    - name: ".rdata"
    - name: ".data"
  must_contain_strings: []              # list of strings that must appear in /list_strings
  endpoint_overrides:                   # (optional) per-endpoint asserts
    /get_function_count:
      function_count_min: 500
```

### `functions` — per-function

```yaml
functions:
  - address: "0x10001000"               # required; hex with 0x prefix
    name: "calc_crc16_8"                # must match /get_function_by_address
    signature_contains: ["ushort", "calc_crc16_8"]   # all substrings must appear in /get_function_signature
    return_type_contains: "ushort"      # appears in /get_function_signature signature line
    param_count: 2                      # exact; from /get_function_signature
    instruction_count_min: 80           # >=; from /get_function_signature
    basic_block_count: 5                # exact; from /get_function_signature
    cyclomatic_complexity: 3            # exact; from /get_function_signature
    xref_count_to_min: 1                # >=; from /get_xrefs_to count
    is_thunk: false                     # exact; from /get_function_by_address
    decompile_must_be_nonempty: true    # /decompile_function returns non-empty
    decompile_contains:                 # all substrings must appear in /decompile_function
      - "0x1021"
      - "0xffff"
    immediate_values_contains: [4129, 65535]   # subset of /get_function_signature.immediate_values
    string_constants_contains: []       # subset of /get_function_signature.string_constants
    callee_names_contains: []           # subset of /get_function_signature.callee_names
```

### `data` — per-data-item (optional)

```yaml
data:
  - address: "0x10000134"
    type_contains: ["pointer"]          # appears in /list_data_items_by_xrefs entry
    xref_count_to_min: 1
```

### `endpoint_smoke` — connectivity + structural

For categories without a per-function or per-data home: hit the endpoint, assert
basic shape. Use this for `/list_calling_conventions`, `/list_namespaces`,
`/list_data_types`, `/get_address_spaces`, etc.

```yaml
endpoint_smoke:
  - endpoint: "/list_calling_conventions"
    method: "GET"                       # default GET
    params: {}                          # query params (program= is auto-added)
    assert:
      type: "lines"                     # response shape
      min_lines: 5
      contains: ["__cdecl", "__stdcall", "__fastcall"]
  - endpoint: "/list_namespaces"
    assert:
      type: "lines"
      min_lines: 1
  - endpoint: "/get_metadata"
    assert:
      type: "text"
      contains: ["Architecture: x86", "Function Count:"]
```

`assert.type` values:
- `lines` — response is line-oriented; `min_lines`, `max_lines`, `contains` (each must appear on some line)
- `text` — response is freeform; `contains` (each substring must appear)
- `json` — response is JSON; `contains_keys`, `min_array_length`, `eq_at` (path → value)
- `nonempty` — response just must not be empty

### `skipped` — explicit coverage gaps

```yaml
skipped:
  - endpoint: "/bsim_query_function_match"
    reason: "BSim DB empty in dev environment"
  - endpoint: "/debugger_set_breakpoint_2"
    reason: "Duplicate of /debugger_set_breakpoint covered elsewhere"
```

Skips are visible in PR review and in the regression output. They are not
silent failures — they document deliberately uncovered surface.

## Strictness

Strict by default. Any non-skipped assertion failure fails the regression.
Per-field failures emit a structured error including the endpoint, expected,
and actual values.

## Authoring workflow

1. After auto-analysis completes on a fresh import, run
   `python fun-doc/benchmark/capture_regression_baseline.py` to capture a starter
   YAML covering every applicable endpoint.
2. Manually review and curate — the captured starter is a *bootstrap*, not the
   final source-of-truth. Promote suspicious values (e.g., values that differ
   from the C source's intent) to comments + skips, fix others.
3. Commit the curated YAML alongside the code change that introduced the
   assertion.
