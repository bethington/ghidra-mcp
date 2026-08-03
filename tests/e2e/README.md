# fun-doc dashboard — browser end-to-end suite

Playwright tests that drive the real pipeline dashboard in a real browser
and cross-check what the page **renders** against what the server's own
JSON APIs **report**.

That pairing is the point. Every dashboard bug this project has actually
shipped left the API perfectly correct and the test suite green:

| Bug | What the API said | What the operator saw |
| --- | --- | --- |
| `in_scope \|\| 1` denominator | correct counts | `326700%` on the completeness bar |
| same class, globals bar | correct counts | `228600%` |
| 7.0.0 envelope unwrap | correct rows | both inventories empty, for days |
| `ghidra_health` lost its emitter | nothing | a green dot for a dead Ghidra |
| context switch via `save_state()` | correct | a ~50 s freeze on every binary switch |

None of those are visible from a request/response assertion. They are
visible from the DOM.

## Running

```bash
# read-only — safe against a live, working fleet
python -m pytest tests/e2e -m "not destructive" --no-cov

# starts and stops real workers, writes and reverts config
python -m pytest tests/e2e -m destructive --no-cov

# everything
python -m pytest tests/e2e --no-cov

# headed, so you can watch it drive the page
python -m pytest tests/e2e --no-cov --headed --slowmo 250

# against a dashboard somewhere else
python -m pytest tests/e2e --no-cov --dashboard-url http://127.0.0.1:5001
```

Prerequisites: `pytest-playwright` plus `python -m playwright install
chromium`, and a dashboard answering on `--dashboard-url` (default
`http://127.0.0.1:5000`). Without one the whole suite **skips** — it
never fails for the dashboard being down.

**Runtime: expect 20–35 minutes for the full suite.** Each test loads a
fresh page and waits for all four bars to hydrate against a live
Ghidra-backed dashboard. That isolation is deliberate — shared page state
between tests is how a suite starts passing for the wrong reasons — but
it is why this is not a tier you run on every edit. Narrow it while
iterating (`tests/e2e/test_bars.py`, `-k legend`).

Run it with `python -u -m pytest ... > out.txt`, not `| tail`: `tail`
buffers the entire stream to EOF, so a piped run shows you nothing at all
until it finishes.

Use `python -m pytest`, not `uv run pytest`: `uv` re-syncs the venv on
every invocation and cannot replace `Scripts/bridge-mcp-ghidra.exe` while
an MCP bridge is running, which fails the run before pytest starts.

## Why `destructive` is safe here

`--allow-unpaused` exists because the destructive worker tests **require
a paused fleet** by default. That is a safety property, not a
limitation: `WorkerManager._park_if_paused` is called at the *top* of
each lane loop, before a function is selected and before any provider
call, so a worker started against a paused fleet parks immediately. The
full start → render → stop lifecycle gets exercised for **zero tokens
and zero documentation changes**.

`worker_guard` stops anything the suite started even when a test fails
midway, and every config write is reverted in a `finally`.

## Files

| File | Covers |
| --- | --- |
| `test_smoke.py` | page loads, all steering controls present, console clean, `/pipeline` alias, theme persistence |
| `test_health_strip.py` | the five dependency dots vs `/api/health/all`; tooltips; `.bad` class; socket-loss precedence |
| `test_bars.py` | all four segmented bars: legend vs API, widths fit the track, widths match their share, headline arithmetic, target follows config |
| `test_workers.py` | pane set vs manager roster, titles, status lines, stale rendering; **destructive**: UI start → park → UI stop, launch rejections |
| `test_settings.py` | popout reflects `/api/queue/config`; **destructive**: Target round-trip that asserts no neighbouring key moved |
| `test_inventory.py` | both inventories vs API, search filtering, untyped/reviewed markers, function drawer |
| `test_binary_picker.py` | focus button, picker, `/api/context`; **destructive**: switch repoints every panel, context switch stays under an 8 s budget |
| `test_regressions.py` | named guards for the bugs in the table above |

## Shared helpers (`conftest.py`)

- `dashboard` — loads the page, waits for real hydration (not
  `networkidle`, which never settles on a page that polls), returns
  `(page, errors)` with console/pageerror/4xx collection attached.
- `read_legend(page, id)` → `{label: count}`. Anchors on the last integer
  because labels contain digits (`80+`, `<80`, `100`).
- `read_segments(page, id)` → `[(title, width_pct)]` for the spans that
  are actually drawn — a zero-count segment isn't rendered, so this is
  the bar as the operator sees it.
- `wait_for(predicate, ...)` — polls a *server-side* condition;
  Playwright's `expect()` can only see the DOM.

## Adding a test

Assert against the API, not a constant. The corpus changes every time a
worker runs; a test that hardcodes `2196` is a test that fails on
Tuesday. If a check can be made without a browser (a data-contract
invariant like `evaluated <= in_scope`), write it without one — it will
be faster and the failure will point at the right layer.
