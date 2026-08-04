# fun-doc dashboard — hermetic route contract

The dashboard tier with **no prerequisites**. No Ghidra, no browser, no
dashboard process, no provider, no network. It builds the real Flask app in
process, puts a fake Ghidra behind it, and asserts what the routes return.

That is what makes it the tier CI can run — and the tier that still works
when the fleet is down, which is exactly when you are most likely to be
changing this code.

## Running

```bash
python -m pytest tests/dashboard -q --no-cov          # ~20s
python -m pytest tests/dashboard -q --no-cov -k faults
```

Use `python -m pytest`, not `uv run pytest`: `uv` re-syncs the venv on every
invocation and cannot replace `Scripts/bridge-mcp-ghidra.exe` while an MCP
bridge is running, which fails the run before pytest starts.

Needs the `fun-doc` dependency group. Without SQLAlchemy the whole tier
skips with a message that says so, rather than taking the rest of the suite
down with an `INTERNALERROR` at collection.

## How it is hermetic

| Real thing | Replaced with | Why it has to be |
| --- | --- | --- |
| `conformance_dashboard._get` / `._post` | `fake_ghidra.FakeGhidra` | the only two functions the read layer uses to reach the plugin |
| `conformance_dashboard.endpoint_contract` | a static "all present" | drives `urllib` itself, and `conformance_api` calls it **from a daemon thread at import** — unpatched, merely building the app makes 19 real requests to 127.0.0.1:8089 |
| `web.OracleHealthMonitor` | `FakeOracleMonitor` | the real one shells out to PowerShell and probes a game process |
| `web.GhidraHealthMonitor` | `FakeGhidraMonitor` | the real one can **launch Ghidra** |
| `state.db`, `priority_queue.json`, `logs/` | a per-test `tmp_path` | a test that rewrites the operator's provider config is worse than no test |

Both monitors are patched at the `web` module attribute **before**
`create_app`, because `WorkerManager.__init__` constructs and `.start()`s
them. Patching the instances afterwards is too late.

## Why a hand-built corpus and not a recording

The assertions that matter are arithmetic, and arithmetic needs known
operands. Every historical bar bug here was a numerator covering a wider
population than its denominator — the `326700%` and `228600%` bars, the
105.3%/172.6% matrix overcount. A recording lets you assert "the page shows
what the API said"; it cannot tell you whether either is *right*.

`fake_ghidra.py` is built so the right answer is known in advance: 50
functions of which 10 are `LIB_CRT`, 28 of the remaining 40 carrying a rung,
20 globals of which 2 are `Scope`-excluded and one address carrying two
labels. So `in_scope` must be 40 and 18, the never-evaluated cell must be
exactly 12, and the one-row-per-address rule has something to actually trip
on.

An endpoint the fake does not model raises loudly rather than returning
`{}` — a panel reading an unmodelled endpoint would otherwise render "no
data" and its test would pass against nothing.

## Files

| File | Covers |
| --- | --- |
| `fake_ghidra.py` | the synthetic program + the `install()` seam |
| `conftest.py` | sandboxed state, fake monitors, the `Harness` client, fault injection |
| `test_smoke_harness.py` | the harness itself — the fake is wired, the monitors started, the corpus arithmetic is what the tests assume |
| `test_route_contract.py` | every GET route answers; response keys the template reads; the bar arithmetic; the 7.0.0 envelope regression; degradation when Ghidra dies |
| `test_fault_injection.py` | the four oracle shapes, Ghidra offline, a broken probe, a paused fleet |

## The two strict xfails

Both record **real, currently-unfixed defects** found by this tier. They are
`strict=True`, so each becomes a *failure* the moment the underlying bug is
fixed — which is what stops the list from outliving the defect.

1. **Eight panels 500 during a Ghidra restart.**
   `matrix`, `bands`, `intake`, `inventory`, `glob_bands`, `globals`,
   `binaries/progress` and `recommended` raise instead of degrading.
   Root cause: `_function_rows` and `_global_rows` are the only two `_get`
   call sites in `conformance_dashboard` without `except OSError`. Every
   other reader there degrades. A Ghidra restart is routine — `tools.setup
   deploy` performs one every time.

2. **A broken oracle probe 500s the whole health strip.**
   `get_health_summary`'s own docstring promises *"Never raises: a broken
   probe reports `unknown` for its own dot rather than 500-ing the whole
   strip."* `_health_oracle` guards its `get_state()` call; `_health_dashboard`
   does not — it reads the same monitor unguarded, just for the `elevated`
   flag.

`test_routes_that_degrade_today_keep_degrading` is the guard with teeth
right now: it fails the moment a *new* uncaught `_get` is added to a path
that currently survives.

## Adding a test

Assert against the corpus constants in `fake_ghidra.py`, not against magic
numbers. If a corpus edit changes them,
`test_corpus_arithmetic_is_what_the_tests_assume` fails first, with a clear
message, instead of eleven confusing failures elsewhere.

If a check needs a browser to be meaningful — anything about *rendering* —
it belongs in `tests/e2e`, not here.
