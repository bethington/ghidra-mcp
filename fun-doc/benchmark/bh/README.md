# BH.dll documentation-quality regression (tier-2 smoke)

Real-world ground-truth grading for fun-doc's documentation output, using
[Project-Diablo-2/BH](https://github.com/Project-Diablo-2/BH) (Apache 2.0,
compatible with this repo's license) as the source-of-truth oracle.

## Why this exists

The existing `fun-doc/benchmark/` harness grades documentation against 5
archetype functions hand-authored in `fun-doc/benchmark/src/*.c`. Useful
but synthetic — won't catch regressions in worker behavior on *real* code.

Tier-1 smoke (`fun-doc/scripts/v58_smoke.py`) confirms the persistence layer
works end-to-end mechanically — runs land in the DB, function rows update,
nothing crashes. **What it cannot tell you** is whether the worker's
*documentation quality* drifted across a release.

This harness closes that gap. BH.dll has:

- ~6,700 functions
- An open-source upstream we can read line-by-line
- A 1:1 export-table mapping for ~9 well-known entry points (free name pins)
- Distinctive string literals (item-property names, error messages,
  hotkey labels) that anchor internal functions to specific source lines
- 11 feature modules (`Item`, `MapNotify`, `Party`, `ChatColor`, ...) —
  each maps to a `BH/Modules/<Feature>/` source directory

Compare what the worker produced for BH.dll → what the source actually
says → per-function score → corpus aggregate.

## Workflow (sketch — Phase 1)

```
# 1. Clone BH source (one-time)
git clone git@github.com:Project-Diablo-2/BH.git C:/Users/benam/source/BH

# 2. Ensure your fun-doc workspace has BH.dll open in Ghidra at a
#    known state (typically the production state.json snapshot)

# 3. Run the grader
python fun-doc/benchmark/bh/grade.py \
    --binary BH.dll \
    --mapping fun-doc/benchmark/bh/mapping.yaml \
    --source-root C:/Users/benam/source/BH \
    --ghidra-url http://127.0.0.1:8089 \
    --output runs/$(date +%Y%m%d-%H%M%S).json

# 4. Compare against the previous run
python fun-doc/benchmark/bh/grade.py --compare runs/latest.json runs/prev.json
```

## What gets graded

Per mapped function:

| Axis | Score | How it's computed |
|---|---|---|
| **Name exactness** | 0 / 1 | Worker's chosen name == source symbol name |
| **Name resemblance** | 0 / 0.5 / 1 | Worker's name contains the source symbol's
  meaningful tokens (e.g. `BHIs` for `BHIsReady`) |
| **Plate quality** | 0 / 0.5 / 1 | Plate first line contains expected keywords
  (e.g. for `BHIsReady`: {"ready", "init", "loaded"}) |
| **Prototype match** | 0 / 0.5 / 1 | Return type + arg count match the source |
| **Variable typing** | 0 / 0.5 / 1 | Of the worker's named locals, fraction whose
  type is consistent with what the source uses |

Per-function score = weighted sum (default: 0.3 name + 0.3 plate + 0.2 proto + 0.2 vars).
Corpus aggregate = mean across all mapped functions.

## When to run

Same trigger as the existing benchmark: **before and after any change that
could affect documentation quality.**

Things that should trigger a BH grading run:

- `fun-doc/fun_doc.py` — prompt construction, scoring, provider invocation
- `fun-doc/web.py` — worker loop, refresh logic
- `src/main/java/com/xebyte/core/NamingConventions.java` — validator changes
- Any worker-prompt change in `fun-doc/prompts/`
- Provider-routing changes
- v5.7.x release cuts (run pre-tag, attach `runs/<version>.json` to the
  release commit so blame on `runs/latest.json` shows which release moved
  the score)

## File layout

```
fun-doc/benchmark/bh/
├── README.md                   # this file
├── mapping.yaml                # source-symbol -> ghidra-address pins + truth
├── grade.py                    # the grader script
└── runs/                       # historical run output (committed alongside code changes)
```

**Not** in this directory:

- The BH source tree itself lives at `C:\Users\benam\source\BH\` (sibling
  to ghidra-mcp). It's a separate clone, separate license, separate repo.
  Don't commit it here.

## Phase 2 (deferred)

- Auto-extract truth from source comments — walk `BH/**/*.cpp`, parse
  function definitions + `// comment` blocks above them, generate truth
  YAML automatically. Mirrors what `fun-doc/benchmark/extract_truth.py`
  does for the synthetic functions.
- BSim-anchored mapping — instead of hand-pinning addresses, compute
  opcode hashes of the compiled-from-source binary (if we set up a build
  environment for BH that targets the same compiler/version), then match
  to the BH.dll in the project tree.
- Multi-binary grading — extend to `BH.dll` siblings across PD2 versions
  (1.13c, 1.13d, etc.) so we measure cross-version doc-transfer quality
  too.

## License notes

This harness reads BH source (Apache 2.0) as a reference. It does not
redistribute BH source or derivative works. The `runs/*.json` output
contains addresses + worker-assigned names from `BH.dll` (project-owned
binary), not source code from the upstream repo. License-clean.
