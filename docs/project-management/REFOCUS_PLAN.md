# Refocus — reducing this repo to the Ghidra MCP server

**Status:** executed 2026-08-11. This is the record of what moved, what stayed,
and the two measurement errors found along the way. The receiving half is
branch `import/ghidra-mcp-tooling` in `d2-game-exe` (commit `af2ebda`),
left unmerged for review.

## Decisions

| Decision | Choice |
| --- | --- |
| Boundary | Strict core — server + bridge |
| Destination | `d2-game-exe`, one destination for everything |
| History | Remove going forward, keep history (no rewrite) |
| Landing | Dedicated branch in a fresh worktree, not onto a dirty `main` |
| Sequencing | Copy → verify byte-identical → remove, same session |
| Duplicates | Delete the superseded copy, keep the category-prefixed one |

No history rewrite means every removal is recoverable and the 7 open PRs are
untouched. The recovery command was **verified working**, not assumed:

```text
git log --all --diff-filter=D -1 --format=%H -- <path>   # the deleting commit
git checkout <that-sha>^ -- <path>                       # restore
```

## What moved (84 files + a provenance note)

| Area | Files | Why it went |
| --- | --- | --- |
| `ghidra_scripts/` | 48 | Hardcoded D2 addresses, D2 binary names, D2 domain nouns |
| `debugger/` | 11 | `d2/conventions.py` is game-side; one package, so it moved whole |
| `scripts/fid/` | 9 | VC6/VS2003 FID work serves the D2 corpus. Its measured knowledge went too, as `scripts/fid/KNOWLEDGE.md` |
| `tests/unit/` | 7 | The debugger's tests |
| `docs/prompts/` | 4 | Workflows describing one corpus, not this server |
| `tests/conformance/` | 1 | `corpus/debugger_live.yaml` |
| `tools/scyllahide/` | 1 | Anti-anti-debug for the PD2-S12 oracle |
| root `.ps1` | 3 | `start-debugger`, `start-oracle`, `install-debugger-scheduled-task` |

Every file was verified **byte-identical (sha256)** at the destination before
anything was deleted here.

## Two measurement errors, both caught before they did damage

### 1. The classifier was detecting headers, not D2-specificity

The first pass grepped each script for `D2Common|Diablo|UnitAny|…` and reported
**118 D2-specific / 42 generic**. That number was wrong, and the recommendation
built on it was nearly inverted.

These scripts carry a documentation header containing `@category Diablo 2.X`.
Grepping the raw file therefore matches "Diablo" in the *header* of any script
that has one — so the classifier was really measuring **header presence**.
Older, unprefixed copies lack the header and scored "generic" while being the
same script.

Stripping the leading comment block before classifying, and judging only on
evidence that survives it — a hardcoded D2 load address (`0x6f8xxxxx`), a D2
binary name, a D2 domain noun — gives the real split:

| | first claim | measured |
| --- | --- | --- |
| D2-specific | 118 | **48** |
| Generic | 42 | **87** |
| Superseded duplicates | — | **25** |

Filename classification was worse still: it found 6.

### 2. `docs/prompts/` was assigned by guesswork

The first plan named `FUNCTION_DOC_WORKFLOW_V5.md` and
`STRING_LABELING_CONVENTION.md` as movers. Counting D2 references shows they
are generic (1 and 3 hits) and they stayed. The actual movers were
`BINARY_DOCUMENTATION_ORDER.md` (48 hits) and
`CROSS_VERSION_MATCHING_COMPREHENSIVE.md` (45), neither of which the plan
mentioned.

## What deliberately stayed

- **87 generic Ghidra scripts.** Convention detection, orphan-code discovery,
  function-parameter repair, padding analysis — they work on any binary and are
  legitimate companions to a Ghidra MCP server.
- **14 of the 17 BSim scripts** and **all three egress/credentials guards.**
  The decision recorded was to move the guards; that decision rested on the
  wrong classification, which said the BSim scripts were leaving. They are not
  — only the three D2-specific `Analyze_BSimStep{1,3,4}` moved. The stated
  principle behind the choice was *"the guards live with what they guard"*, and
  applying that principle to the corrected facts keeps them here. Moving them
  would have left 14 BSim scripts in a public repo with nothing watching for a
  hardcoded private address — the exact leak the guard's own docstring records
  having happened once already.
- **`tools/context_analysis/`.** It measures this server's own MCP tool catalog
  against an LLM context window. That is core server work; the plan was wrong
  to list it as a mover.
- **The 22 debugger proxy tools** in `python/bridge_mcp_ghidra/debugger.py`.
  They are bridge code and forward to whatever `GHIDRA_DEBUGGER_URL` names, so
  they work fine with the server hosted elsewhere. The existing env gate means
  they register only when configured.
- **The `debugger` dependency group** in `pyproject.toml`. It looked dead, but
  `tools/setup/ghidra.py` needs it for the *Ghidra TraceRmi* backend — a
  different debugger that stays. Only `--cov=debugger` was removed, the package
  it pointed at being gone.

## 25 superseded duplicates, deleted

Exact code duplicates (header stripped) where one copy carried a category
prefix and the other an older `//@author GhidraMCP` stub — e.g.
`ClearAllComments` / `Document_ClearAllComments`. Two files for one script is a
live hazard: edit one, run the other, and the difference is invisible. The
prefixed copy was kept in all 25 cases; the rule was verified by hand against
every pair, not just asserted.

## What this cost

1. **The single-commit/single-CI relationship is gone**, now for the debugger
   as well as fun-doc. The debugger's HTTP surface is a cross-repo contract:
   a route or payload change there breaks the bridge's proxies from a distance.
   `tests/unit/test_bridge_utils.py::TestDebuggerEnabled` and
   `::TestDebuggerToolRegistration` are what remain, and they only prove the
   proxies register — not that the far end still speaks the same protocol.

2. **Coverage denominator changed.** Measured after removal: **63.62%**,
   against a CI floor of 58%. The ratchet holds, and the stale comment naming
   `debugger/tracing.py` was corrected.

3. **`scripts/fid/`'s measured knowledge nearly evaporated.** The CLAUDE.md row
   holding the VS2003-vs-VC6 diagnosis was removed with the code; it was
   written to `scripts/fid/KNOWLEDGE.md` in the destination instead of lost.

## Still open

- `scripts/d2probe/` (removed earlier, 22 files) **still has no owning repo**.
  Deleting it here only stopped this repo being the answer by default.
  Restoring it into D2MOO is the outstanding half of that fix.
- The import branch is **unmerged**. Until it is, the moved files live on a
  local branch plus `ghidra-mcp` history.
