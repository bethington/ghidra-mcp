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

## The move was incomplete, and only running the tests showed it

`tests/unit/test_address_map.py` moved. `tests/fixtures/dll_exports/D2Common.txt`,
the data it reads, did not — it was tracked here, and only the *test* was in the
moved set. Run in the new repo, all six `TestOrdinalParsing` cases failed with
`FileNotFoundError`, and the debugger suite was **6 failed, 165 passed**.

Nothing caught this earlier because the byte-identity check answers "did the
files I chose arrive intact", not "did I choose the right set". A file-by-file
verification is blind by construction to a file that was never on the list. The
thing that found it was **executing the moved tests in their new home** — the
only check that consults the code's real dependencies rather than my list of
them.

Fixed in `d2-game-exe` `cf276c8` (fixture verified byte-identical, sha256
`0cb01e9d…`), removed here in the same pass since its only consumer had already
left. Suite there is now **171 passed, 1 skipped**.

The general rule: after moving code, *run it*. Byte-identity is necessary and
nowhere near sufficient.

## Closed

- **The import branch is merged.** `import/ghidra-mcp-tooling` (`af2ebda`) landed
  in `d2-game-exe` `main` as merge `ababd88` on 2026-08-11 — 85 files,
  +28,848 lines, zero conflicts. It merged into a `main` carrying unrelated
  in-flight minimax work; path overlap with both the modified and the untracked
  files was checked and was empty before merging, and that work was confirmed
  untouched afterwards.
- **`scripts/d2probe/` has an owning repo.** D2MOO `tools/d2probe/`, commit
  `c9438d6`, on `master` and `pd2-focus` and pushed to `origin/pd2-focus`.
  Verified by sha256 against the blobs deleted here: **21 of 22 byte-identical**,
  the 22nd being `README.md`, rewritten for the new home rather than lost.
- **The `ghidra-mcp` side is published.** `origin/main` and `origin/dev` are both
  at `c4d1ced`; the whole refocus is upstream, not sitting on a local branch.

## Known defect in what stayed

`ghidra_scripts/Repair_AutoFixOrdinalLinkage.java:182` hardcodes
`C:\Users\benam\source\mcp\ghidra-mcp\dll_exports` unconditionally. Header-stripped
its logic is generic ordinal-linkage repair, so keeping it was right — but in a
public repo it aborts with "DLL exports directory not found" for every user but
one. Kept-because-generic and actually-usable-by-anyone are different bars, and
the classification pass only measured the first.
