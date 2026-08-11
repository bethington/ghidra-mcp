# Refocus plan — reduce this repo to the Ghidra MCP server

**Status:** draft for review. Nothing in the "needs sign-off" tables has been
executed. Two safe items were executed on 2026-08-11 and are marked DONE.

**Decisions this plan implements** (agreed 2026-08-11):

| Decision | Choice |
| --- | --- |
| Destination for evicted work | Decide per item |
| Boundary | **Strict core** — server + bridge only |
| History | Remove going forward, **keep history** (no rewrite) |
| Execution | Plan doc + safe quick wins now; the rest waits for sign-off |

No history rewrite means every removal stays recoverable with
`git checkout <deleting-commit>^ -- <path>`, and the 7 open PRs are unaffected.
That is the whole reason the choice matters: a rewrite would have invalidated
every outstanding contributor branch.

---

## 1. Where the repo actually stands

Tracked files by top-level directory, measured 2026-08-11 *after* the d2probe
removal below:

| Dir | Files | Verdict |
| --- | --- | --- |
| `tests/` | 183 | **Core** (but see §4 — some tests move with their subject) |
| `ghidra_scripts/` | 172 | **Split** — 118 D2-specific, 42 generic, 12 misc |
| `src/` | 118 | **Core** — the Ghidra plugin itself |
| `docs/` | 81 | **Split** — workflow prompts are fun-doc's, not the server's |
| `scripts/` | 16 | **Mostly moves** |
| `tools/` | 17 | **Split** — `setup/` is core, the rest is not |
| `python/` | 15 | **Core** — the bridge |
| `debugger/` | 11 | **Moves** (largest judgement call; see §3) |
| `.github/` | 11 | Core |
| `docker/` | 6 | Core |

Two big items already left and need no further action:

- **`fun-doc/`** — already untracked; 0 tracked files. CLAUDE.md records the
  2026-08-11 move to `d2-game-exe`. Only gitignored runtime droppings remain on
  disk (`logs/`, `state.db`, `priority_queue.json`). Safe to delete locally
  whenever; git does not see them.
- **`d2-analysis/`** — gitignored, 14,768 files, never tracked.

---

## 2. Executed now (safe, unambiguous)

### DONE — `scripts/d2probe/` removed

22 files, 919 lines. This is the exact cautionary tale CLAUDE.md's scope
section already names: committed 2026-08-02 *after* being identified as
out-of-scope in its own README, on the reasoning that the wrong repo beat no
repo. Nothing outside itself referenced it except that CLAUDE.md paragraph,
which has been updated to past tense with the recovery command.

**Outstanding:** these files still have no owning repo. Deleting them here only
stopped this repo from being the answer by default; it did not give them a
home. Restoring them into D2MOO is the other half of the fix.

### DONE — dangling `fun-doc` references in tests

`tests/unit/test_no_default_data_egress.py` was **failing on disk right now**,
not merely in CI: it did `_read("fun-doc/fun_doc.py")` against a path that no
longer exists. Fixed by dropping the fun-doc assertion (that check travels with
fun-doc) and removing `"fun-doc"` from `checked_roots`. The Java-side
assertions — which are what this repo actually ships — are untouched. Suite is
green (4 passed).

The other three hits are **comments only** and compile/run fine:
`tests/integration/conftest.py`, `tests/integration/test_endpoint_registration_parity.py`,
`tests/conformance/run_conformance.py`. They mention "fun-doc worker fleet" as
rationale. Recommend leaving the text as-is — it explains *why* a concurrency
assumption exists, and that reasoning is still true of any external client.

---

## 3. Needs sign-off — the real extractions

### 3a. `ghidra_scripts/` — split, do not move wholesale

This is the item where the strict-core boundary is most expensive, so it gets
the most evidence.

Measured by **content** (grep for `D2Common|D2Client|D2Game|Diablo|UnitAny|d2moo|PD2|Storm.dll|Fog.dll`),
not filename — filename classification undercounts by 20× (6 vs 118):

| Class | Count | Recommendation |
| --- | --- | --- |
| D2-specific `.java` | 118 | → D2MOO or a `d2-ghidra-scripts` repo |
| Generic `.java` | 42 | **Stay** — these are legitimate companions to a Ghidra MCP server |
| `.py` + misc | 12 | Triage individually |

**A correction worth recording:** I initially reported the Java server as
*depending* on `ghidra_scripts/`. It does not. All twelve references in
`GhidraMCPPlugin.java`, `ProgramScriptService.java`,
`GhidraMCPHeadlessServer.java` and `HeadlessEndpointHandler.java` resolve
`~/ghidra_scripts` (user home) or `./ghidra_scripts/` as a **runtime search
path** for the `run_ghidra_script` endpoint. Moving the directory would not
break the build or the server — it would only mean the repo ships no scripts.

**Coupling that does break:** `tests/unit/test_no_default_data_egress.py` has
two guards that read this directory — `test_bsim_scripts_have_no_default_destination`
(asserts BSim scripts carry no literal destination URL) and
`test_bsim_credentials_file_is_not_committed` (asserts `db.env` is untracked
and `db.env.example` exists). Both assert-on-empty is *not* protected in the
first case: it does `assert scripts, "glob is matching nothing"`, which is
correct and will fail loudly rather than silently pass. **If the 17 BSim
scripts move out, that guard must move with them** — it is a real
password-leak guard, and its docstring records that a rename already retired it
once before.

**Recommendation:** move the 118 D2-specific scripts; keep the 42 generic ones
plus `README.md`; move `db.env.example` + both BSim guards along with the BSim
scripts to wherever they land.

### 3b. `debugger/` — the largest judgement call

11 tracked files, a standalone HTTP server on port 8099. Strict core says it
goes. Three facts argue for care:

- The **bridge proxies 22 debugger tools** via `GHIDRA_DEBUGGER_URL`. Those
  proxy definitions live in `python/bridge_mcp_ghidra/debugger.py`, which is
  core and would stay. Moving the server without the proxies leaves 22 tools
  pointing at a service this repo no longer contains.
- **5 unit test files** move with it: `test_debugger_engine.py`,
  `test_debugger_server.py`, `test_address_map.py`, `test_d2_conventions.py`,
  `test_windbg.py`.
- `debugger/d2/` is explicitly D2-convention code — unambiguously game-side.

**Recommendation:** move it, and move the 22 bridge proxy tools' *registration*
behind the existing `GHIDRA_DEBUGGER_URL` env gate so the bridge degrades
cleanly to "not configured" rather than advertising tools with no server. The
gate already exists (`TestDebuggerEnabled` / `TestDebuggerToolRegistration`
cover platform gating), so this is a small change, not a rewrite.

Also moves with it: `start-debugger.ps1`, `install-debugger-scheduled-task.ps1`,
`start-oracle.ps1`, `tests/conformance/corpus/debugger_live.yaml`.

### 3c. `scripts/` — 16 files

| Path | Files | Recommendation |
| --- | --- | --- |
| `scripts/fid/` | 9 | Move — VC6/VS2003 FID database building is D2-toolchain work |
| `scripts/bsim/` | 2 | Move with the BSim scripts (3a) |
| `scripts/ghidra/` | 2 | **Stay** — Ghidra project utilities |
| `scripts/upgrade_project_language.py` | 1 | **Stay** — SLEIGH language upgrades; has a unit test; CLAUDE.md documents it as the fix for a Ghidra-upgrade failure mode |
| `scripts/launch-ghidra-scoped.ps1` | 1 | **Stay** |
| `scripts/ghidra_server_health_check.py` | 1 | **Stay** |

### 3d. `tools/` — 17 files

| Path | Recommendation |
| --- | --- |
| `tools/setup/` | **Stay** — the build/deploy backend; core |
| `tools/gen_readme_api_reference.py` | **Stay** |
| `tools/context_analysis/` (3) | Move or delete — LLM context measurement, not server work |
| `tools/scyllahide/` (1 README) | Move — anti-anti-debug tooling is game-side |

### 3e. `docs/` — 81 files

`docs/prompts/` holds `FUNCTION_DOC_WORKFLOW_V5.md`,
`DATA_TYPE_INVESTIGATION_WORKFLOW.md`, `STRING_LABELING_CONVENTION.md`. These
describe **fun-doc's** documentation workflow, not the server's API. They
should follow fun-doc to `d2-game-exe`.

`docs/prompts/TOOL_USAGE_GUIDE.md` **stays** — it is the operator guide for
this server's 253 tools and CLAUDE.md names it as authoritative.

---

## 4. What this costs — stated plainly

Splitting is not free, and the plan should say so rather than only list wins:

1. **The single-commit/single-CI relationship is gone.** CLAUDE.md already
   records this for fun-doc. Today a response-envelope change and its consumer
   fix land in one commit and one CI run. After the split they cannot. A
   contract change here can break a consumer at a distance, silently.
   *Mitigation:* the response-contract tests (`test_response_schemas.py`,
   `test_response_contract_callers.py`) become the interface guard and should
   be treated as such — they are no longer just internal hygiene.

2. **`tests/` shrinks by more than the moved directories suggest.** Debugger
   alone takes 5 unit test files. The BSim guards take real security coverage
   with them. A refocus that *reduces* this repo's security-test surface has
   gone wrong; those guards must land somewhere, not evaporate.

3. **The 42 generic Ghidra scripts are an asset**, not residue. A Ghidra MCP
   server that ships zero Ghidra scripts is a narrower product than one that
   ships 42 useful ones.

---

## 5. Recommended order

1. ~~`scripts/d2probe/`~~ — DONE
2. ~~dangling `fun-doc` test references~~ — DONE
3. `tools/scyllahide/`, `tools/context_analysis/` — 4 files, zero coupling
4. `docs/prompts/` workflow docs → `d2-game-exe` (keep `TOOL_USAGE_GUIDE.md`)
5. `scripts/fid/` → D2MOO or `d2-game-exe`
6. `ghidra_scripts/` split — 118 out, 42 stay, **BSim guards move with BSim**
7. `debugger/` + its 5 tests + 3 `.ps1` files, with the bridge proxy gated
8. Update CLAUDE.md's scope list, `AGENTS.md`, and `README.md` to match

Steps 3–5 are low-risk and independently reversible. Step 6 needs the
egress-guard decision made first. Step 7 is the only one that changes what the
bridge advertises to MCP clients, and should be its own PR.

---

## 6. Open question for you

`ghidra_scripts/` is the one place where strict-core and usefulness genuinely
conflict. The 42 generic scripts (convention detection, orphan-code finding,
function-parameter repair, padding analysis) are exactly the kind of thing
someone installing a Ghidra MCP server would want, and they are not D2 work.

My recommendation is the split in 3a — keep them. The alternative, moving all
172 for a clean boundary, trades a real capability for a tidier tree. Say the
word if you'd rather have the clean boundary and I'll take all 172.
