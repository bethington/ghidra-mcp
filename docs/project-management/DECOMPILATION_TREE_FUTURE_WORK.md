# Decompilation DecompTree — Future Work

Parked during the 7.2.0 tree work (commits `a3e5bb4`..`7a76ab8`). Everything
here was either measured and deferred, or found while building something else.
Items carry their evidence so nobody has to re-derive it.

Design record: `~/.claude/plans/proud-imagining-charm.md`.

---

## 1. Multiple views into one unchanged binary (carving)

The motivating case: the TC-Helicon keyboard firmware
(`firmware_reconstructed.bin`) is a flat 284 KB dump hand-carved into nine named
blocks — `ram` @ `08005000`, `SRAM` @ `20000000`, `config_header`, `keymaps`,
`fn_layers`, `macros`, `userpics`, `calib_data`, `magnetism`. That carving is
destructive-ish: there is one layout, and trying an alternative means editing it.

Ghidra already supports non-destructive alternatives; the MCP surface does not
expose them. All APIs below verified against the installed 12.x jars:

* **`FileBytes` is the immutable substrate.** `Memory.getAllFileBytes()`,
  `createFileBytes(name, offset, size, stream, monitor)`, and crucially
  `FileBytes.getOriginalByte(off)` **vs** `getModifiedByte(off)` — the original
  import survives patching. Memory blocks are *views* onto ranges of it.
* **`Memory.locateAddressesForFileBytesOffset(fileBytes, offset)`** returns
  **every address** a given file byte is currently mapped at. This is a reverse
  index from file offset to all views — exactly the cross-check that makes a
  speculative carving safe ("is the byte I am reasoning about at `08005000`
  really file offset `0x5000`?").
* **`Memory.createInitializedBlock(name, start, FileBytes, offset, len, overlay)`**
  — N blocks may reference the same file range at different addresses, no copy.
* **`Memory.createByteMappedBlock(name, start, mappedFrom, len, ByteMappingScheme, overlay)`**
  — the block's bytes *are* another block's bytes (a live view, not a copy).
  `ByteMappingScheme` handles non-1:1 (e.g. one byte per two on word-addressed
  devices). See also `MemoryBlockType.BYTE_MAPPED` / `BIT_MAPPED`.
* **`overlay=true`** puts the block in its own address space, so one file offset
  can live at `bank0:8000` *and* `bank1:8000` simultaneously.
* **Multiple Program Trees.** `Listing.createRootModule(name)` creates an
  *additional* tree; `getTreeNames()` enumerates them and the GUI tabs them. One
  program can carry a "by peripheral" and a "by subsystem" organisation at once.

### Proposed work

1. Extend `/create_memory_block` (`ProgramScriptService.java:2768`). It currently
   exposes only `name`, `address`, `size`, `read`/`write`/`execute`/`volatile`,
   `comment` — no overlay, no mapping, no `FileBytes` backing. Add `overlay`,
   `mapped_from` (byte-mapped), `file_offset` (+ length) for FileBytes-backed
   blocks.
2. New READ_ONLY `/locate_file_offset` wrapping
   `locateAddressesForFileBytesOffset`.
3. Consider letting the tree materialise **several layouts** of one corpus by
   mirroring multiple Program Trees, rather than only the partition cascade.

**Caveat, already load-bearing elsewhere:** overlay spaces make bare addresses
ambiguous, which is why `ServiceUtils.addressToJson` qualifies them as
`space:hex`. `ls` already has three overlay spaces (`.shstrtab`,
`.gnu_debuglink`, `_elfSectionHeaders`) and rendered `.shstrtab::00000000` in its
Program Tree. DecompTree filenames need the same treatment once more than one space
holds functions — carving into overlays would exercise that path for real.

---

## 2. Known warts in the shipped tree

* **Cancel mislabels the in-flight function.** Stopping a sweep writes
  `// DECOMPILATION FAILED: … Stream Closed` for the function that was being
  decompiled. That is the cancel (`DecompInterface.stopProcess()`), not a defect
  in the binary, and it inflates `functions_failed`. Distinguish cancel-induced
  from genuine failure.
* **~8 ms/function of unprofiled sweep overhead.** `ls` ran 17 ms/fn against a
  measured 7.8 ms raw decompile. The 10% throttle is a duty cycle (verified: it
  sleeps only after 250 ms of held CPU), so it is not the cause. Suspects, in no
  particular order: header render, `fp` hashing, `emit.text().getBytes(UTF_8).length`
  (encodes the whole function text just to count bytes), StringBuilder growth.
  **Profile before optimising** — the realistic target size is DLL-scale, which
  sweeps in 28 s.
* **`decompile_timeout_seconds` is the wall-time knob and it is blunt.** On `ls`,
  **8 pathological functions each burned the full 30 s = 240 s of a 669 s sweep
  (36%)**. Options: a lower default with the failures recorded, or a two-pass
  scheme (fast pass, then retry the timeouts at a longer budget).

---

## 3. Deferred from the tree plan

* **Write-back.** The tree is generated output. `fp` already ships in every block
  header specifically as the apply-time stale-base check, so the layout is ready;
  the `apply` step (parse an edited plate block / renamed file back into
  `set_comment` / `rename_function`) is a second product.
* **Writing the Ghidra Program Tree** — `/partition_program?apply=true`. There is
  **zero** Program Tree write API usage anywhere in this repo, and it is a program
  WRITE with transaction and undo semantics. Its own commit.
* **`bin/stale`** — a local `fp`/`dts` join answering "which files are stale" with
  zero Ghidra calls. Falls out of `STATUS.md` + the block headers.
* **Per-function incremental resweep.** Ghidra has no per-function staleness
  primitive, and a DLL resweep is 28 s. Today: missing-files-only (widening) or
  everything (repartition). Block splicing (`/decompile_tree_refresh`) already covers
  the labelling case.
* **`name:` regex exclusions.** Deliberately cut in favour of tag/partition/range.
  Reconsider once naming is well underway.
* **`git init` in the tree.** Diffing decompilation across sessions is genuinely
  valuable and is a second sync problem plus 25k-file commits.
* **MoJoFM partition scoring.** `fun-doc/benchmark/` compiles `Benchmark.dll` from
  known `src/*.c`, so translation-unit membership is known **by construction** —
  the only ground truth available for scoring compartment quality. Until it
  exists, `modules/index.md` correctly says compartments are *coherent but
  unscored*.

---

## 4. Partitioning strategies not implemented

Measured during design; each failed or was not reached. See the plan for numbers.

* **Omnipresent-node stripping before graph clustering** (Mancoridis et al.,
  *Bunch*, 1998). Utility hubs connect to everything and collapse every cluster
  into one — measured here as a single label-propagation community of **703 of
  906** functions. Strip top-k by degree, cluster, re-attach.
* **Degree-corrected stochastic block model** (Karrer & Newman 2011). No
  resolution limit, and it can express hub-and-satellite structure that modularity
  structurally cannot. Best theoretical fit for a call graph.
* **Infomap** — map equation over a directed flow graph, which a call graph is.
* **METIS / KaHIP** — only if a *hard* balance constraint is wanted; the byte-budget
  file splitter already gives predictable file sizes.
* **Dominator-tree grouping** (Lengauer–Tarjan, near-linear). A function dominated
  by X is unreachable except through X — a principled generalisation of
  single-caller absorption, which measured only **8%**. The call graph is
  effectively a **DAG** (<1% of functions are in cycles), so this is well-behaved.

**Do not revisit `ParallelDecompiler`.** Verified genuinely parallel (10 threads,
9 concurrently in flight, 10 `configure()` calls) and **1.01×** — throughput is
`ProgramDB`-lock-bound at ~128 fn/s.

**Untested hypothesis worth an hour:** that lock is per-`ProgramDB`, so
*cross-program* sweeps may scale even though intra-program never does. Relevant to
the fun-doc 5-DLL corpus. Needs two programs open in one instance.

---

## 5. Repo-level items found while building this

* **`get_function_signature` is misnamed.** It returns structural metrics
  (instruction count, cyclomatic complexity, basic-block hashes, string constants,
  immediates) for cross-binary comparison — not a signature. `get_function_fingerprint`
  would fix a name that actively misleads. Second such case after
  `get_bulk_function_hashes`.
* **Tool folds identified but not done** (each loses nothing):
  `analyze_function_complete` → `get_function_bundle` (strict superset: 12 of 14
  keys shared, the other two derivable); `list_methods` → `find_functions` (it
  returns bare strings — a response-contract violation — and is `find_functions`
  minus every filter); the three `get_current_{address,function,selection}` → one
  `get_current_location`; `force_decompile` → a `refresh` param on
  `decompile_function`; `get_xrefs_from` gaining `addresses=` for symmetry with
  `get_xrefs_to`.
* **Function sub-resources**, e.g. `ghidra://function/{p}/{addr}/disassembly`,
  `/pcode`, `/fingerprint`, `/callers`. Verified feasible: FastMCP's matcher is
  `re.match("^…$")` with `[^/]+` per variable, so a 4-segment URI cannot be
  swallowed by the 2-segment bundle template. **Sections must be literal
  segments**, never a `{section}` variable — `{program}/{address}/{section}` would
  shadow the existing `{program}/by-name/{name}` template, and `ResourceManager`
  takes the first matching template in registration order with no ambiguity check.
  Note this is additive, not a tool-count reduction: resources are strictly
  additive because clients without resource support still need the tools.
* **Pre-existing test failures**, neither caused by nor fixed by this work:
  6 errors in `com.xebyte.offline.ProgramStorageEndpointsValidationTest`
  (`NoClassDefFoundError: org/jdom/output/XMLOutputter` + a Mockito
  `UnfinishedStubbingException`), and 2 in `tests/unit/test_gradle_tasks.py`
  (Gradle cannot resolve `:runtimeClasspath` in this environment).
