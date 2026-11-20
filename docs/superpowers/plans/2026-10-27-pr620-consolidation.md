# PR 620 consolidation implementation plan

Goal: make the combined 7.1 landing branch reviewable without adding six overlapping variable/equate tools.

Approved design: decompiler_symbols is a get_functions field; new stack locals are created through set_variables and its naming guards; list_program_items(kind=equates) reads equates; set_equate(action=apply|remove|rename) is the single writer. Typed Program/Function/Address parameters use the scanner resolver. All writes use the injected shared threading strategy. Existing contributor commits and credit remain.

- [x] Establish baseline Python/offline Java tests on exact PR head 8cf1bc234bf1c58625b4693c5b670de9e097532f.
- [x] Equate slice: write failing behavior tests for signed scalars, replacement, validation and lock coverage; implement reader consolidation and one writer; run tests.
- [x] Variable slice: write failing behavior tests for field-selective decompilation and stack-local creation/naming/overlap; implement using existing services; run tests.
- [x] Refresh invalidation dispatch, remove stale tool catalog entries, regenerate source-derived catalog and schema; update operator docs, changelog and computed counts without rewriting 7.0 history.
- [x] Run Python unit/offline suites, Java offline and real-Ghidra tests, extension build; inspect failures rather than weakening guards.
- [x] Review combined diff and prepare exact commands, test results, remaining live deployment/release limitations and an additive commit for Ben. Do not merge or publish comments.

Review risks: negative scalar signedness; old equate attached after replacement; invalid replacement deleting locals; dry-run rollback; decompiler opening for metadata-only requests; global equate rename invalidation; stale catalog descriptions and counts.

Verification: 1,106 Java tests passed (zero skips); 1,458 Python tests passed with eight platform/live-service skips. Extension build, markdown lint and Ruff F checks passed. Independent review found two local-creation hazards; both were fixed and reviewed again. Tree fixture portability/threading errors were reproduced and fixed without weakening production guards. This is merge preparation, not tagged-release evidence or a deployment to the user's running Ghidra.
