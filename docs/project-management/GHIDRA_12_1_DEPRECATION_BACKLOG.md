# Ghidra 12.1 Deprecation Backlog

`./gradlew.bat compileJava -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1_PUBLIC`
currently succeeds, but emits deprecation/removal warnings from Ghidra 12.1.
These are not release blockers for v5.11.x, but they are compatibility work
that should be paid down before the next Ghidra major/minor retarget.

Priority order:

1. Comment APIs: replace uses of deprecated `CodeUnit.*_COMMENT`,
   `Listing.getComment(int, Address)`, `Listing.setComment(Address, int, String)`,
   and `CodeUnit.setComment(int, String)` across GUI, headless, and services.
2. Import APIs: migrate `AutoImporter.importAsBinary`,
   `AutoImporter.importByUsingBestGuess`, and
   `LoadResults.getPrimaryDomainObject()` in `ProgramScriptService` and
   `HeadlessProgramProvider`.
3. Emulation APIs: evaluate the replacement path for deprecated
   `ghidra.app.emulator.EmulatorHelper` in `EmulationService`.
4. Build tooling: run Gradle with `--warning-mode all` and remove build-script
   deprecations before Gradle 10.

Acceptance criteria:

- Java compile is clean of Ghidra deprecation/removal warnings, or remaining
  warnings are documented with upstream migration blockers.
- GUI and headless endpoint behavior remains covered by the existing integration
  suites and the manual endpoint parity test.
