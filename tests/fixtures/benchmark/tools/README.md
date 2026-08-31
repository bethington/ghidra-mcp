# Re-deriving the regression baseline

`regression/*.yaml` pins numbers — parameter counts, basic-block counts,
instruction counts, string counts. Those must be **measured**, never read off
the generator source and hoped for: `basic_block_count` in particular comes from
Ghidra's CFG, not from how many labels the assembler emitted.

`DumpBenchmarkFacts.java` is the measuring instrument. It reports, for a program
open in Ghidra, exactly the fields the baseline asserts, and it counts basic
blocks with the same `BasicBlockModel.getCodeBlocksContaining(body)` call that
`BinaryComparisonService` uses to answer `/get_function_signature`.

Run it against the fixture in a throwaway headless project — never against the
live GUI instance or a shared project:

```text
F:\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat ^
  %TEMP%\bmproj BenchFixture ^
  -import tests\fixtures\benchmark\Benchmark.dll ^
  -scriptPath tests\fixtures\benchmark\tools ^
  -postScript DumpBenchmarkFacts.java ^
  -deleteProject
```

`-deleteProject` removes the temporary project afterwards. Repeat for
`BenchmarkDebug.exe`.

Two caveats worth knowing before you trust the output:

* Headless runs the default analyzers. The deploy path calls `/run_analysis`
  after import, which enables a slightly richer set. Values that differ between
  the two are exactly the ones to express as `*_min` rather than pinning.
* `analyzeHeadless` reads the same Ghidra user-settings directory as a running
  GUI instance. It does not need the project that instance has open, and it must
  not be pointed at one.
