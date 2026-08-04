"""Undocumented -> documented, over the whole of Benchmark.dll.

Three prerequisite levels, each self-skipping:

* **no prerequisites** -- the name-heuristic control below runs anywhere.
* **a dedicated Ghidra** -- the clean-room precondition and the byte-exact
  library control. No tokens are spent; these are the cheapest high-value
  checks in the tier and they exercise the lanes a pinned per-function run
  never reaches.
* **``--real-provider``** -- the documentation pass itself.

The corpus is the WHOLE binary, not the nine authored functions. That is the
point: a pinned run never exercises the selector, `library_code_detector`,
`crt_identify` or the FID tier-0 lane, and those are precisely the
subsystems that silently mislabel real code when they break. `Benchmark.dll`
is the only binary in the project with ground truth about which functions
are hand-written, so it is the only place the "0 authored functions claimed
as library" control can be measured rather than believed.
"""

from __future__ import annotations

import pytest

import floors

pytestmark = pytest.mark.benchmark_e2e


# --------------------------------------------------------------------------
# no prerequisites: the name heuristic, against the authored names
# --------------------------------------------------------------------------


def test_the_name_heuristic_never_claims_an_authored_function(authored_functions):
    """`library_code_detector` must not classify hand-written code from its
    name alone.

    This is the cheap half of the control and it needs nothing but the
    ground-truth name list. It is worth having separately because a name
    rule is the easiest thing to over-broaden: `RUNTIME_PREFIXES` once made
    `CRT_`-prefixed hand-written functions read 87% "non-library", and the
    inverse mistake is what this catches.
    """
    from library_code_detector import detect_library_code

    claimed = []
    for name in authored_functions:
        result = detect_library_code(name=name, decompile=None, callees=None)
        if result.is_library:
            claimed.append((name, getattr(result, "reasons", None)))
    assert not claimed, (
        "the name heuristic claimed hand-authored functions as library code. "
        "LIB_CRT makes the selector skip a function PERMANENTLY, so this "
        f"silently deletes them from the corpus: {claimed}"
    )


# --------------------------------------------------------------------------
# dedicated Ghidra, no tokens
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def program_functions(ghidra, benchmark_program):
    resp = ghidra.get("/list_functions", program=benchmark_program, limit=100000)
    fns = resp.get("functions") if isinstance(resp, dict) else None
    if not fns:
        pytest.skip(
            f"{benchmark_program} has no functions on the dedicated instance -- "
            f"import Benchmark.dll and let auto-analysis finish first"
        )
    return {str(f["address"]).lower().replace("0x", ""): f.get("name") or "" for f in fns}


def test_the_binary_is_actually_loaded(program_functions):
    """A corpus of one is a corpus that proves nothing."""
    assert len(program_functions) >= 20, (
        f"only {len(program_functions)} functions; Benchmark.dll links a static "
        f"CRT and should carry well over twenty"
    )


def test_the_authored_functions_are_all_present(program_functions, authored_functions):
    """Ground truth has nine entries; the binary must contain all nine.

    `extract_truth.py` derives the answer key from the C sources, NOT from
    the compiled binary, so the two can drift -- a source function that got
    inlined away is scored forever against something that is not there.
    """
    present = set(program_functions.values())
    missing = [n for n in authored_functions if n not in present]
    assert not missing, (
        f"ground truth scores {missing}, which are not in the loaded binary. "
        f"Either the fixture is stale (re-run build.py + the import) or the "
        f"compiler inlined them away and the answer key needs regenerating."
    )


def test_the_baseline_really_is_undocumented(program_functions, authored_functions):
    """The clean-room precondition.

    "Undocumented -> documented" measures nothing if the starting state was
    already documented by a previous run. Every function that is NOT one of
    the nine authored ones and not a linked CRT symbol should still carry a
    Ghidra default name.
    """
    import re

    default = re.compile(r"^(FUN_|SUB_|thunk_FUN_)", re.I)
    authored = set(authored_functions)
    documented = [
        name
        for name in program_functions.values()
        if name and not default.match(name) and name not in authored
        and not name.startswith("_") and not name.startswith("@")
    ]
    # The linked CRT arrives with real symbol names from the .lib, so a
    # nonzero count here is expected; what must not happen is the corpus
    # arriving already documented in fun-doc's own PascalCase convention.
    pascal_documented = [n for n in documented if re.match(r"^[A-Z][a-z]+[A-Z]", n)]
    assert not pascal_documented, (
        "the fixture is not a clean room -- these carry fun-doc-style names "
        f"before the run started: {pascal_documented[:10]}. Reset it via "
        f"`tools.setup deploy`, which calls reset_benchmark_fixture."
    )


def test_byte_exact_crt_identification_never_claims_an_authored_function(
    ghidra, benchmark_program, authored_functions, monkeypatch
):
    """The positive control, at the byte level, over the WHOLE binary.

    `crt_identify` compares each function's bytes against the real static
    runtimes and either matches exactly or abstains. Run over Benchmark.dll
    it should claim the linked CRT (`_strlen`, `_memset`, ...) and abstain on
    all nine authored functions. Zero of the nine, ever -- an ambiguous or
    weak match must write NOTHING, because `LIB_CRT` is permanent.
    """
    import crt_identify

    # `crt_identify._get` resolves its URL at module level, so it would talk
    # to 8089 regardless of --benchmark-ghidra-url. Re-point it.
    monkeypatch.setattr(
        crt_identify,
        "_get",
        lambda path, **params: ghidra.get(path, **params),
        raising=False,
    )
    monkeypatch.setattr(
        crt_identify,
        "_post",
        lambda path, program, body: ghidra.post(path, body, program=program),
        raising=False,
    )

    try:
        index = crt_identify.load_index()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"no MSVC runtime libraries indexable on this box ({exc})")
    if not getattr(index, "functions", None) and not len(getattr(index, "by_size", {}) or {}):
        pytest.skip("library index is empty; nothing to match against")

    matches = crt_identify.identify_program(benchmark_program, index=index)
    claimed_names = {m.current_name for m in matches if m.current_name}
    violations = floors.check_no_authored_function_claimed_as_library(
        authored_functions, claimed_names
    )
    assert not violations, "\n".join(str(v) for v in violations)


def test_crt_identification_actually_claims_the_linked_runtime(
    ghidra, benchmark_program, monkeypatch
):
    """The negative control's mirror: a detector that claims NOTHING also
    passes the "never claims an authored function" test.

    Benchmark.dll links a static CRT, so a healthy detector finds some of it.
    Zero matches means the index or the masking broke, and the control above
    would have gone quietly green on a dead detector.
    """
    import crt_identify

    monkeypatch.setattr(
        crt_identify, "_get", lambda path, **params: ghidra.get(path, **params), raising=False
    )
    try:
        index = crt_identify.load_index()
        matches = crt_identify.identify_program(benchmark_program, index=index)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"crt_identify unavailable here ({exc})")
    assert matches, (
        "crt_identify found NOTHING in a binary that statically links the CRT. "
        "The 'never claims an authored function' control cannot distinguish a "
        "careful detector from a dead one, so this is the check that keeps it "
        "honest."
    )


# --------------------------------------------------------------------------
# the documentation pass itself -- spends tokens
# --------------------------------------------------------------------------


@pytest.mark.real_provider
@pytest.mark.slow
def test_full_documentation_pass(
    ghidra,
    benchmark_program,
    authored_functions,
    baseline_run,
    fundoc_sandbox,
    request,
):
    """Document every authored function, then hold the result to the floors.

    Mechanical floors are hard failures; semantic quality is a delta against
    the committed `runs/latest.json`. See `floors.py` for why the two halves
    are gated differently.
    """
    import os

    import run_benchmark

    monkeypatch = request.getfixturevalue("monkeypatch")
    runs_dir = fundoc_sandbox / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(run_benchmark, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(run_benchmark, "LATEST_FILE", runs_dir / "latest.json")
    monkeypatch.setenv("FUNDOC_BENCHMARK_PROGRAM", benchmark_program)
    # `ghidra_bridge` binds GHIDRA_URL at import; set it before the runner
    # imports it so the pass writes to the DEDICATED instance.
    os.environ["GHIDRA_SERVER_URL"] = ghidra.base

    run = run_benchmark.run(
        tier="fast",
        mock=False,
        variant="baseline",
        provider="minimax",
        model=None,
        full_matrix=False,
    )

    report = floors.evaluate(
        run,
        baseline=baseline_run if (baseline_run or {}).get("mock") is False else None,
        authored=authored_functions,
        library_claims=[],
    )
    assert report.ok, "\n" + report.format()
