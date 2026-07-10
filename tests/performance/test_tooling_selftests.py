"""Run the port-pipeline tooling modules' built-in `_selftest()` known-answer
checks as offline CI gates.

Each of these modules ships a self-contained `_selftest()` that validates its
core pure logic against inline fixtures -- no Ghidra, oracle, network, or
external repo. Running them here turns those authored known-answer checks into
enforced regression gates (and exercises the modules' logic under coverage).

`d2moo_names._selftest()` is intentionally NOT run here: it loads struct headers
from an external D2MOO checkout that doesn't exist in CI. Its pure parsing/
derivation logic is covered by test_d2moo_names.py with an inline fixture.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))


# abi_static / fast_path / bench_score have dedicated test modules that already
# run their _selftest() plus direct checks; these five are gated only here.
@pytest.mark.parametrize(
    "module_name",
    [
        "prove_doc",
        "bench_d2common",
        "golden_bench",
        "ledger_apply",
        "verify_shadow_fix",
    ],
)
def test_module_selftest_passes(module_name):
    module = __import__(module_name)
    assert hasattr(module, "_selftest"), f"{module_name} lost its _selftest()"
    assert module._selftest() == 0, f"{module_name}._selftest() reported failure"
