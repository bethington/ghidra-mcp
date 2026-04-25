"""Offline test for extract_truth.py's C-source + yaml merge.

Verifies that:
  * libclang-parsed structural data for src/crc16.c ends up in
    ground_truth.json with the expected shape.
  * truth/crc16.truth.yaml's semantic overlay is applied (synonyms,
    canonical plate, algorithm tag, weights are all merged in).
  * orphan functions (DllMain etc.) are excluded from the final map.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip(
    "clang.cindex",
    reason="benchmark truth extraction requires clang/libclang Python packages",
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = REPO_ROOT / "fun-doc" / "benchmark"
EXTRACT_SCRIPT = BENCHMARK_DIR / "extract_truth.py"
GROUND_TRUTH_FILE = BENCHMARK_DIR / "ground_truth.json"


@pytest.fixture(scope="module")
def ground_truth() -> dict:
    """Re-run extract_truth.py at test time so the test exercises the
    whole parse pipeline, not a stale on-disk JSON. We invoke as a
    subprocess to match how `python extract_truth.py` is actually
    used and to avoid importing (and caching) the module globally.
    """
    result = subprocess.run(
        [sys.executable, str(EXTRACT_SCRIPT)],
        cwd=str(BENCHMARK_DIR),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"extract_truth.py failed:\n{result.stderr}"
    return json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))


def test_crc16_structural_parsed_correctly(ground_truth):
    assert "calc_crc16" in ground_truth["functions"]
    fn = ground_truth["functions"]["calc_crc16"]

    # Structural data from libclang
    assert fn["name"] == "calc_crc16"
    assert fn["return_type"] == "unsigned short"
    assert len(fn["parameters"]) == 2
    assert fn["parameters"][0]["name"] == "data"
    assert fn["parameters"][1]["name"] == "length"

    # Locals: crc, byte_index, bit_index (order defined by source)
    local_names = [l["name"] for l in fn["locals"]]
    assert "crc" in local_names
    assert "byte_index" in local_names
    assert "bit_index" in local_names


def test_crc16_semantic_overlay_merged(ground_truth):
    fn = ground_truth["functions"]["calc_crc16"]

    # Semantic data from truth.yaml
    assert "CalcCrc16" in fn.get("name_synonyms", [])
    assert fn["algorithm_tag"] == "CRC-16-CCITT"
    assert "XMODEM CRC" in fn.get("algorithm_synonyms", [])
    assert "CRC-16" in fn["canonical_plate"]
    assert fn["weights"]["name"] == 0.25
    assert fn["weights"]["signature"] == 0.25


def test_dllmain_not_scored(ground_truth):
    """Boilerplate functions (DllMain) have no truth.yaml and should
    not appear in the merged map — they won't be scored."""
    assert "DllMain" not in ground_truth["functions"]
