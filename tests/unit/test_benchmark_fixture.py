"""Offline guards on the deploy-regression benchmark fixture.

None of this needs Ghidra, a deploy, or a network. That is deliberate: the
fixture exists to make the deploy tiers meaningful, and a fixture whose own
correctness can only be checked by running the thing it gates is not much of a
foundation.

Three properties are pinned here.

1. **The committed binaries are what the committed generator produces.** A
   regeneration must be byte-identical, or the binary in git is an artifact
   nobody can reproduce.
2. **The regression baselines agree with the binaries about addresses.** This
   is the trap the predecessor fixture documented and could not close: its
   addresses were build observations, a toolchain change moved them all, and
   the only symptom was a red deploy gate. Here the disagreement is caught in
   milliseconds, in CI, before anyone runs a deploy.
3. **The generated machine code is correct.** On Windows the debuggee is
   executed and its exit code compared against a CRC computed in Python --
   which also proves the Windows loader accepted the images and resolved
   ``calc_crc16`` through the DLL's export table.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "benchmark"
DLL_PATH = FIXTURE_DIR / "Benchmark.dll"
EXE_PATH = FIXTURE_DIR / "BenchmarkDebug.exe"
MANIFEST_PATH = FIXTURE_DIR / "build_manifest.json"
REGRESSION_DIR = FIXTURE_DIR / "regression"


def _load_generator():
    """Import make_fixture.py by path.

    tests/fixtures/ is not a package, and the generator is deliberately
    importable stand-alone so it can be run as a script from a checkout.
    """
    spec = importlib.util.spec_from_file_location(
        "benchmark_make_fixture", FIXTURE_DIR / "make_fixture.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator():
    return _load_generator()


@pytest.fixture(scope="module")
def manifest():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


class TestCommittedFilesMatchTheGenerator:
    def test_all_three_artifacts_are_committed(self):
        for path in (DLL_PATH, EXE_PATH, MANIFEST_PATH):
            assert path.is_file(), f"{path} is missing from the checkout"

    def test_regeneration_is_byte_identical(self, generator):
        dll, exe, fresh_manifest = generator.generate()
        assert dll == DLL_PATH.read_bytes(), (
            "Benchmark.dll differs from a fresh generation. Regenerate with "
            "`python tests/fixtures/benchmark/make_fixture.py` and commit the "
            "result -- and check regression/*.yaml, because a changed image "
            "may have moved a function."
        )
        assert exe == EXE_PATH.read_bytes(), (
            "BenchmarkDebug.exe differs from a fresh generation; see above."
        )
        committed = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        assert fresh_manifest == committed

    def test_generation_is_deterministic_across_runs(self, generator):
        first_dll, first_exe, _ = generator.generate()
        second_dll, second_exe, _ = generator.generate()
        assert first_dll == second_dll
        assert first_exe == second_exe

    def test_manifest_digests_match_the_files(self, manifest):
        expected = {
            "Benchmark.dll": DLL_PATH,
            "BenchmarkDebug.exe": EXE_PATH,
        }
        for name, path in expected.items():
            payload = path.read_bytes()
            entry = manifest["images"][name]
            assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
            assert entry["size_bytes"] == len(payload)

    def test_manifest_records_what_produced_the_binaries(self, manifest):
        # The old fixture's manifest existed because two toolchains produced
        # indistinguishable PE headers. The question is the same; keep an
        # answer in the file rather than in someone's memory.
        assert manifest["producer"].endswith("make_fixture.py")
        assert manifest["generator_version"]
        assert manifest["deterministic"] is True


class TestImagesAreWellFormedPE32:
    """A structural read-back, independent of the writer that produced them."""

    @staticmethod
    def _parse(payload: bytes) -> dict:
        assert payload[:2] == b"MZ"
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        assert payload[pe_offset:pe_offset + 4] == b"PE\0\0"
        machine, section_count = struct.unpack_from("<HH", payload, pe_offset + 4)
        characteristics = struct.unpack_from("<H", payload, pe_offset + 22)[0]
        optional_offset = pe_offset + 24
        magic = struct.unpack_from("<H", payload, optional_offset)[0]
        entry_rva = struct.unpack_from("<I", payload, optional_offset + 16)[0]
        image_base = struct.unpack_from("<I", payload, optional_offset + 28)[0]
        subsystem = struct.unpack_from("<H", payload, optional_offset + 68)[0]
        directory_count = struct.unpack_from("<I", payload, optional_offset + 92)[0]
        table_offset = optional_offset + 96
        directories = [
            struct.unpack_from("<II", payload, table_offset + 8 * index)
            for index in range(directory_count)
        ]
        section_offset = optional_offset + 224
        sections = []
        for index in range(section_count):
            base = section_offset + 40 * index
            name = payload[base:base + 8].rstrip(b"\0").decode("ascii")
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<IIII", payload, base + 8
            )
            sections.append(
                {
                    "name": name,
                    "rva": rva,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                }
            )
        return {
            "machine": machine,
            "magic": magic,
            "characteristics": characteristics,
            "entry_rva": entry_rva,
            "image_base": image_base,
            "subsystem": subsystem,
            "directories": directories,
            "sections": sections,
        }

    @staticmethod
    def _read_exports(payload: bytes, parsed: dict) -> list[str]:
        rva, size = parsed["directories"][0]
        assert size > 0, "no export directory"

        def to_offset(target: int) -> int:
            for section in parsed["sections"]:
                if section["rva"] <= target < section["rva"] + section["raw_size"]:
                    return section["raw_offset"] + (target - section["rva"])
            raise AssertionError(f"rva 0x{target:x} is outside every section")

        base = to_offset(rva)
        name_count = struct.unpack_from("<I", payload, base + 24)[0]
        name_table = struct.unpack_from("<I", payload, base + 32)[0]
        names = []
        for index in range(name_count):
            name_rva = struct.unpack_from(
                "<I", payload, to_offset(name_table + 4 * index)
            )[0]
            offset = to_offset(name_rva)
            end = payload.index(b"\0", offset)
            names.append(payload[offset:end].decode("ascii"))
        return names

    def test_dll_headers(self):
        parsed = self._parse(DLL_PATH.read_bytes())
        assert parsed["machine"] == 0x014C          # i386
        assert parsed["magic"] == 0x010B            # PE32
        assert parsed["characteristics"] & 0x2000   # IMAGE_FILE_DLL
        assert parsed["characteristics"] & 0x0001   # RELOCS_STRIPPED
        assert parsed["image_base"] == 0x10000000
        assert [s["name"] for s in parsed["sections"]] == [".text", ".rdata", ".data"]

    def test_exe_headers(self):
        parsed = self._parse(EXE_PATH.read_bytes())
        assert parsed["machine"] == 0x014C
        assert not parsed["characteristics"] & 0x2000
        assert parsed["subsystem"] == 3             # console
        assert parsed["image_base"] == 0x00400000

    def test_dll_exports_every_documented_function(self, manifest):
        payload = DLL_PATH.read_bytes()
        names = self._read_exports(payload, self._parse(payload))
        assert names == sorted(manifest["exports"])
        assert names == sorted(names), "the loader binary-searches this table"

    def test_no_relocation_directory(self):
        # RELOCS_STRIPPED is set, so the loader honours the preferred base --
        # which is what makes the addresses in regression/*.yaml stable.
        for path in (DLL_PATH, EXE_PATH):
            parsed = self._parse(path.read_bytes())
            assert parsed["directories"][5] == (0, 0)


class TestRegressionBaselinesAgreeWithTheBinaries:
    """The address-keyed drift guard.

    A regenerated fixture that moves a function used to be discoverable only by
    running a deploy against a live Ghidra. Now it fails here.
    """

    @staticmethod
    def _baseline_functions(path: Path) -> dict[str, int]:
        """Read `address:` / `name:` pairs without requiring PyYAML.

        The parser is deliberately dumb: it walks the file for an `address:`
        line followed by a `name:` line, which is the shape every entry in the
        `functions:` block has. Keeping it dependency-free means this guard
        runs in the plainest possible unit environment.
        """
        found: dict[str, int] = {}
        pending: int | None = None
        for line in path.read_text(encoding="utf-8").splitlines():
            address = re.match(r'\s*-?\s*address:\s*"(0x[0-9a-fA-F]+)"', line)
            if address:
                pending = int(address.group(1), 16)
                continue
            name = re.match(r'\s*name:\s*"([A-Za-z_][A-Za-z0-9_]*)"', line)
            if name and pending is not None:
                found[name.group(1)] = pending
                pending = None
        return found

    @pytest.mark.parametrize(
        "baseline_name,image_name",
        [
            ("Benchmark.dll.yaml", "Benchmark.dll"),
            ("BenchmarkDebug.exe.yaml", "BenchmarkDebug.exe"),
        ],
    )
    def test_every_baseline_address_matches_the_manifest(
        self, baseline_name, image_name, manifest
    ):
        baseline = REGRESSION_DIR / baseline_name
        assert baseline.is_file(), f"{baseline} is missing"
        functions = manifest["images"][image_name]["functions"]
        # Ghidra names the image entry point "entry" whatever the source called
        # it, so the baselines say "entry" where the manifest says DllMain /
        # exe_entry.
        entry_address = int(manifest["images"][image_name]["entry_point"], 16)
        addresses = {name: int(value, 16) for name, value in functions.items()}
        addresses["entry"] = entry_address

        asserted = self._baseline_functions(baseline)
        assert asserted, f"{baseline} declares no function addresses"
        for name, address in asserted.items():
            assert name in addresses, (
                f"{baseline_name} asserts a function {name!r} that the fixture "
                f"does not contain"
            )
            assert address == addresses[name], (
                f"{baseline_name} says {name} is at 0x{address:08x}; the "
                f"fixture puts it at 0x{addresses[name]:08x}. Regenerating the "
                f"fixture moved it -- update the baseline."
            )

    def test_the_dll_baseline_covers_every_exported_function(self, manifest):
        asserted = self._baseline_functions(REGRESSION_DIR / "Benchmark.dll.yaml")
        missing = set(manifest["exports"]) - set(asserted)
        assert not missing, (
            f"exported but unasserted: {sorted(missing)}. Every export is "
            "cheap to assert and an unasserted one is a hole in the gate."
        )

    def test_baselines_target_the_project_paths_the_runner_imports_to(self):
        for name, expected in (
            ("Benchmark.dll.yaml", "/testing/benchmark/Benchmark.dll"),
            ("BenchmarkDebug.exe.yaml", "/testing/benchmark/BenchmarkDebug.exe"),
        ):
            text = (REGRESSION_DIR / name).read_text(encoding="utf-8")
            assert f'path: "{expected}"' in text


class TestSetupWiring:
    """tools.setup must point at the fixture that exists."""

    def test_paths_resolve(self):
        from tools.setup import ghidra as setup_ghidra

        assert (REPO_ROOT / setup_ghidra.DEFAULT_BENCHMARK_DLL) == DLL_PATH
        assert (REPO_ROOT / setup_ghidra.DEFAULT_BENCHMARK_DEBUG_EXE) == EXE_PATH
        assert setup_ghidra._benchmark_regression_dir(REPO_ROOT) == REGRESSION_DIR

    def test_no_reference_to_the_repository_the_fixture_left(self):
        from tools.setup import ghidra as setup_ghidra

        source = Path(setup_ghidra.__file__).read_text(encoding="utf-8")
        for line_number, line in enumerate(source.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue          # the history is allowed to be described
            assert "fun-doc" not in line, (
                f"tools/setup/ghidra.py:{line_number} still references fun-doc "
                f"outside a comment: {line.strip()}"
            )

    def test_every_fixture_backed_tier_is_declared_as_such(self):
        from tools.setup import ghidra as setup_ghidra

        # run_deploy_tests calls reset_benchmark_fixture for each of these, so
        # each must also be in BENCHMARK_DEPLOY_TEST_MODES -- that set is what
        # enables the prompt policy before the imports and cleans up the
        # restored CodeBrowser tools afterwards. negative-contract was missing.
        expected = {
            "benchmark-read",
            "benchmark-write",
            "negative-contract",
            "multi-program",
            "debugger-live",
            "release",
        }
        assert expected <= setup_ghidra.BENCHMARK_DEPLOY_TEST_MODES
        assert setup_ghidra._deploy_tests_use_benchmark(["negative-contract"])
        assert not setup_ghidra._deploy_tests_use_benchmark(["endpoint-catalog"])
        assert not setup_ghidra._deploy_tests_use_benchmark(["selected-contract"])


@pytest.mark.skipif(sys.platform != "win32", reason="PE32 execution needs Windows")
class TestTheGeneratedCodeActuallyRuns:
    """Execute the fixture and check the answer.

    This is the falsification lever for the machine code itself. Everything
    else in this file checks the shape of the bytes; only this checks that they
    compute the right thing.
    """

    def test_debuggee_returns_the_expected_crc(self, generator, manifest):
        expected = generator.reference_crc16(manifest["banner"].encode("ascii"))
        assert expected == manifest["banner_crc16"]
        result = subprocess.run(
            [str(EXE_PATH)], cwd=str(FIXTURE_DIR), capture_output=True, timeout=60
        )
        assert result.returncode == expected, (
            f"BenchmarkDebug.exe exited {result.returncode}, expected "
            f"{expected} (0x{expected:04x}) -- the generated calc_crc16 does "
            f"not compute a CRC-16/CCITT."
        )

    def test_dll_loads_and_its_export_table_resolves(self, manifest):
        # The '@' mode does LoadLibraryA + GetProcAddress("calc_crc16") and
        # exits with the result. Reaching the right exit code proves the loader
        # accepted Benchmark.dll, ran its DllMain, and resolved the export by
        # name out of the generated export directory.
        result = subprocess.run(
            [str(EXE_PATH), "@"], cwd=str(FIXTURE_DIR),
            capture_output=True, timeout=60,
        )
        assert result.returncode != 0x0E01, "LoadLibraryA(Benchmark.dll) failed"
        assert result.returncode != 0x0E02, "GetProcAddress(calc_crc16) failed"
        assert result.returncode == manifest["banner_crc16"]
