"""Unit tests for debugger/address_map.py — address translation and ordinal parsing."""

import os
from pathlib import Path

import pytest

# Allow running from project root
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from debugger.address_map import AddressMapper, ModuleMapping
from debugger.protocol import ModuleInfo


class TestModuleMapping:
    def test_offset_positive(self):
        m = ModuleMapping("D2Common.dll", ghidra_base=0x6FD60000,
                          runtime_base=0x74A60000, size=0x100000)
        assert m.offset == 0x74A60000 - 0x6FD60000

    def test_offset_negative(self):
        m = ModuleMapping("D2Common.dll", ghidra_base=0x74A60000,
                          runtime_base=0x6FD60000, size=0x100000)
        assert m.offset < 0

    def test_contains_ghidra(self):
        m = ModuleMapping("test.dll", 0x10000, 0x20000, 0x5000)
        assert m.contains_ghidra(0x10000)
        assert m.contains_ghidra(0x14FFF)
        assert not m.contains_ghidra(0x15000)
        assert not m.contains_ghidra(0x0FFFF)

    def test_contains_runtime(self):
        m = ModuleMapping("test.dll", 0x10000, 0x20000, 0x5000)
        assert m.contains_runtime(0x20000)
        assert m.contains_runtime(0x24FFF)
        assert not m.contains_runtime(0x25000)

    def test_to_runtime(self):
        m = ModuleMapping("test.dll", 0x10000, 0x20000, 0x5000)
        assert m.to_runtime(0x10000) == 0x20000
        assert m.to_runtime(0x12345) == 0x22345

    def test_to_ghidra(self):
        m = ModuleMapping("test.dll", 0x10000, 0x20000, 0x5000)
        assert m.to_ghidra(0x20000) == 0x10000
        assert m.to_ghidra(0x22345) == 0x12345


class TestAddressMapper:
    def setup_method(self):
        self.mapper = AddressMapper()
        runtime_modules = [
            ModuleInfo("D2Common.dll", runtime_base=0x74A60000, size=0x100000),
            ModuleInfo("D2Client.dll", runtime_base=0x73B00000, size=0x200000),
            ModuleInfo("Fog.dll", runtime_base=0x75000000, size=0x50000),
        ]
        ghidra_bases = {
            "D2Common.dll": 0x6FD60000,
            "D2Client.dll": 0x6FAB0000,
            "Fog.dll": 0x6FF50000,
        }
        self.mapper.update_from_modules(runtime_modules, ghidra_bases)

    def test_to_runtime_with_module(self):
        result = self.mapper.to_runtime(0x6FD60000, "D2Common.dll")
        assert result == 0x74A60000

    def test_to_runtime_auto_detect(self):
        # Address in D2Common range
        result = self.mapper.to_runtime(0x6FD70000)
        expected = 0x6FD70000 + (0x74A60000 - 0x6FD60000)
        assert result == expected

    def test_to_runtime_unknown_raises(self):
        with pytest.raises(ValueError, match="not in any mapped module"):
            self.mapper.to_runtime(0x00400000)  # Not in any module

    def test_to_runtime_unknown_module_raises(self):
        with pytest.raises(ValueError, match="not in address map"):
            self.mapper.to_runtime(0x10000, "Unknown.dll")

    def test_to_ghidra(self):
        module, addr = self.mapper.to_ghidra(0x74A60000)
        assert module == "D2Common.dll"
        assert addr == 0x6FD60000

    def test_to_ghidra_unknown_raises(self):
        with pytest.raises(ValueError):
            self.mapper.to_ghidra(0x00400000)

    def test_try_to_ghidra_returns_none(self):
        assert self.mapper.try_to_ghidra(0x00400000) is None

    def test_try_to_ghidra_returns_tuple(self):
        result = self.mapper.try_to_ghidra(0x74A60000)
        assert result == ("D2Common.dll", 0x6FD60000)

    def test_roundtrip(self):
        original = 0x6FD9F450
        runtime = self.mapper.to_runtime(original, "D2Common.dll")
        module, back = self.mapper.to_ghidra(runtime)
        assert module == "D2Common.dll"
        assert back == original

    def test_normalize_name(self):
        assert AddressMapper._normalize_name("D2COMMON.DLL") == "d2common"
        assert AddressMapper._normalize_name("D2Common.dll") == "d2common"
        assert AddressMapper._normalize_name("/Vanilla/1.00/D2Common.dll") == "d2common"
        assert AddressMapper._normalize_name("Fog.dll") == "fog"

    def test_update_summary(self):
        mapper = AddressMapper()
        runtime = [ModuleInfo("A.dll", 0x10000, 0x1000),
                   ModuleInfo("B.dll", 0x20000, 0x1000)]
        ghidra = {"A.dll": 0x50000}
        result = mapper.update_from_modules(runtime, ghidra)
        assert result["mapped"] == 1
        assert result["unmapped"] == 1
        assert "A.dll" in result["mapped_modules"]
        assert "B.dll" in result["unmapped_modules"]


class TestOrdinalParsing:
    def setup_method(self):
        self.mapper = AddressMapper()
        self.tmpdir = Path(__file__).parent.parent / "fixtures" / "dll_exports"

    def test_load_ordinals(self):
        summary = self.mapper.load_ordinal_exports(self.tmpdir)
        assert "D2Common" in summary
        assert summary["D2Common"] == 3

    def test_resolve_ordinal_no_mapping(self):
        self.mapper.load_ordinal_exports(self.tmpdir)
        result = self.mapper.resolve_ordinal("D2Common.dll", 10624)
        assert result is not None
        assert result["ordinal"] == 10624
        assert result["label"] == "CalcMissileVelocityParam"
        assert result["ghidra_address"] == "0x6FDA1234"
        assert result["runtime_address"] is None  # No module mapping yet

    def test_resolve_ordinal_with_mapping(self):
        self.mapper.load_ordinal_exports(self.tmpdir)
        # Add module mapping
        runtime_modules = [
            ModuleInfo("D2Common.dll", runtime_base=0x74A60000, size=0x200000),
        ]
        self.mapper.update_from_modules(runtime_modules, {"D2Common.dll": 0x6FD60000})

        result = self.mapper.resolve_ordinal("D2Common.dll", 10624)
        assert result is not None
        assert result["runtime_address"] is not None

    def test_resolve_ordinal_not_found(self):
        self.mapper.load_ordinal_exports(self.tmpdir)
        result = self.mapper.resolve_ordinal("D2Common.dll", 99999)
        assert result is None

    def test_resolve_ordinal_wrong_dll(self):
        self.mapper.load_ordinal_exports(self.tmpdir)
        result = self.mapper.resolve_ordinal("NotADll.dll", 10000)
        assert result is None

    def test_ordinal_count(self):
        self.mapper.load_ordinal_exports(self.tmpdir)
        assert self.mapper.get_ordinal_count("D2Common.dll") == 3
        assert self.mapper.get_ordinal_count("NotADll.dll") == 0

    def test_load_real_exports(self):
        """Test loading actual dll_exports/ if available."""
        real_dir = Path(__file__).parent.parent.parent / "dll_exports"
        if not real_dir.is_dir():
            pytest.skip("dll_exports/ not found")
        mapper = AddressMapper()
        summary = mapper.load_ordinal_exports(real_dir)
        assert len(summary) > 0
        # D2Common should have ordinals
        assert mapper.get_ordinal_count("D2Common.dll") > 100
