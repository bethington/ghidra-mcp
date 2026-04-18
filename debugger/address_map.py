"""
Bidirectional address translation between Ghidra (static) and runtime (dynamic).

Ghidra uses the PE image base from the binary (e.g., D2Common.dll at 0x6FD60000).
At runtime, ASLR may relocate DLLs to different bases. This mapper translates
addresses in both directions using the module base offsets.

Also handles ordinal resolution from dll_exports/*.txt files.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .protocol import ModuleInfo

logger = logging.getLogger(__name__)

# Pattern: D2COMMON.DLL::Ordinal_10000@6fd9f450->Ordinal_10000
_EXPORT_LINE_RE = re.compile(
    r"^(?P<dll>[^:]+)::(?P<label>[^@]+)@(?P<addr>[0-9a-fA-F]+)->(?P<name>.+)$"
)

# Extract ordinal number from label like "Ordinal_10000"
_ORDINAL_RE = re.compile(r"Ordinal_(\d+)")


@dataclass
class ModuleMapping:
    """Maps a single module between Ghidra and runtime address spaces."""
    name: str
    ghidra_base: int
    runtime_base: int
    size: int

    @property
    def offset(self) -> int:
        """runtime_base - ghidra_base. Add to Ghidra addr to get runtime."""
        return self.runtime_base - self.ghidra_base

    def contains_ghidra(self, addr: int) -> bool:
        return self.ghidra_base <= addr < self.ghidra_base + self.size

    def contains_runtime(self, addr: int) -> bool:
        return self.runtime_base <= addr < self.runtime_base + self.size

    def to_runtime(self, ghidra_addr: int) -> int:
        return ghidra_addr + self.offset

    def to_ghidra(self, runtime_addr: int) -> int:
        return runtime_addr - self.offset


@dataclass
class OrdinalEntry:
    """A single ordinal export from dll_exports/*.txt."""
    dll: str
    ordinal: int
    label: str  # e.g. "Ordinal_10000" or renamed label
    ghidra_address: int


class AddressMapper:
    """Bidirectional address translation between Ghidra and runtime."""

    def __init__(self):
        self._modules: Dict[str, ModuleMapping] = {}  # normalized_name -> mapping
        self._ordinals: Dict[str, Dict[int, OrdinalEntry]] = {}  # dll -> {ordinal -> entry}

    # -- Module mapping ----------------------------------------------------

    def update_from_modules(self, runtime_modules: List[ModuleInfo],
                            ghidra_bases: Dict[str, int]) -> dict:
        """Rebuild module map from runtime + Ghidra data.

        Args:
            runtime_modules: Modules from dbgeng's module_list().
            ghidra_bases: {module_name: image_base} from Ghidra's /get_metadata.

        Returns:
            Summary of mapped/unmapped modules.
        """
        self._modules.clear()
        mapped = []
        unmapped = []

        # Normalize Ghidra base names for matching
        ghidra_normalized: Dict[str, Tuple[str, int]] = {}
        for name, base in ghidra_bases.items():
            key = self._normalize_name(name)
            ghidra_normalized[key] = (name, base)

        for mod in runtime_modules:
            key = self._normalize_name(mod.name)
            if key in ghidra_normalized:
                orig_name, ghidra_base = ghidra_normalized[key]
                mapping = ModuleMapping(
                    name=mod.name,
                    ghidra_base=ghidra_base,
                    runtime_base=mod.runtime_base,
                    size=mod.size,
                )
                self._modules[key] = mapping
                mod.ghidra_base = ghidra_base
                mapped.append(mod.name)
                logger.info(
                    f"Mapped {mod.name}: ghidra=0x{ghidra_base:08X} "
                    f"runtime=0x{mod.runtime_base:08X} "
                    f"offset={mapping.offset:+#X}")
            else:
                unmapped.append(mod.name)

        return {
            "mapped": len(mapped),
            "unmapped": len(unmapped),
            "mapped_modules": mapped,
            "unmapped_modules": unmapped[:20],  # Cap output
        }

    def get_module(self, name: str) -> Optional[ModuleMapping]:
        """Look up a module mapping by name."""
        return self._modules.get(self._normalize_name(name))

    def get_all_modules(self) -> List[ModuleMapping]:
        return list(self._modules.values())

    # -- Address translation -----------------------------------------------

    def to_runtime(self, ghidra_addr: int,
                   module: Optional[str] = None) -> int:
        """Convert a Ghidra address to a runtime address.

        Args:
            ghidra_addr: Address in Ghidra's address space.
            module: Optional module name for disambiguation.

        Returns:
            Runtime address.

        Raises:
            ValueError: If the address can't be mapped.
        """
        if module:
            mapping = self.get_module(module)
            if mapping is None:
                raise ValueError(f"Module '{module}' not in address map")
            return mapping.to_runtime(ghidra_addr)

        # Auto-detect module from address range
        for mapping in self._modules.values():
            if mapping.contains_ghidra(ghidra_addr):
                return mapping.to_runtime(ghidra_addr)

        raise ValueError(
            f"Address 0x{ghidra_addr:08X} not in any mapped module. "
            f"Mapped: {', '.join(m.name for m in self._modules.values())}")

    def to_ghidra(self, runtime_addr: int) -> Tuple[str, int]:
        """Convert a runtime address to (module_name, ghidra_address).

        Raises:
            ValueError: If the address can't be mapped.
        """
        for mapping in self._modules.values():
            if mapping.contains_runtime(runtime_addr):
                return mapping.name, mapping.to_ghidra(runtime_addr)

        raise ValueError(
            f"Runtime address 0x{runtime_addr:08X} not in any mapped module")

    def try_to_ghidra(self, runtime_addr: int) -> Optional[Tuple[str, int]]:
        """Like to_ghidra but returns None instead of raising."""
        try:
            return self.to_ghidra(runtime_addr)
        except ValueError:
            return None

    # -- Ordinal resolution ------------------------------------------------

    def load_ordinal_exports(self, exports_dir: str | Path) -> dict:
        """Load ordinal export files from dll_exports/ directory.

        Parses files like D2Common.txt with format:
            D2COMMON.DLL::Ordinal_10000@6fd9f450->Ordinal_10000

        Returns:
            Summary of loaded ordinals per DLL.
        """
        exports_dir = Path(exports_dir)
        if not exports_dir.is_dir():
            raise FileNotFoundError(f"Exports directory not found: {exports_dir}")

        summary = {}
        for f in exports_dir.glob("*.txt"):
            count = self._load_ordinal_file(f)
            if count > 0:
                summary[f.stem] = count
                logger.info(f"Loaded {count} ordinals from {f.name}")

        total = sum(summary.values())
        logger.info(f"Total ordinals loaded: {total} across {len(summary)} DLLs")
        return summary

    def _load_ordinal_file(self, path: Path) -> int:
        """Parse a single ordinal export file."""
        count = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    m = _EXPORT_LINE_RE.match(line)
                    if not m:
                        continue

                    dll = m.group("dll")
                    label = m.group("label")
                    addr = int(m.group("addr"), 16)

                    # Extract ordinal number
                    om = _ORDINAL_RE.search(label)
                    if not om:
                        continue
                    ordinal = int(om.group(1))

                    dll_key = self._normalize_name(dll)
                    if dll_key not in self._ordinals:
                        self._ordinals[dll_key] = {}

                    self._ordinals[dll_key][ordinal] = OrdinalEntry(
                        dll=dll,
                        ordinal=ordinal,
                        label=m.group("name"),
                        ghidra_address=addr,
                    )
                    count += 1
        except Exception as e:
            logger.error(f"Error reading {path}: {e}")
        return count

    def resolve_ordinal(self, dll: str, ordinal: int) -> Optional[dict]:
        """Resolve a DLL ordinal to addresses.

        Returns:
            Dict with ghidra_address, runtime_address (if mapped), label.
            None if ordinal not found.
        """
        dll_key = self._normalize_name(dll)
        entries = self._ordinals.get(dll_key, {})
        entry = entries.get(ordinal)
        if entry is None:
            return None

        result: dict = {
            "dll": entry.dll,
            "ordinal": ordinal,
            "label": entry.label,
            "ghidra_address": f"0x{entry.ghidra_address:08X}",
        }

        # Try to get runtime address
        try:
            runtime = self.to_runtime(entry.ghidra_address, dll)
            result["runtime_address"] = f"0x{runtime:08X}"
        except ValueError:
            result["runtime_address"] = None

        return result

    def get_ordinal_count(self, dll: str) -> int:
        """Get the number of loaded ordinals for a DLL."""
        return len(self._ordinals.get(self._normalize_name(dll), {}))

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize a module/DLL name for matching.

        "D2COMMON.DLL" -> "d2common"
        "D2Common.dll" -> "d2common"
        "/Vanilla/1.00/D2Common.dll" -> "d2common"
        """
        # Take basename, strip extension, lowercase
        basename = os.path.basename(name)
        stem = os.path.splitext(basename)[0]
        return stem.lower()
