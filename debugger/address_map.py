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
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from .protocol import ModuleInfo

logger = logging.getLogger(__name__)

# Pattern: D2COMMON.DLL::Ordinal_10000@6fd9f450->Ordinal_10000
_EXPORT_LINE_RE = re.compile(
    r"^(?P<dll>[^:]+)::(?P<label>[^@]+)@(?P<addr>[0-9a-fA-F]+)->(?P<name>.+)$"
)

# Extract ordinal number from label like "Ordinal_10000"
_ORDINAL_RE = re.compile(r"Ordinal_(\d+)")

# Mapping lookup order. Later stages are increasingly permissive and must be
# treated as aliases, not unique identities.
_MATCH_ORDER = ("exact", "basename", "canonical", "fuzzy")
_SAFE_QUOTE_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789."


@dataclass
class ModuleMapping:
    """Maps a single module between Ghidra and runtime address spaces."""

    name: str
    ghidra_base: int
    runtime_base: int
    size: int
    ghidra_name: str = ""
    image_path: str = ""
    loaded_name: str = ""
    match_kind: str = ""
    match_key: str = ""

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


@dataclass(frozen=True)
class _GhidraBaseCandidate:
    """A Ghidra module/image-base candidate collected from sync_modules."""

    id: str
    name: str
    base: int


@dataclass
class _ResolvedCandidate:
    """A tentative runtime<->Ghidra match before global ambiguity checks."""

    module: ModuleInfo
    ghidra: _GhidraBaseCandidate
    match_kind: str
    match_key: str


@dataclass
class OrdinalEntry:
    """A single ordinal export from dll_exports/*.txt."""

    dll: str
    ordinal: int
    label: str  # e.g. "Ordinal_10000" or renamed label
    ghidra_address: int


class AddressMapper:
    """Bidirectional address translation between Ghidra and runtime.

    Module matching is deliberately fail-closed:

    1. exact name/path match
    2. case-insensitive basename match
    3. non-destructive canonical basename match (percent encoding)
    4. fuzzy Ghidra/dbgeng-style alias match, only if unique

    Internally, aliases map to *lists* of mappings. A fuzzy collision therefore
    raises an ambiguity error instead of silently choosing the wrong module.
    """

    def __init__(self):
        self._modules: List[ModuleMapping] = []
        self._mapped_index: dict[str, dict[str, list[ModuleMapping]]] = self._new_index()
        self._ordinals: Dict[str, Dict[int, OrdinalEntry]] = {}  # dll -> {ordinal -> entry}

    # -- Module mapping ----------------------------------------------------

    def update_from_modules(
        self,
        runtime_modules: List[ModuleInfo],
        ghidra_bases: Dict[str, int] | None = None,
        ghidra_modules: Optional[list[dict]] = None,
    ) -> dict:
        """Rebuild module map from runtime + Ghidra data.

        Args:
            runtime_modules: Modules from dbgeng's module_list().
            ghidra_bases: legacy {module_name_or_alias: image_base} from Ghidra.
            ghidra_modules: optional canonical module payload with stable ids.

        Returns:
            Summary of mapped/unmapped/ambiguous modules.
        """
        self._modules.clear()
        self._mapped_index = self._new_index()

        ghidra_index = self._new_index()
        for candidate in self._build_ghidra_candidates(
            ghidra_bases=ghidra_bases or {}, ghidra_modules=ghidra_modules or []
        ):
            for kind, key in self._aliases_for_name(candidate.name).items():
                ghidra_index[kind][key].append(candidate)

        tentative: list[_ResolvedCandidate] = []
        unmapped: list[dict] = []
        ambiguous: list[dict] = []

        for mod in runtime_modules:
            resolved = self._resolve_ghidra_candidate_for_runtime_module(mod, ghidra_index)
            if resolved is None:
                unmapped.append({"module": mod.name, "reason": "no_match"})
            elif isinstance(resolved, str):
                ambiguous.append({"module": mod.name, "reason": resolved})
            else:
                tentative.append(resolved)

        # Global ambiguity check: if multiple runtime modules resolve to the
        # same exact Ghidra candidate, do not map any of them. This prevents two
        # same-basename runtime DLLs from sharing one Ghidra image base.
        by_ghidra: dict[tuple[str, int], list[_ResolvedCandidate]] = defaultdict(list)
        for item in tentative:
            by_ghidra[(item.ghidra.id, item.ghidra.base)].append(item)

        accepted: list[_ResolvedCandidate] = []
        rejected_runtime_ids: set[tuple[int, int, str]] = set()
        for (ghidra_id, ghidra_base), items in by_ghidra.items():
            representative = items[0].ghidra
            runtime_ids = {
                (item.module.runtime_base, item.module.size, item.module.name)
                for item in items
            }
            if len(runtime_ids) > 1:
                candidates = [
                    self._runtime_module_label(item.module)
                    for item in sorted(items, key=lambda x: x.module.runtime_base)
                ]
                for item in items:
                    rejected_runtime_ids.add(
                        (item.module.runtime_base, item.module.size, item.module.name)
                    )
                ambiguous.append(
                    {
                        "ghidra": representative.name,
                        "ghidra_id": ghidra_id,
                        "ghidra_base": f"0x{ghidra_base:08X}",
                        "reason": "multiple_runtime_modules_match_same_ghidra_candidate",
                        "candidates": candidates,
                    }
                )
            else:
                accepted.extend(items)

        mapped = []
        for item in accepted:
            if (item.module.runtime_base, item.module.size, item.module.name) in rejected_runtime_ids:
                continue
            mapping = ModuleMapping(
                name=item.module.name,
                ghidra_name=item.ghidra.name,
                ghidra_base=item.ghidra.base,
                runtime_base=item.module.runtime_base,
                size=item.module.size,
                image_path=getattr(item.module, "image_path", None) or "",
                loaded_name=getattr(item.module, "loaded_name", None) or "",
                match_kind=item.match_kind,
                match_key=item.match_key,
            )
            self._modules.append(mapping)
            self._index_mapping(mapping)

            item.module.ghidra_base = item.ghidra.base
            item.module.ghidra_name = item.ghidra.name
            item.module.match_kind = item.match_kind
            item.module.match_key = item.match_key
            mapped.append(item.module.name)
            logger.info(
                "Mapped %s -> %s via %s:%s ghidra=0x%08X runtime=0x%08X offset=%+#X",
                item.module.name,
                item.ghidra.name,
                item.match_kind,
                item.match_key,
                item.ghidra.base,
                item.module.runtime_base,
                mapping.offset,
            )

        return {
            "mapped": len(mapped),
            "unmapped": len(unmapped),
            "ambiguous": len(ambiguous),
            "mapped_modules": mapped,
            "unmapped_modules": [item["module"] for item in unmapped[:20]],
            "unmapped_details": unmapped[:20],
            "ambiguous_modules": ambiguous[:20],
        }

    def get_module(self, name: str) -> Optional[ModuleMapping]:
        """Look up a module mapping by name. Returns None on miss/ambiguity."""
        try:
            return self._resolve_mapped_module_by_name(name)
        except ValueError:
            return None

    def require_module(self, name: str) -> ModuleMapping:
        """Look up a module mapping by name and raise clear errors."""
        mapping = self._resolve_mapped_module_by_name(name)
        if mapping is None:
            raise ValueError(f"Module '{name}' not in address map")
        return mapping

    def get_mapping_for_runtime_module(self, module: ModuleInfo) -> Optional[ModuleMapping]:
        """Return the already accepted mapping for an exact runtime module instance."""
        for mapping in self._modules:
            if mapping.runtime_base == module.runtime_base and mapping.size == module.size:
                return mapping
        return None

    def get_all_modules(self) -> List[ModuleMapping]:
        return list(self._modules)

    # -- Address translation -----------------------------------------------

    def to_runtime(self, ghidra_addr: int, module: Optional[str] = None) -> int:
        """Convert a Ghidra address to a runtime address.

        Args:
            ghidra_addr: Address in Ghidra's address space.
            module: Optional module name for disambiguation.

        Returns:
            Runtime address.

        Raises:
            ValueError: If the address can't be mapped or the module alias is ambiguous.
        """
        if module:
            mapping = self.require_module(module)
            if not mapping.contains_ghidra(ghidra_addr):
                raise ValueError(
                    f"Address 0x{ghidra_addr:08X} is outside mapped module "
                    f"'{mapping.name}' Ghidra range "
                    f"0x{mapping.ghidra_base:08X}-0x{mapping.ghidra_base + mapping.size:08X}"
                )
            return mapping.to_runtime(ghidra_addr)

        matches = [m for m in self._modules if m.contains_ghidra(ghidra_addr)]
        if len(matches) == 1:
            return matches[0].to_runtime(ghidra_addr)
        if len(matches) > 1:
            raise ValueError(
                f"Address 0x{ghidra_addr:08X} matches multiple mapped modules: "
                f"{', '.join(m.name for m in matches)}. Provide an exact module name/path."
            )

        raise ValueError(
            f"Address 0x{ghidra_addr:08X} not in any mapped module. "
            f"Mapped: {', '.join(m.name for m in self._modules)}"
        )

    def to_ghidra(self, runtime_addr: int) -> Tuple[str, int]:
        """Convert a runtime address to (module_name, ghidra_address).

        Raises:
            ValueError: If the address can't be mapped.
        """
        matches = [m for m in self._modules if m.contains_runtime(runtime_addr)]
        if len(matches) == 1:
            return matches[0].name, matches[0].to_ghidra(runtime_addr)
        if len(matches) > 1:
            raise ValueError(
                f"Runtime address 0x{runtime_addr:08X} matches multiple mapped modules: "
                f"{', '.join(m.name for m in matches)}"
            )
        raise ValueError(f"Runtime address 0x{runtime_addr:08X} not in any mapped module")

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

                    dll_key = self._ordinal_key(dll)
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
        dll_key = self._ordinal_key(dll)
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
        return len(self._ordinals.get(self._ordinal_key(dll), {}))

    # -- Matching helpers --------------------------------------------------

    @staticmethod
    def _new_index():
        return {kind: defaultdict(list) for kind in _MATCH_ORDER}

    def _resolve_ghidra_candidate_for_runtime_module(
        self,
        module: ModuleInfo,
        ghidra_index: dict[str, dict[str, list[_GhidraBaseCandidate]]],
    ) -> _ResolvedCandidate | str | None:
        aliases = self._aliases_for_runtime_module(module)
        for kind in _MATCH_ORDER:
            for key in aliases.get(kind, []):
                unique = self._dedupe_candidates(ghidra_index[kind].get(key, []))
                if len(unique) == 1:
                    return _ResolvedCandidate(module, unique[0], kind, key)
                if len(unique) > 1:
                    return (
                        f"ambiguous_{kind}_match: "
                        + ", ".join(f"{c.name}@0x{c.base:08X}" for c in unique)
                    )
        return None

    def _resolve_mapped_module_by_name(self, name: str) -> Optional[ModuleMapping]:
        aliases = self._aliases_for_name(name)
        for kind in _MATCH_ORDER:
            key = aliases.get(kind)
            if not key:
                continue
            unique = self._dedupe_mappings(self._mapped_index[kind].get(key, []))
            if len(unique) == 1:
                return unique[0]
            if len(unique) > 1:
                raise ValueError(
                    f"Ambiguous module mapping for '{name}' via {kind}:{key}. "
                    f"Candidates: {', '.join(self._mapping_label(m) for m in unique)}. "
                    "Use a more exact module name/path."
                )
        return None

    def _index_mapping(self, mapping: ModuleMapping) -> None:
        names = [mapping.name, mapping.ghidra_name, mapping.image_path, mapping.loaded_name]
        for raw_name in names:
            for kind, key in self._aliases_for_name(raw_name).items():
                self._mapped_index[kind][key].append(mapping)

    def _aliases_for_runtime_module(self, module: ModuleInfo) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {kind: [] for kind in _MATCH_ORDER}
        names = [
            getattr(module, "image_path", None) or "",
            getattr(module, "loaded_name", None) or "",
            module.name,
        ]
        for raw_name in names:
            aliases = self._aliases_for_name(raw_name)
            for kind, key in aliases.items():
                if key and key not in result[kind]:
                    result[kind].append(key)
        return result

    @classmethod
    def _aliases_for_name(cls, name: str) -> dict[str, str]:
        text = cls._clean_text(name)
        if not text:
            return {}
        basename = cls._basename(text)
        return {
            "exact": text.casefold(),
            "basename": basename.casefold(),
            "canonical": cls._canonical_basename_key(basename),
            "fuzzy": cls._fuzzy_basename_key(basename),
        }

    @staticmethod
    def _parse_base(base: int | str) -> int:
        if isinstance(base, str):
            text = base.strip()
            return int(text, 16) if text.casefold().startswith("0x") else int(text)
        return int(base)

    def _build_ghidra_candidates(
        self, ghidra_bases: Dict[str, int | str], ghidra_modules: list[dict]
    ) -> list[_GhidraBaseCandidate]:
        if ghidra_modules:
            result: list[_GhidraBaseCandidate] = []
            for entry in ghidra_modules:
                module_id = str(entry.get("id", "")).strip()
                if not module_id:
                    module_id = str(entry.get("name", "")).strip()
                if "base" not in entry:
                    logger.warning("Skipping Ghidra module without base: %r", entry)
                    continue
                base = self._parse_base(entry["base"])
                names = entry.get("names", []) or []
                canonical_name = str(entry.get("name", "")).strip()
                if canonical_name:
                    names = [canonical_name, *names]
                if not names:
                    names = [module_id]
                for raw_name in names:
                    text = self._clean_text(raw_name)
                    if text:
                        result.append(_GhidraBaseCandidate(module_id or text, text, base))
            return result
        return [
            _GhidraBaseCandidate(str(name), str(name), self._parse_base(base))
            for name, base in ghidra_bases.items()
        ]

    @staticmethod
    def _dedupe_candidates(
        candidates: list[_GhidraBaseCandidate],
    ) -> list[_GhidraBaseCandidate]:
        seen = set()
        result = []
        for item in candidates:
            ident = (item.id, item.base)
            if ident not in seen:
                seen.add(ident)
                result.append(item)
        return result

    @staticmethod
    def _dedupe_mappings(mappings: list[ModuleMapping]) -> list[ModuleMapping]:
        seen = set()
        result = []
        for item in mappings:
            ident = (item.runtime_base, item.size, item.name)
            if ident not in seen:
                seen.add(ident)
                result.append(item)
        return result

    @staticmethod
    def _mapping_label(mapping: ModuleMapping) -> str:
        return f"{mapping.name}@0x{mapping.runtime_base:08X}"

    @staticmethod
    def _runtime_module_label(module: ModuleInfo) -> str:
        return f"{module.name}@0x{module.runtime_base:08X}"

    @staticmethod
    def _clean_text(value: str) -> str:
        text = unicodedata.normalize("NFC", str(value or "").strip())
        return text.replace("\\", "/")

    @staticmethod
    def _basename(value: str) -> str:
        return value.rsplit("/", 1)[-1]

    @staticmethod
    def _canonical_basename_key(basename: str) -> str:
        # Non-destructive: spaces, hyphens and literal '%' are preserved through
        # encoding. "a b.exe" -> "a%20b.exe", "a%20b.exe" -> "a%2520b.exe".
        return quote(basename.casefold(), safe=_SAFE_QUOTE_CHARS)

    @staticmethod
    def _fuzzy_basename_key(basename: str) -> str:
        # Convert common dbgeng/Ghidra sanitizations back into an extension while
        # keeping .exe and .dll distinct. Example:
        #   Example_Program___Retail_exe -> exampleprogramretail.exe
        value = basename.lower()
        if not os.path.splitext(value)[1]:
            value = re.sub(r"[\s_.-]+(exe|dll)$", r".\1", value)
        stem, ext = os.path.splitext(value)
        stem = re.sub(r"[^a-z0-9]+", "", stem)
        ext = ext if ext in {".exe", ".dll"} else ""
        return f"{stem}{ext}"

    @classmethod
    def _ordinal_key(cls, name: str) -> str:
        """Compatibility key for ordinal exports: basename without extension."""
        basename = cls._basename(cls._clean_text(name))
        stem = os.path.splitext(basename)[0]
        return stem.lower()

    @classmethod
    def _normalize_name(cls, name: str) -> str:
        """Backward-compatible helper retained for external callers/tests."""
        return cls._ordinal_key(name)
