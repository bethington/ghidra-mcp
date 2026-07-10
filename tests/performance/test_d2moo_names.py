"""Offline unit tests for d2moo_names.py.

d2moo_names resolves a proven getter's REAL field/struct name from the D2MOO
reimpl headers (community-canonical names like nThrowable, not offset-derived
GetItemTypeField10). The header *load* reads an external D2MOO checkout, so we
drive the pure parsing/derivation logic with an inline fixture header + explicit
`structs` dicts -- no external repo needed, CI-safe.
"""

from __future__ import annotations

import sys
from pathlib import Path

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

import d2moo_names as dn  # noqa: E402


# A minimal D2MOO-shaped header: `<type> <name>;  // 0x<offset>`.
FIXTURE_HEADER = """
struct D2ItemTypesTxt {
    unsigned short wShoots;  // 0x0c
    unsigned char nThrowable;  // 0x10
    unsigned char pad[0xd3];  // 0x11
};

struct D2OverlayTxt {
    unsigned int dwFlags;  // 0x00
};
"""


def _parsed():
    structs = {}
    dn._parse_file(FIXTURE_HEADER, structs)
    return structs


def test_parse_file_reads_offset_annotated_fields():
    s = _parsed()
    assert "D2ItemTypesTxt" in s
    it = s["D2ItemTypesTxt"]
    assert it["fields"][0x10]["name"] == "nThrowable"
    assert it["fields"][0x0C]["name"] == "wShoots"
    assert it["fields"][0x0C]["width"] == 2  # unsigned short
    # size is max(offset + width) across fields -- past the last field's offset
    assert it["size"] > 0x11
    assert it["fields"][0x11]["array"] is True  # pad[0xd3] is an array field


def test_by_size_bridges_stride_to_struct():
    s = _parsed()
    size = s["D2ItemTypesTxt"]["size"]
    assert "D2ItemTypesTxt" in dn.by_size(size, s)
    assert dn.by_size(0x1, s) == []  # nothing that small


def test_semantic_suffix_strips_hungarian_prefix():
    assert dn.semantic_suffix("nThrowable") == "Throwable"
    assert dn.semantic_suffix("wShoots") == "Shoots"
    assert dn.semantic_suffix("dwFlags") == "Flags"
    # no recognizable prefix -> PascalCased as-is
    assert dn.semantic_suffix("Cost")[:1] == "C"


def test_is_offset_name_detects_offset_derived_tokens():
    assert dn.is_offset_name("DATATBLS_GetItemTypeField10")
    assert dn.is_offset_name("ITEMS_GetItemRecordField104")
    assert not dn.is_offset_name("DATATBLS_GetItemTypeThrowable")


def test_domain_shortens_struct_to_name_core():
    assert dn._domain("D2ItemTypesTxt") == "ItemType"
    assert dn._domain("D2OverlayTxt") == "Overlay"
    assert dn._domain("D2ItemsTxt") == "Item"


def test_derive_getter_name_from_field():
    s = _parsed()
    d = dn.derive_getter_name("DATATBLS_GetItemTypeField10", "D2ItemTypesTxt", 0x10, s)
    assert d["ok"]
    assert d["field"] == "nThrowable"
    assert "Throwable" in d["proposed_name"]
    # no field at the given offset -> not ok (offset name stays honest)
    d2 = dn.derive_getter_name("X", "D2ItemTypesTxt", 0x999, s)
    assert not d2["ok"]


def test_extract_from_candidate_pulls_stride_and_offsets():
    cpp = (
        'extern "C" unsigned char __stdcall DATATBLS_GetItemTypeField10(int idx){\n'
        '  char* records = (char*)*(void**)(base + 0xbf8);\n'
        '  char* rec = records + (int)idx * 0xe4;\n'
        '  return *(unsigned char*)(rec + 0x10);\n'
        '}\n'
    )
    out = dn._extract_from_candidate(cpp)
    assert out["stride"] == 0xE4
    assert out["read_off"] == 0x10
