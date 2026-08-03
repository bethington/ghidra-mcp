"""Offline tests for fun-doc/crt_identify.py.

No Ghidra, no network. The COFF parser is exercised against a synthetic object
built here byte by byte, so the parser is genuinely covered rather than being
trusted because a real .lib happened to be on disk.
"""
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "fun-doc"))

import crt_identify as ci  # noqa: E402


# ---------------------------------------------------------------- masking ---

def test_mask_bytes_zeroes_four_bytes_per_reloc():
    body = bytes(range(16))
    out = ci.mask_bytes(body, [4])
    assert out[4:8] == b"\0\0\0\0"
    assert out[0:4] == body[0:4]
    assert out[8:] == body[8:]


def test_mask_bytes_clamps_at_end_of_body():
    """A relocation two bytes from the end must not raise or wrap."""
    assert ci.mask_bytes(b"\xaa" * 6, [4]) == b"\xaa\xaa\xaa\xaa\x00\x00"


def test_informative_counts_only_unmasked_bytes():
    fn = ci.LibFunc("_x", bytes(22), (2, 12), "o.obj", "l.lib")
    assert fn.size == 22
    assert fn.informative == 22 - 8


def test_informative_does_not_double_count_overlapping_relocs():
    fn = ci.LibFunc("_x", bytes(20), (4, 6), "o.obj", "l.lib")
    # 4..7 and 6..9 overlap -> 6 masked bytes, not 8
    assert fn.informative == 14


# ------------------------------------------------------------ index guards ---

def _fn(name, size, relocs=(), first=b"\x55\x8b\xec\x83\xec\x10\x53\x56"):
    body = first + bytes(range(size - len(first)))
    return ci.LibFunc(name, body[:size], tuple(relocs), "o.obj", "l.lib")


def test_index_rejects_functions_shorter_than_prefix():
    idx = ci.LibraryIndex()
    assert idx.add(_fn("_tiny", 6)) is False
    assert idx.count == 0 and idx.rejected == 1


def test_index_rejects_relocation_dominated_functions():
    """The import-thunk class: six bytes, four of them a relocated address.

    Every import thunk in a binary is `ff 25 <addr>`, so masking makes them all
    identical. Admitting these made a D2Common sweep claim 108 extra functions,
    including game code like PRESET_AllocateAndValidateResourceSlot.
    """
    idx = ci.LibraryIndex()
    assert idx.add(ci.LibFunc("__getdrives", b"\xff\x25\x00\x00\x00\x00\x90\x90",
                              (2,), "o.obj", "l.lib")) is False
    assert idx.count == 0


def test_index_accepts_a_normal_function():
    idx = ci.LibraryIndex()
    assert idx.add(_fn("_qsort", 64)) is True
    assert idx.count == 1


def test_candidates_finds_a_clean_prefix_function():
    idx = ci.LibraryIndex()
    fn = _fn("_qsort", 64)
    idx.add(fn)
    assert [c.name for c in idx.candidates(fn.body[:ci.PREFIX])] == ["_qsort"]


def test_candidates_finds_a_function_with_a_reloc_inside_the_prefix():
    """The whole point of the mask-pattern buckets.

    The library's copy has zeros where the linker will write an address; the
    linked image has the real address. Lookup must still find it.
    """
    idx = ci.LibraryIndex()
    lib_body = b"\xb8\x00\x00\x00\x00\x50\xe8\x11" + bytes(40)
    idx.add(ci.LibFunc("_ctor", lib_body, (1,), "o.obj", "l.lib"))
    image_head = b"\xb8\x78\x56\x34\x12\x50\xe8\x11"      # same code, linked
    assert [c.name for c in idx.candidates(image_head)] == ["_ctor"]


def test_candidates_rejects_a_different_function_with_the_same_mask_pattern():
    idx = ci.LibraryIndex()
    idx.add(ci.LibFunc("_ctor", b"\xb8\x00\x00\x00\x00\x50\xe8\x11" + bytes(40),
                       (1,), "o.obj", "l.lib"))
    # same relocation position, different surrounding opcodes
    assert idx.candidates(b"\xb8\x78\x56\x34\x12\x99\x99\x99") == []


# ----------------------------------------------------------- match verdicts ---

def _match(**kw):
    base = dict(address="00001000", current_name="FUN_00001000",
                lib_name="_qsort", size=64, obj="o.obj", lib="libcmt.lib",
                informative=64)
    base.update(kw)
    return ci.Match(**base)


def test_strong_unambiguous_match_is_writable_and_nameable():
    m = _match()
    assert m.writable and m.confident_name and not m.weak


def test_ambiguous_match_is_never_written():
    """Ambiguity means the evidence does not identify a function.

    LIB_CRT makes the selector skip a function permanently, so an ambiguous
    match must not earn one: 141 OpenSSL functions all matched `__ld12tod`.
    """
    m = _match(lib_name=None, ambiguous=True,
               candidates=["__ld12tod", "__ld12tof"])
    assert not m.writable and not m.confident_name


def test_weak_match_is_reported_but_never_written():
    m = _match(informative=ci.STRONG_INFORMATIVE_BYTES - 1)
    assert m.weak
    assert not m.writable and not m.confident_name


def test_linker_local_label_is_never_applied_as_a_name():
    """Same class of junk as the FID database's `$L20876`."""
    m = _match(lib_name="$L20876")
    assert m.writable                 # it IS library code
    assert not m.confident_name       # but that is not a name


def test_short_but_informative_match_is_not_named():
    m = _match(size=ci.MIN_CONFIDENT_LEN - 1,
               informative=ci.STRONG_INFORMATIVE_BYTES + 5)
    assert not m.confident_name


@pytest.mark.parametrize("name,expected", [
    ("FUN_6fd51000", True), ("SUB_1000", True), ("LAB_1000", True),
    ("thunk_FUN_6fd51000", True), ("entry", True),
    ("_qsort", False), ("LOG_CloseLogFileHandle", False),
    ("DATATBLS_GetLCIDFromCodePage", False), ("", False),
])
def test_is_default_name(name, expected):
    assert ci.is_default_name(name) is expected


def test_guard_ordering_is_sane():
    """A weak floor below the index floor would make the weak band empty."""
    assert ci.MIN_INFORMATIVE_BYTES < ci.STRONG_INFORMATIVE_BYTES


# --------------------------------------------------------------- COFF parse ---

def _build_coff(func_name: str, code: bytes, reloc_offsets=()) -> bytes:
    """A minimal but valid i386 COFF object with one code section."""
    nrel = len(reloc_offsets)
    hdr_size = 20
    sec_size = 40
    data_off = hdr_size + sec_size
    reloc_off = data_off + len(code)
    sym_off = reloc_off + nrel * 10

    section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", 0, 0, len(code), data_off,
        reloc_off if nrel else 0, 0, nrel, 0,
        0x20 | 0x20000000 | 0x40000000)          # CODE | EXECUTE | READ

    relocs = b"".join(struct.pack("<IIH", off, 0, 6) for off in reloc_offsets)

    # One symbol; long names live in the string table.
    name_field = struct.pack("<II", 0, 4)        # offset 4 into the string table
    symbol = name_field + struct.pack(
        "<IhHBB", 0, 1, ci.IMAGE_SYM_DTYPE_FUNCTION << 4,
        ci.IMAGE_SYM_CLASS_EXTERNAL, 0)
    encoded = func_name.encode() + b"\0"
    strtab = struct.pack("<I", 4 + len(encoded)) + encoded

    header = struct.pack("<HHIIIHH", ci.IMAGE_FILE_MACHINE_I386, 1, 0,
                         sym_off, 1, 0, 0)
    return header + section + code + relocs + symbol + strtab


def test_coff_functions_extracts_body_and_relocations():
    code = bytes(range(64))
    blob = _build_coff("_myfunc", code, (8, 20))
    got = list(ci.coff_functions(blob))
    assert len(got) == 1
    name, body, relocs = got[0]
    assert name == "_myfunc"
    assert body == code
    assert relocs == [8, 20]


def test_coff_functions_ignores_non_i386_objects():
    blob = bytearray(_build_coff("_myfunc", bytes(64)))
    struct.pack_into("<H", blob, 0, 0x8664)      # AMD64
    assert list(ci.coff_functions(bytes(blob))) == []


def test_coff_functions_survives_a_truncated_object():
    assert list(ci.coff_functions(b"\x4c\x01")) == []


def test_ar_members_rejects_a_non_archive():
    with pytest.raises(ValueError):
        list(ci.ar_members(b"not an archive"))


def test_ar_members_reads_members_and_skips_symbol_tables():
    def member(name, body):
        hdr = (f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'0':<8}"
               f"{len(body):<10}").encode() + b"`\n"
        return hdr + body + (b"\n" if len(body) & 1 else b"")

    data = (b"!<arch>\n"
            + member("/", b"symtab")            # skipped
            + member("a.obj/", b"AAAA")
            + member("b.obj/", b"BBB"))
    assert list(ci.ar_members(data)) == [("a.obj", b"AAAA"), ("b.obj", b"BBB")]


# ------------------------------------------------- end-to-end, if libs exist ---

def test_real_library_index_is_sane_if_present():
    libs = [p for p in ci.default_libraries() if os.path.exists(p)]
    if not libs:
        pytest.skip("vendored VS2003/VC6 libraries not present")
    idx = ci.load_index(libs)
    assert idx.count > 1000, "a CRT should contribute thousands of functions"
    assert idx.rejected > 0, "the informative-bytes floor should reject some"
    # Every indexed function must satisfy the guards it was admitted under.
    for lst in idx.clean.values():
        for fn in lst:
            assert fn.size >= ci.PREFIX
            assert fn.informative >= ci.MIN_INFORMATIVE_BYTES
