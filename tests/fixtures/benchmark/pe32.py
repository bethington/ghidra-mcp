"""A minimal, deterministic PE32 (32-bit Windows) image writer.

Enough of the format to produce a real, loadable x86 DLL or console EXE with
an export table, an import table and named sections -- and nothing else. There
is no compiler, no linker and no CRT involved, so the output is a pure function
of this repository's own source and is byte-identical on every machine.

What is deliberately omitted, and why it is safe to omit:

* **Base relocations.** ``IMAGE_FILE_RELOCS_STRIPPED`` is set and
  ``DllCharacteristics`` is 0, so the loader honours the preferred image base.
  That is also what keeps the fixture's function addresses stable, which is the
  whole point of an address-keyed regression baseline.
* **Debug directory / PDB.** Nothing to strip, so nothing can leak a local path.
* **Rich header.** It records a build toolchain; there isn't one. Provenance
  lives in ``build_manifest.json`` instead, which is a file a human can read.
* **Checksum.** Only drivers and some system DLLs are checked.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

TEXT_CHARACTERISTICS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
RDATA_CHARACTERISTICS = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
DATA_CHARACTERISTICS = (
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
)

DIRECTORY_EXPORT = 0
DIRECTORY_IMPORT = 1
DIRECTORY_IAT = 12

# A fixed timestamp. Real linkers write "now"; that would make every rebuild
# differ and defeat the byte-identity check that proves the committed binary
# came from the committed generator. 2026-08-31T00:00:00Z.
FIXED_TIMESTAMP = 0x68B3E980

# The conventional MS-DOS stub: a 16-bit program that prints a message and
# exits. Byte-for-byte what link.exe emits, so a hex dump of the fixture looks
# like a hex dump of any other PE.
DOS_STUB = bytes.fromhex(
    "0e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f"
    "742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000"
)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    data: bytes
    characteristics: int

    @property
    def virtual_size(self) -> int:
        return len(self.data)

    @property
    def raw_size(self) -> int:
        return align_up(len(self.data), FILE_ALIGNMENT)


def build_image(
    *,
    image_base: int,
    sections: list[Section],
    entry_rva: int,
    directories: dict[int, tuple[int, int]],
    is_dll: bool,
    subsystem: int,
) -> bytes:
    """Assemble a complete PE32 image.

    ``directories`` maps an ``IMAGE_DIRECTORY_ENTRY_*`` index to ``(rva, size)``.
    Sections must be supplied in ascending RVA order.
    """
    if not sections:
        raise ValueError("a PE image needs at least one section")
    for earlier, later in zip(sections, sections[1:]):
        if later.rva <= earlier.rva:
            raise ValueError("sections must be in ascending RVA order")

    header_size = (
        0x40 + len(DOS_STUB)          # DOS header + stub
        + 4 + 20 + 224                 # PE signature + COFF header + optional header
        + 40 * len(sections)           # section table
    )
    size_of_headers = align_up(header_size, FILE_ALIGNMENT)

    raw_offset = size_of_headers
    raw_offsets: list[int] = []
    for section in sections:
        raw_offsets.append(raw_offset)
        raw_offset += section.raw_size

    size_of_code = sum(
        section.raw_size for section in sections
        if section.characteristics & IMAGE_SCN_CNT_CODE
    )
    size_of_initialized = sum(
        section.raw_size for section in sections
        if section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA
    )
    base_of_code = next(
        (s.rva for s in sections if s.characteristics & IMAGE_SCN_CNT_CODE), 0
    )
    base_of_data = next(
        (s.rva for s in sections
         if s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA),
        0,
    )
    last = sections[-1]
    size_of_image = align_up(last.rva + last.virtual_size, SECTION_ALIGNMENT)

    characteristics = (
        0x0001   # RELOCS_STRIPPED -- no .reloc, so honour the preferred base
        | 0x0002  # EXECUTABLE_IMAGE
        | 0x0004  # LINE_NUMS_STRIPPED
        | 0x0008  # LOCAL_SYMS_STRIPPED
        | 0x0100  # 32BIT_MACHINE
    )
    if is_dll:
        characteristics |= 0x2000

    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<H", dos_header, 0x02, 0x90)   # bytes on last page
    struct.pack_into("<H", dos_header, 0x04, 0x03)   # pages in file
    struct.pack_into("<H", dos_header, 0x08, 0x04)   # size of header in paragraphs
    struct.pack_into("<H", dos_header, 0x0A, 0x00)
    struct.pack_into("<H", dos_header, 0x0C, 0xFFFF)
    struct.pack_into("<H", dos_header, 0x10, 0xB8)
    struct.pack_into("<H", dos_header, 0x18, 0x40)   # relocation table offset
    struct.pack_into("<I", dos_header, 0x3C, 0x40 + len(DOS_STUB))  # e_lfanew

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,                 # Machine: i386
        len(sections),
        FIXED_TIMESTAMP,
        0,                      # PointerToSymbolTable
        0,                      # NumberOfSymbols
        224,                    # SizeOfOptionalHeader
        characteristics,
    )

    optional = struct.pack(
        "<HBBIIIIIII",
        0x010B,                 # PE32
        7, 10,                  # linker version, cosmetic
        size_of_code,
        size_of_initialized,
        0,                      # SizeOfUninitializedData
        entry_rva,
        base_of_code,
        base_of_data,
        image_base,
    )
    optional += struct.pack(
        "<IIHHHHHHIIIIHHIIIIII",
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        4, 0,                   # OS version 4.00 (Win NT / 9x era, as D2's own)
        0, 0,                   # image version
        4, 0,                   # subsystem version 4.00
        0,                      # Win32VersionValue
        size_of_image,
        size_of_headers,
        0,                      # CheckSum
        subsystem,
        0,                      # DllCharacteristics: no ASLR, no DEP opt-in
        0x100000, 0x1000,       # stack reserve / commit
        0x100000, 0x1000,       # heap reserve / commit
        0,                      # LoaderFlags
        16,                     # NumberOfRvaAndSizes
    )
    for index in range(16):
        rva, size = directories.get(index, (0, 0))
        optional += struct.pack("<II", rva, size)
    assert len(optional) == 224, len(optional)

    table = bytearray()
    for section, offset in zip(sections, raw_offsets):
        name = section.name.encode("ascii")
        if len(name) > 8:
            raise ValueError(f"section name too long: {section.name}")
        table += struct.pack(
            "<8sIIIIIIHHI",
            name.ljust(8, b"\0"),
            section.virtual_size,
            section.rva,
            section.raw_size,
            offset,
            0, 0, 0, 0,         # relocations / line numbers: none
            section.characteristics,
        )

    image = bytearray()
    image += dos_header
    image += DOS_STUB
    image += b"PE\0\0"
    image += coff
    image += optional
    image += table
    image += b"\0" * (size_of_headers - len(image))
    for section in sections:
        image += section.data
        image += b"\0" * (section.raw_size - len(section.data))
    return bytes(image)


def build_export_directory(
    *,
    dll_name: str,
    exports: list[tuple[str, int]],
    directory_rva: int,
    ordinal_base: int = 1,
) -> bytes:
    """Serialise an export directory that starts at ``directory_rva``.

    ``exports`` is ``(name, function RVA)``. Names are sorted, because the
    Windows loader binary-searches the name table; an unsorted table resolves
    some names and silently fails others.
    """
    ordered = sorted(exports)
    count = len(ordered)

    header_size = 40
    address_table_rva = directory_rva + header_size
    name_pointer_rva = address_table_rva + 4 * count
    ordinal_table_rva = name_pointer_rva + 4 * count
    strings_rva = ordinal_table_rva + 2 * count

    strings = bytearray()
    dll_name_rva = strings_rva + len(strings)
    strings += dll_name.encode("ascii") + b"\0"

    name_rvas: list[int] = []
    for name, _rva in ordered:
        name_rvas.append(strings_rva + len(strings))
        strings += name.encode("ascii") + b"\0"

    body = struct.pack(
        "<IIHHIIIIIII",
        0,                      # Characteristics
        FIXED_TIMESTAMP,
        0, 0,                   # version
        dll_name_rva,
        ordinal_base,
        count,                  # NumberOfFunctions
        count,                  # NumberOfNames
        address_table_rva,
        name_pointer_rva,
        ordinal_table_rva,
    )
    assert len(body) == header_size, len(body)
    for _name, rva in ordered:
        body += struct.pack("<I", rva)
    for rva in name_rvas:
        body += struct.pack("<I", rva)
    for index in range(count):
        body += struct.pack("<H", index)
    body += bytes(strings)
    return body


@dataclass
class ImportedDll:
    name: str
    functions: list[str]


def build_import_directory(
    *, imports: list[ImportedDll], directory_rva: int
) -> tuple[bytes, dict[str, int], tuple[int, int]]:
    """Serialise an import directory that starts at ``directory_rva``.

    Returns ``(bytes, iat_slot_rvas, (iat_rva, iat_size))``. The slot map is
    keyed ``"DLLNAME!Function"`` so generated code can call through a named
    thunk without knowing the layout.

    The lookup table and the address table are separate copies, as a real
    linker emits them: the loader overwrites the address table in place and
    keeps the lookup table as the record of what was asked for.
    """
    descriptor_size = 20
    descriptors_size = descriptor_size * (len(imports) + 1)

    lookup_rva = directory_rva + descriptors_size
    lookup_size = sum(4 * (len(dll.functions) + 1) for dll in imports)
    iat_rva = lookup_rva + lookup_size
    iat_size = lookup_size
    strings_rva = iat_rva + iat_size

    strings = bytearray()
    hint_name_rvas: dict[str, int] = {}
    dll_name_rvas: dict[str, int] = {}
    for dll in imports:
        for function in dll.functions:
            key = f"{dll.name}!{function}"
            if len(strings) % 2:
                strings += b"\0"          # hint/name entries are word-aligned
            hint_name_rvas[key] = strings_rva + len(strings)
            strings += struct.pack("<H", 0) + function.encode("ascii") + b"\0"
    for dll in imports:
        dll_name_rvas[dll.name] = strings_rva + len(strings)
        strings += dll.name.encode("ascii") + b"\0"

    descriptors = bytearray()
    lookup = bytearray()
    iat = bytearray()
    slots: dict[str, int] = {}
    for dll in imports:
        # The two tables are built in lockstep and have identical layout, so
        # one cursor describes both.
        cursor = len(lookup)
        descriptors += struct.pack(
            "<IIIII",
            lookup_rva + cursor,      # OriginalFirstThunk
            0,                        # TimeDateStamp (unbound)
            0,                        # ForwarderChain
            dll_name_rvas[dll.name],
            iat_rva + cursor,         # FirstThunk
        )
        for function in dll.functions:
            key = f"{dll.name}!{function}"
            slots[key] = iat_rva + len(iat)
            lookup += struct.pack("<I", hint_name_rvas[key])
            iat += struct.pack("<I", hint_name_rvas[key])
        lookup += struct.pack("<I", 0)
        iat += struct.pack("<I", 0)
    descriptors += b"\0" * descriptor_size

    body = bytes(descriptors) + bytes(lookup) + bytes(iat) + bytes(strings)
    return body, slots, (iat_rva, iat_size)
