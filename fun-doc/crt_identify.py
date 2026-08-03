"""Ground-truth CRT identification: is this function literally library code?

fun-doc has three ways to decide a function is runtime library code, and until
now the best of them was still a guess:

    tier 0  Ghidra's Function ID analyzer  -- hash-exact, but its hashing drops
            short functions (71 of 1,120 signatures excluded from the VS2003
            build as hash-too-short / duplicate / thunk) and it only ever runs
            at analysis time
    tier 1  curated LIB_* Ghidra tags      -- durable, but hand-maintained
    tier 2  library_code_detector.py       -- names and callees, deliberately
            conservative, and admittedly weak (it saw only 10 of 79 CRT_
            functions on a corpus calibration)

This module adds the one that is not a guess at all. Diablo II statically links
Visual Studio .NET 2003 SP1's `libcmt.lib`, proven two independent ways (Rich
header product IDs, and relocation-masked byte comparison scoring 100.0% against
VS2003 versus 6-18% against VC6). We have that library on disk. So instead of
inferring "this looks like CRT" from a name, we can ask "are these bytes,
literally, `_qsort` out of qsort.obj" -- and get a yes or no.

HOW IT WORKS

A linked image cannot be compared byte-for-byte against a library object,
because the linker rewrites fields inside the code: absolute addresses (DIR32)
and call displacements (REL32). But the object's own relocation table says
exactly where those fields are. Zero them on BOTH sides and the remainder must
match exactly, or it is not the same function.

Only the OBJECT's relocations are needed -- not the PE's .reloc. That is the
part worth remembering: .reloc lists only base-relocations (DIR32), so masking
with it alone leaves every `call rel32` displacement unmasked and every
function containing a call fails to match.

WHY IT BEATS THE FID DATABASE BUILT FROM THE SAME LIBRARY

Measured on D2Common (2,569 functions): this index matches 244, Ghidra's FID
analyzer with `vs2003_libcmt.fidb` attached matches 204. The difference is
almost entirely length -- FID will not hash a short function, and CRT is full
of them. `__lockexit` is NINE bytes and matches exactly.

GUARDS (the falsify.py discipline: ambiguous means no finding, never a weak one)

  * The comparison window is the LIBRARY function's length, so a binary
    function's size is never needed -- but the window must not run past the
    next function's start, or a short function's prefix would be matched
    against its neighbour's body.
  * A match whose masked bytes are shared by several DIFFERENT library names is
    AMBIGUOUS. The function is still library code -- that much is certain -- but
    the name is a guess, so no name is offered. Tiny stubs (`ret`, `xor eax,eax;
    ret`, a 5-byte jmp thunk) are the usual cause.
  * Below MIN_CONFIDENT_LEN bytes a match is reported but never used to rename,
    even when unambiguous. There simply is not enough code in four bytes for
    equality to mean identity.

Public API:
    load_index(libs=None)                  -> LibraryIndex (cached per process)
    identify_function(program, address)    -> Match | None
    identify_program(program)              -> list[Match]
    sync_to_ghidra(program, match, ...)    -> dict   THE single writer
    rich_toolchain(program_or_path)        -> str | None
"""

from __future__ import annotations

import json
import os
import re
import struct
import threading
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

GHIDRA_URL = os.environ.get("GHIDRA_URL", "http://127.0.0.1:8089").rstrip("/")

# Prefix length used to bucket the index. Long enough to partition well, short
# enough that most functions have no relocation inside it.
PREFIX = 8

# Below this many bytes an exact match is real but not *identifying* -- far too
# little code for equality to imply it is the same function rather than the same
# three instructions. Reported, classified, never used to rename.
MIN_CONFIDENT_LEN = 16

# The floor that actually matters, and it is NOT total length: a match is only
# evidence to the extent that bytes were COMPARED, and relocation sites are
# masked away before comparison. An import thunk is six bytes -- `ff 25` plus a
# four-byte relocated address -- so masking leaves TWO informative bytes, and
# every import thunk in a binary is then byte-identical to every other. Measured
# on D2Common: without this floor the sweep "identified" 108 extra functions,
# essentially all of them game import thunks matching the library's own
# `__getdrives` thunk, including PRESET_AllocateAndValidateResourceSlot. That is
# not a near miss, it is a whole class of nonsense, and it inflated an earlier
# prototype's headline from 179 to 244.
#
# Applied at INDEX BUILD time so the junk never enters the lookup at all.
MIN_INFORMATIVE_BYTES = 12

# The floor for WRITING anything to Ghidra. Between MIN_ and STRONG_ a match is
# reported but never tagged, bookmarked or applied -- it goes in the JSON for a
# human, and no further.
#
# Calibrated against a negative control rather than by taste. libcrypto-1_1.dll
# is OpenSSL built with a modern toolchain: it should match almost nothing in a
# VS2003/VC6 index, so every match it produces is a false positive. Measured:
#
#     floor   libcrypto matches   D2Common   Fog
#       12        163 (155 amb)      165     244     <- 141 of them "__ld12tod"
#       16         14 (  6 amb)      152     228
#       20          8 (  0 amb)      144     216     <- control goes clean
#       32          4 (  0 amb)      124     182     <- only real matches lost
#
# Twenty is where the control stops producing ambiguity on its own merits while
# the true-positive binaries still keep their matches. Past it we only lose real
# ones. The 141-way "__ld12tod" pileup is the shape to remember: a 22-byte
# function with two relocations has 14 informative bytes, and generic little
# wrappers like that are shared by hundreds of unrelated functions.
STRONG_INFORMATIVE_BYTES = 20

# The bookmark category this module owns. Deliberately NOT "Function ID
# Analyzer": that one belongs to Ghidra's analyzer, and doc_lint reads it as
# tier 0. Ours is a separate, equally durable source that survives renames the
# same way.
BOOKMARK_CATEGORY = "CRT Identify"

LIBRARY_TAG = "LIB_CRT"

# MSVC linker-local labels. Same class of junk that `$L20876` turned out to be
# in the FID database -- a real match, but not a name. See doc_lint.is_linker_local.
LINKER_LOCAL = re.compile(r"^\$(L|LN|SG|M|T)\d+$")

# A name that already looks like a canonical CRT symbol: `_qsort`, `__unlock`,
# `___sbh_alloc_block`. Used to leave alias differences alone -- see
# sync_to_ghidra.
CRT_SHAPED = re.compile(r"^_{1,3}[a-z]")

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_DTYPE_FUNCTION = 2
IMAGE_SCN_CNT_CODE = 0x20
IMAGE_FILE_MACHINE_I386 = 0x14C


# --------------------------------------------------------------------------
# COFF archive / object parsing
# --------------------------------------------------------------------------

def ar_members(data: bytes) -> Iterable[Tuple[str, bytes]]:
    """Yield (member_name, blob) for each member of a COFF archive (.lib)."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not a COFF archive")
    pos, longnames = 8, b""
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[0:16].decode("ascii", "replace").strip()
        try:
            size = int(hdr[48:58].decode("ascii").strip())
        except ValueError:
            break
        body = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)          # members are 2-byte aligned
        if name.startswith("//"):              # the long-name string table
            longnames = body
            continue
        if name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            end = longnames.find(b"\0", off)
            name = longnames[off:end].decode("ascii", "replace")
        elif name.endswith("/"):
            name = name[:-1]
        if name in ("/", ""):                  # the two symbol-table members
            continue
        yield name, body


def coff_functions(blob: bytes) -> Iterable[Tuple[str, bytes, List[int]]]:
    """Yield (symbol, body, reloc_offsets) for every function in a COFF object.

    A function's extent is the gap to the next symbol in the same section --
    objects carry no explicit size -- so symbols are sorted by value first.
    """
    if len(blob) < 20:
        return
    machine, nsec, _stamp, symptr, nsym, optsz, _chars = struct.unpack_from(
        "<HHIIIHH", blob, 0)
    if machine != IMAGE_FILE_MACHINE_I386 or not symptr or not nsym:
        return

    secs = []
    off = 20 + optsz
    for i in range(nsec):
        s = blob[off + i * 40: off + (i + 1) * 40]
        if len(s) < 40:
            return
        _vsize, _vaddr, rawsize, rawptr, relptr, _lnptr, nrel, _nln, flags = \
            struct.unpack_from("<IIIIIIHHI", s, 8)
        secs.append((rawsize, rawptr, relptr, nrel, flags))

    strtab = blob[symptr + nsym * 18:]

    def symname(rec: bytes) -> str:
        if rec[0:4] == b"\0\0\0\0":
            o = struct.unpack_from("<I", rec, 4)[0]
            end = strtab.find(b"\0", o)
            return strtab[o:end].decode("ascii", "replace")
        return rec[0:8].rstrip(b"\0").decode("ascii", "replace")

    # STATIC symbols are admitted alongside EXTERNAL ones because the filter
    # below keeps only DTYPE_FUNCTION -- these are genuine file-local functions,
    # not the internal labels that would truncate a function if used as
    # boundaries. Measured: dropping them costs real coverage (D2Common 179 ->
    # 160 matches), so the intuition that they were noise was simply wrong.
    per_sec: Dict[int, List[Tuple[int, str]]] = {}
    i = 0
    while i < nsym:
        rec = blob[symptr + i * 18: symptr + (i + 1) * 18]
        if len(rec) < 18:
            break
        value, secnum, stype, sclass, naux = struct.unpack_from("<IhHBB", rec, 8)
        if (sclass in (IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC)
                and secnum > 0
                and (stype >> 4) == IMAGE_SYM_DTYPE_FUNCTION):
            per_sec.setdefault(secnum - 1, []).append((value, symname(rec)))
        i += 1 + naux

    for secidx, syms in per_sec.items():
        if secidx >= len(secs):
            continue
        rawsize, rawptr, relptr, nrel, flags = secs[secidx]
        if not flags & IMAGE_SCN_CNT_CODE:
            continue
        raw = blob[rawptr:rawptr + rawsize]
        relocs = []
        for r in range(nrel):
            ro = relptr + r * 10
            if ro + 10 > len(blob):
                break
            relocs.append(struct.unpack_from("<I", blob, ro)[0])
        ordered = sorted(set(syms))
        for j, (value, name) in enumerate(ordered):
            end = ordered[j + 1][0] if j + 1 < len(ordered) else rawsize
            body = raw[value:end]
            if body:
                yield name, body, [v - value for v in relocs if value <= v < end]


def mask_bytes(body: bytes, relocs: Sequence[int], width: int = 4) -> bytes:
    """Zero the 4-byte field at each relocation site."""
    b = bytearray(body)
    n = len(b)
    for off in relocs:
        for k in range(width):
            if 0 <= off + k < n:
                b[off + k] = 0
    return bytes(b)


# --------------------------------------------------------------------------
# The index
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class LibFunc:
    name: str
    body: bytes
    relocs: Tuple[int, ...]
    obj: str
    lib: str

    @property
    def size(self) -> int:
        return len(self.body)

    @property
    def informative(self) -> int:
        """Bytes that survive masking -- the only ones a match is evidence of."""
        covered = {o for r in self.relocs
                   for o in range(r, r + 4) if 0 <= o < len(self.body)}
        return len(self.body) - len(covered)


class LibraryIndex:
    """Masked-prefix lookup over every function in a set of static libraries.

    Bucketing has one wrinkle: the mask depends on the LIBRARY function's
    relocations, which are unknown when hashing a candidate from the binary.
    Functions whose first PREFIX bytes contain no relocation (the large
    majority) bucket on their raw prefix. The rest are grouped by their mask
    PATTERN within the prefix -- there are only a handful of distinct patterns,
    so the binary side simply applies each pattern in turn. That keeps lookup
    O(number of distinct patterns) instead of O(number of library functions),
    which is the difference between a sweep taking seconds and taking hours.
    """

    def __init__(self) -> None:
        self.clean: Dict[bytes, List[LibFunc]] = {}
        self.patterned: Dict[Tuple[int, ...], Dict[bytes, List[LibFunc]]] = {}
        self.count = 0
        self.rejected = 0
        self.libs: List[str] = []

    def add(self, fn: LibFunc) -> bool:
        # Too little survives masking for a match to mean anything, or the body
        # is shorter than the prefix we bucket on. Both are rejected here rather
        # than at lookup, so the lookup never has to reason about them.
        if fn.size < PREFIX or fn.informative < MIN_INFORMATIVE_BYTES:
            self.rejected += 1
            return False
        self.count += 1
        inprefix = tuple(sorted({o for r in fn.relocs
                                 for o in range(r, r + 4) if 0 <= o < PREFIX}))
        if not inprefix:
            self.clean.setdefault(fn.body[:PREFIX], []).append(fn)
        else:
            masked = bytearray(fn.body[:PREFIX])
            for o in inprefix:
                masked[o] = 0
            self.patterned.setdefault(inprefix, {}).setdefault(
                bytes(masked), []).append(fn)
        return True

    def candidates(self, head: bytes) -> List[LibFunc]:
        """Library functions whose prefix could match these bytes."""
        out = list(self.clean.get(head, ()))
        for pattern, table in self.patterned.items():
            masked = bytearray(head)
            for o in pattern:
                if o < len(masked):
                    masked[o] = 0
            out.extend(table.get(bytes(masked), ()))
        return out

    @classmethod
    def from_libraries(cls, libs: Sequence[str]) -> "LibraryIndex":
        idx = cls()
        for lib in libs:
            if not os.path.exists(lib):
                continue
            idx.libs.append(lib)
            with open(lib, "rb") as fh:
                data = fh.read()
            for member, blob in ar_members(data):
                try:
                    for name, body, relocs in coff_functions(blob):
                        idx.add(LibFunc(name, body, tuple(relocs), member, lib))
                except (struct.error, ValueError, IndexError):
                    # A malformed member is not worth aborting a 1,300-function
                    # index over; skip it and keep going.
                    continue
        return idx


def default_libraries() -> List[str]:
    """The release runtime libraries vendored with the benchmark toolchain.

    Merged deliberately rather than routed per binary: a relocation-masked
    exact match effectively cannot collide across toolchains, so merging costs
    no accuracy and avoids a routing layer that can itself be wrong. Use
    rich_toolchain() to report which binaries we hold no library for.
    """
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "benchmark", "tools", "vc6")
    return [
        os.path.join(root, "VS7", "Lib", "libcmt.lib"),     # VS2003 C runtime
        os.path.join(root, "VS7", "Lib", "libcpmt.lib"),    # VS2003 C++ / STL
        os.path.join(root, "VC98", "LIB", "LIBCMT.LIB"),    # VC6 C runtime
    ]


_index_lock = threading.Lock()
_index_cache: Dict[Tuple[str, ...], LibraryIndex] = {}


def load_index(libs: Optional[Sequence[str]] = None) -> LibraryIndex:
    """Build (once per process) and return the merged library index."""
    key = tuple(libs or default_libraries())
    with _index_lock:
        if key not in _index_cache:
            _index_cache[key] = LibraryIndex.from_libraries(key)
        return _index_cache[key]


# --------------------------------------------------------------------------
# Reading the program under test
# --------------------------------------------------------------------------

def _get(path: str, **params) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=180) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _post(path: str, program: str, body: dict) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode({"program": program})
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


class CodeImage:
    """Executable bytes of a program, pulled from Ghidra in bulk.

    Read from Ghidra rather than the file on disk on purpose: the on-disk path
    a program was imported from is frequently stale or gone (D2Common's points
    at a directory that no longer exists), whereas Ghidra always has the bytes.
    Fetched in 256 KB chunks -- .text is three requests, not one per function.
    """

    CHUNK = 0x40000

    def __init__(self, program: str) -> None:
        self.program = program
        self.blocks: List[Tuple[int, bytes]] = []
        for seg in _get("/list_segments", program=program,
                        limit=200).get("segments", []):
            if not seg.get("executable") or not seg.get("initialized"):
                continue
            start = int(str(seg["start"]), 16)
            size = int(seg["size"])
            buf = bytearray()
            while len(buf) < size:
                n = min(self.CHUNK, size - len(buf))
                res = _get("/read_memory", program=program,
                           address=f"{start + len(buf):x}", length=n)
                hexed = res.get("hex") or ""
                if not hexed:
                    break
                buf.extend(bytes.fromhex(hexed))
            self.blocks.append((start, bytes(buf)))

    def read(self, addr: int, length: int) -> bytes:
        for start, buf in self.blocks:
            if start <= addr < start + len(buf):
                off = addr - start
                return buf[off:off + length]
        return b""


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

@dataclass
class Match:
    address: str
    current_name: str
    lib_name: Optional[str]          # None when ambiguous
    size: int
    obj: str
    lib: str
    ambiguous: bool = False
    candidates: List[str] = field(default_factory=list)
    program: str = ""
    informative: int = 0

    @property
    def weak(self) -> bool:
        """Too few bytes survived masking for this to be worth writing down."""
        return self.informative < STRONG_INFORMATIVE_BYTES

    @property
    def writable(self) -> bool:
        """May ANYTHING be written to Ghidra for this match?

        Ambiguity and weakness both mean the evidence does not identify a
        function -- and an unidentified function must not be tagged LIB_CRT,
        because that tag makes the selector skip it forever. Reported, not
        written: the JSON report is the review surface.
        """
        return not self.ambiguous and not self.weak

    @property
    def confident_name(self) -> bool:
        """May this match's NAME be written into Ghidra?"""
        return bool(self.writable
                    and self.lib_name
                    and self.size >= MIN_CONFIDENT_LEN
                    and not LINKER_LOCAL.match(self.lib_name))


def _canon(name: str) -> str:
    return (name or "").lstrip("_").lower()


def is_default_name(name: str) -> bool:
    """Ghidra's own placeholder names, the only ones safe to overwrite."""
    return bool(re.match(r"^(FUN_|SUB_|LAB_|thunk_FUN_|Ordinal_|entry$)",
                         name or ""))


def match_at(index: LibraryIndex, image: CodeImage, addr: int,
             window: int) -> Optional[Tuple[List[LibFunc], int]]:
    """All library functions matching at `addr`, bounded by `window` bytes."""
    head = image.read(addr, PREFIX)
    if len(head) < PREFIX:
        return None
    found: List[LibFunc] = []
    best = 0
    for fn in index.candidates(head):
        n = fn.size
        if n > window:                 # would run past the next function
            continue
        img = image.read(addr, n)
        if len(img) != n:
            continue
        if mask_bytes(fn.body, fn.relocs) == mask_bytes(img, fn.relocs):
            found.append(fn)
            best = max(best, n)
    return (found, best) if found else None


def identify_program(program: str,
                     index: Optional[LibraryIndex] = None,
                     image: Optional[CodeImage] = None) -> List[Match]:
    """Every function in `program` that is byte-identical to library code."""
    index = index or load_index()
    image = image or CodeImage(program)

    fns = sorted((int(str(f["address"]), 16), f.get("name") or "")
                 for f in _get("/list_functions", program=program,
                               limit=100000).get("functions", []))

    out: List[Match] = []
    for i, (addr, name) in enumerate(fns):
        # The window is the distance to the next function. Without it a short
        # library function could match a longer binary function's prologue and
        # claim the whole thing.
        window = (fns[i + 1][0] - addr) if i + 1 < len(fns) else 0x1000
        if window <= 0:
            continue
        hit = match_at(index, image, addr, window)
        if not hit:
            continue
        found, best = hit
        names = sorted({f.name for f in found})
        distinct = {_canon(n) for n in names}
        winner = max(found, key=lambda f: f.size)
        out.append(Match(
            address=f"{addr:08x}", current_name=name,
            lib_name=winner.name if len(distinct) == 1 else None,
            size=best, obj=winner.obj, lib=os.path.basename(winner.lib),
            ambiguous=len(distinct) > 1, candidates=names, program=program,
            informative=winner.informative))
    return out


def identify_function(program: str, address: str,
                      index: Optional[LibraryIndex] = None) -> Optional[Match]:
    """Single-function lookup for the triage hook.

    Builds no CodeImage: it reads only the bytes it needs, so the cold path
    pays one small request rather than a whole-section fetch.
    """
    index = index or load_index()
    addr = int(str(address).replace("0x", ""), 16)

    class _One(CodeImage):                      # noqa: D401 - tiny shim
        def __init__(self) -> None:             # pylint: disable=super-init-not-called
            self.program = program
            res = _get("/read_memory", program=program,
                       address=f"{addr:x}", length=0x1000)
            self.blocks = [(addr, bytes.fromhex(res.get("hex") or ""))]

    image = _One()
    hit = match_at(index, image, addr, 0x1000)
    if not hit:
        return None
    found, best = hit
    names = sorted({f.name for f in found})
    distinct = {_canon(n) for n in names}
    winner = max(found, key=lambda f: f.size)
    return Match(address=f"{addr:08x}", current_name="",
                 lib_name=winner.name if len(distinct) == 1 else None,
                 size=best, obj=winner.obj, lib=os.path.basename(winner.lib),
                 ambiguous=len(distinct) > 1, candidates=names, program=program,
                 informative=winner.informative)


# --------------------------------------------------------------------------
# The single writer
# --------------------------------------------------------------------------

def sync_to_ghidra(match: Match, apply_name: bool = True,
                   rename_documented: bool = False) -> dict:
    """Write one match's verdict to Ghidra. THE single writer for this module.

    Every lane -- sweep, triage hook, dashboard -- goes through here, for the
    same reason falsify.sync_to_ghidra exists: when a second writer grows
    somewhere else, a fix to one of them silently misses the other.

    Always: the LIB_CRT tag and a durable bookmark. The bookmark is the point --
    like FID's, it SURVIVES a later rename, so a documentation pass that
    overwrites the name is recoverable rather than merely detectable.

    The name is applied only when the match is confident AND the function still
    carries a Ghidra default. Overwriting real documentation is gated behind
    rename_documented, because that bucket deserves review, not a sweep.
    """
    program, addr = match.program, match.address
    result = {"address": addr, "tagged": False, "bookmarked": False,
              "renamed": None, "skipped": None}

    # Nothing at all is written for a match that does not identify a function.
    # The LIB_CRT tag makes the selector skip a function permanently, so an
    # ambiguous or weak match must not earn one -- 141 OpenSSL functions once
    # "matched" __ld12tod, and tagging them would have retired real code.
    if not match.writable:
        result["skipped"] = "ambiguous" if match.ambiguous else "weak-evidence"
        return result

    tag = _post("/add_function_tag", program,
                {"function": addr, "tags": LIBRARY_TAG})
    result["tagged"] = bool(tag.get("success")
                            or str(tag.get("status", "")).lower() == "success")

    bm = _post("/set_bookmark", program, {
        "address": addr, "category": BOOKMARK_CATEGORY,
        "comment": f"CRT exact match - {match.lib_name} ({match.obj}) "
                   f"[{match.lib}, {match.size}b, "
                   f"{match.informative} informative]"})
    result["bookmarked"] = bool(bm.get("success")
                                or str(bm.get("status", "")).lower() == "success")

    if not apply_name or not match.confident_name:
        result["skipped"] = ("too-short" if match.size < MIN_CONFIDENT_LEN else
                             "linker-local" if match.lib_name
                             and LINKER_LOCAL.match(match.lib_name) else
                             "name-not-requested")
        return result

    if _canon(match.current_name) == _canon(match.lib_name or ""):
        result["skipped"] = "already-correct"
        return result

    if not is_default_name(match.current_name) and not rename_documented:
        result["skipped"] = "documented-name-preserved"
        return result

    # Even with rename_documented, leave a name that is ALREADY a canonical CRT
    # symbol alone. `_memmove` -> `_memcpy` is not a correction: MSVC compiles
    # both from one object, so the two names are aliases and the existing one is
    # at least as informative. The finding worth acting on is a GAME-STYLE name
    # on library code, not a decoration difference between two library names.
    if not is_default_name(match.current_name) and CRT_SHAPED.match(match.current_name):
        result["skipped"] = "already-a-library-name"
        return result

    res = _post("/rename_function", program,
                {"old_name": addr, "new_name": match.lib_name})
    ok = bool(res.get("success")
              or str(res.get("status", "")).lower() == "success")

    if not ok and "already exists at this address" in str(res):
        # Not a real conflict, and restore_fid_names.py hit the same wall: an
        # analyzer left its own label on the address as a non-primary symbol, so
        # the rename is blocked by the very evidence being applied. Drop the
        # duplicate label, then take the name.
        _post("/delete_label", program,
              {"address": addr, "name": match.lib_name})
        res = _post("/rename_function", program,
                    {"old_name": addr, "new_name": match.lib_name})
        ok = bool(res.get("success")
                  or str(res.get("status", "")).lower() == "success")

    result["renamed"] = match.lib_name if ok else None
    if not ok:
        # Loud, never silent -- a failed write-back that prints nothing is how
        # the wrong-binary CONF_ bug hid for weeks.
        result["error"] = str(res)[:200]
    return result


# --------------------------------------------------------------------------
# Rich header -- which toolchain built this, and do we hold its library?
# --------------------------------------------------------------------------

def rich_toolchain(path: str) -> Optional[dict]:
    """Parse a PE's Rich header -> {'builds': {...}, 'toolchain': str}.

    This is the measurement that identified D2's CRT in the first place: every
    shipped D2 binary carries 710-series product IDs at build 6030 (VS .NET
    2003 SP1) and zero VC6 objects. Used here for an honest coverage report --
    'no matches' on a binary we hold no library for is a gap, not a result.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(0x1000)
    except OSError:
        return None
    end = data.find(b"Rich")
    if end < 0:
        return None
    key = struct.unpack_from("<I", data, end + 4)[0]
    # The "DanS" signature is stored XOR-encrypted with the same key, so search
    # for its encrypted form rather than the literal.
    start = data.rfind(struct.pack("<I", 0x536E6144 ^ key), 0, end)
    if start < 0:
        return None
    builds: Dict[Tuple[int, int], int] = {}
    for off in range(start + 16, end, 8):
        if off + 8 > end:
            break
        comp, count = struct.unpack_from("<II", data, off)
        comp ^= key
        count ^= key
        prod, build = comp >> 16, comp & 0xFFFF
        if prod or build:
            builds[(prod, build)] = builds.get((prod, build), 0) + count
    if not builds:
        return None
    known = {6030: "VS2003 SP1 (7.10.6030)", 8804: "VC6 SP6 (6.0.8804)",
             9782: "VS2005", 21022: "VS2008", 30729: "VS2008 SP1",
             40219: "VS2010 SP1", 50727: "VS2005 SP1"}
    top = max(builds.items(), key=lambda kv: kv[1])[0][1]
    return {"builds": {f"{p}:{b}": c for (p, b), c in sorted(builds.items())},
            "toolchain": known.get(top, f"build {top}")}
