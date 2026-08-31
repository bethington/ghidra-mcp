"""A minimal, deterministic 32-bit x86 assembler.

Only the instruction forms the benchmark fixture needs are implemented. Every
encoding is written out explicitly so the emitted bytes are a property of this
file and nothing else -- no toolchain, no environment, no ordering surprises.
Assembling the same program twice on any machine produces identical bytes,
which is what lets the committed fixture be checked byte-for-byte in CI.

Two kinds of forward reference are supported:

``rel32``
    A jump or call to a label inside the same code stream. Patched to
    ``target - (site + 4)``.

``abs32``
    A 32-bit virtual address of a symbol that lives in another section (a
    string, a global, an import thunk). Patched to ``image_base + rva`` at
    finalize time from a caller-supplied symbol table.

Branches always use the rel32 form even where rel8 would fit. That costs a few
bytes and buys fixed instruction sizes, so no second sizing pass is needed and
the layout cannot shift under an edit.
"""

from __future__ import annotations

import struct

# Register numbers, as used in ModR/M reg and r/m fields.
EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI = range(8)

REG_NAMES = {
    EAX: "eax", ECX: "ecx", EDX: "edx", EBX: "ebx",
    ESP: "esp", EBP: "ebp", ESI: "esi", EDI: "edi",
}

# 8-bit register numbers (al, cl, dl, bl share the low three bits with their
# 32-bit counterparts, which is all this assembler uses).
AL, CL, DL, BL = 0, 1, 2, 3

# Condition-code suffixes for the 0F 8x near-jump forms.
CONDITION_CODES = {
    "o": 0x0, "no": 0x1,
    "b": 0x2, "nb": 0x3, "ae": 0x3,
    "z": 0x4, "e": 0x4, "nz": 0x5, "ne": 0x5,
    "be": 0x6, "a": 0x7,
    "s": 0x8, "ns": 0x9,
    "l": 0xC, "ge": 0xD, "le": 0xE, "g": 0xF,
}


def _modrm(mod: int, reg: int, rm: int) -> int:
    return ((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)


def _mem_ebp(reg: int, disp: int) -> bytes:
    """ModR/M + displacement for ``[ebp+disp]``.

    ebp has no mod=00 form (that encoding means "absolute disp32"), so a zero
    displacement still needs the disp8 form.
    """
    if -128 <= disp <= 127:
        return bytes([_modrm(1, reg, EBP), disp & 0xFF])
    return bytes([_modrm(2, reg, EBP)]) + struct.pack("<i", disp)


def _mem_base(reg: int, base: int, disp: int) -> bytes:
    """ModR/M + displacement for ``[base+disp]``.

    esp is rejected rather than silently mis-encoded: it needs a SIB byte, and
    this assembler deliberately has none.
    """
    if base == ESP:
        raise ValueError("esp as a memory base needs a SIB byte; not supported")
    if base == EBP:
        return _mem_ebp(reg, disp)
    if disp == 0:
        return bytes([_modrm(0, reg, base)])
    if -128 <= disp <= 127:
        return bytes([_modrm(1, reg, base), disp & 0xFF])
    return bytes([_modrm(2, reg, base)]) + struct.pack("<i", disp)


class Assembler:
    """Accumulates machine code plus label definitions and relocations."""

    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self._rel32: list[tuple[int, str]] = []      # (patch offset, label)
        self._abs32: list[tuple[int, str]] = []      # (patch offset, symbol)

    # -- structure ---------------------------------------------------------

    @property
    def offset(self) -> int:
        return len(self.code)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"duplicate label {name!r}")
        self.labels[name] = len(self.code)

    def _emit(self, *values: int) -> None:
        self.code.extend(values)

    def _emit_bytes(self, data: bytes) -> None:
        self.code.extend(data)

    def _rel32_to(self, label: str) -> None:
        self._rel32.append((len(self.code), label))
        self.code.extend(b"\x00\x00\x00\x00")

    def _abs32_to(self, symbol: str) -> None:
        self._abs32.append((len(self.code), symbol))
        self.code.extend(b"\x00\x00\x00\x00")

    def finalize(self, image_base: int, code_rva: int,
                 symbols: dict[str, int]) -> bytes:
        """Patch every relocation and return the finished code bytes.

        ``symbols`` maps a symbol name to its RVA. Code labels are resolved
        from this assembler's own label table, so a label and an external
        symbol may not share a name.
        """
        out = bytearray(self.code)
        for site, label in self._rel32:
            if label not in self.labels:
                raise KeyError(f"undefined code label {label!r}")
            delta = self.labels[label] - (site + 4)
            out[site:site + 4] = struct.pack("<i", delta)
        for site, symbol in self._abs32:
            if symbol not in symbols:
                raise KeyError(f"undefined data symbol {symbol!r}")
            out[site:site + 4] = struct.pack("<I", image_base + symbols[symbol])
        _ = code_rva  # kept in the signature: callers place code by RVA
        return bytes(out)

    # -- stack / frame -----------------------------------------------------

    def push(self, reg: int) -> None:
        self._emit(0x50 + reg)

    def pop(self, reg: int) -> None:
        self._emit(0x58 + reg)

    def push_imm32(self, value: int) -> None:
        self._emit(0x68)
        self._emit_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def push_abs(self, symbol: str) -> None:
        """push imm32, where the immediate is a symbol's virtual address."""
        self._emit(0x68)
        self._abs32_to(symbol)

    def enter_frame(self, locals_bytes: int = 0) -> None:
        self.push(EBP)
        self.mov_reg_reg(EBP, ESP)
        if locals_bytes:
            self.sub_reg_imm32(ESP, locals_bytes)

    def leave(self) -> None:
        self._emit(0xC9)

    def ret(self) -> None:
        self._emit(0xC3)

    def ret_imm16(self, value: int) -> None:
        self._emit(0xC2)
        self._emit_bytes(struct.pack("<H", value))

    def int3(self, count: int = 1) -> None:
        """Inter-function padding, matching the MSVC 7.x linker's 0xCC."""
        self._emit(*([0xCC] * count))

    # -- moves -------------------------------------------------------------

    def mov_reg_reg(self, dst: int, src: int) -> None:
        self._emit(0x89, _modrm(3, src, dst))

    def mov_reg_imm32(self, reg: int, value: int) -> None:
        self._emit(0xB8 + reg)
        self._emit_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def mov_reg_abs_addr(self, reg: int, symbol: str) -> None:
        """mov reg, <address of symbol> (the address itself, not its content)."""
        self._emit(0xB8 + reg)
        self._abs32_to(symbol)

    def mov_reg_local(self, reg: int, disp: int) -> None:
        self._emit(0x8B)
        self._emit_bytes(_mem_ebp(reg, disp))

    def mov_local_reg(self, disp: int, reg: int) -> None:
        self._emit(0x89)
        self._emit_bytes(_mem_ebp(reg, disp))

    def mov_local_imm32(self, disp: int, value: int) -> None:
        self._emit(0xC7)
        self._emit_bytes(_mem_ebp(0, disp))
        self._emit_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def mov_reg_mem(self, dst: int, base: int, disp: int = 0) -> None:
        self._emit(0x8B)
        self._emit_bytes(_mem_base(dst, base, disp))

    def mov_mem_reg(self, base: int, disp: int, src: int) -> None:
        self._emit(0x89)
        self._emit_bytes(_mem_base(src, base, disp))

    def mov_reg_global(self, reg: int, symbol: str) -> None:
        """mov reg, dword [<symbol>] -- absolute, mod=00 rm=101."""
        self._emit(0x8B, _modrm(0, reg, 5))
        self._abs32_to(symbol)

    def mov_global_reg(self, symbol: str, src: int) -> None:
        self._emit(0x89, _modrm(0, src, 5))
        self._abs32_to(symbol)

    def movzx_reg_byte_mem(self, dst: int, base: int, disp: int = 0) -> None:
        self._emit(0x0F, 0xB6)
        self._emit_bytes(_mem_base(dst, base, disp))

    def mov_byte_reg_mem(self, dst8: int, base: int, disp: int = 0) -> None:
        """mov r8, byte [base+disp]."""
        self._emit(0x8A)
        self._emit_bytes(_mem_base(dst8, base, disp))

    # -- arithmetic / logic ------------------------------------------------

    def _alu_reg_reg(self, opcode: int, dst: int, src: int) -> None:
        self._emit(opcode, _modrm(3, src, dst))

    def add_reg_reg(self, dst: int, src: int) -> None:
        self._alu_reg_reg(0x01, dst, src)

    def sub_reg_reg(self, dst: int, src: int) -> None:
        self._alu_reg_reg(0x29, dst, src)

    def xor_reg_reg(self, dst: int, src: int) -> None:
        self._alu_reg_reg(0x31, dst, src)

    def or_reg_reg(self, dst: int, src: int) -> None:
        self._alu_reg_reg(0x09, dst, src)

    def and_reg_reg(self, dst: int, src: int) -> None:
        self._alu_reg_reg(0x21, dst, src)

    def cmp_reg_reg(self, left: int, right: int) -> None:
        self._alu_reg_reg(0x39, left, right)

    def test_reg_reg(self, left: int, right: int) -> None:
        self._alu_reg_reg(0x85, left, right)

    def test_byte_reg(self, left8: int, right8: int) -> None:
        self._emit(0x84, _modrm(3, right8, left8))

    def cmp_byte_reg_imm8(self, reg8: int, value: int) -> None:
        self._emit(0x80, _modrm(3, 7, reg8), value & 0xFF)

    def _alu_reg_imm32(self, ext: int, reg: int, value: int) -> None:
        # 81 /ext id -- the imm32 form is used unconditionally so that an
        # immediate's encoded width never depends on its value.
        self._emit(0x81, _modrm(3, ext, reg))
        self._emit_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def add_reg_imm32(self, reg: int, value: int) -> None:
        self._alu_reg_imm32(0, reg, value)

    def or_reg_imm32(self, reg: int, value: int) -> None:
        self._alu_reg_imm32(1, reg, value)

    def and_reg_imm32(self, reg: int, value: int) -> None:
        self._alu_reg_imm32(4, reg, value)

    def sub_reg_imm32(self, reg: int, value: int) -> None:
        self._alu_reg_imm32(5, reg, value)

    def xor_reg_imm32(self, reg: int, value: int) -> None:
        self._alu_reg_imm32(6, reg, value)

    def cmp_reg_imm32(self, reg: int, value: int) -> None:
        self._alu_reg_imm32(7, reg, value)

    def test_reg_imm32(self, reg: int, value: int) -> None:
        # F7 /0 id (the A9 short form for eax is deliberately not used, so the
        # encoding does not change when the register does).
        self._emit(0xF7, _modrm(3, 0, reg))
        self._emit_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def cmp_local_imm32(self, disp: int, value: int) -> None:
        self._emit(0x81)
        self._emit_bytes(_mem_ebp(7, disp))
        self._emit_bytes(struct.pack("<I", value & 0xFFFFFFFF))

    def cmp_reg_local(self, reg: int, disp: int) -> None:
        self._emit(0x3B)
        self._emit_bytes(_mem_ebp(reg, disp))

    def inc_local(self, disp: int) -> None:
        self._emit(0xFF)
        self._emit_bytes(_mem_ebp(0, disp))

    def inc_reg(self, reg: int) -> None:
        self._emit(0x40 + reg)

    def dec_reg(self, reg: int) -> None:
        self._emit(0x48 + reg)

    def shl_reg_imm8(self, reg: int, count: int) -> None:
        self._emit(0xC1, _modrm(3, 4, reg), count & 0xFF)

    def shr_reg_imm8(self, reg: int, count: int) -> None:
        self._emit(0xC1, _modrm(3, 5, reg), count & 0xFF)

    def imul_reg_reg(self, dst: int, src: int) -> None:
        self._emit(0x0F, 0xAF, _modrm(3, dst, src))

    def div_reg(self, reg: int) -> None:
        """Unsigned edx:eax / reg -> eax quotient, edx remainder."""
        self._emit(0xF7, _modrm(3, 6, reg))

    def cdq(self) -> None:
        self._emit(0x99)

    def or_mem_reg(self, base: int, disp: int, src: int) -> None:
        self._emit(0x09)
        self._emit_bytes(_mem_base(src, base, disp))

    # -- control flow ------------------------------------------------------

    def jmp(self, label: str) -> None:
        self._emit(0xE9)
        self._rel32_to(label)

    def jcc(self, condition: str, label: str) -> None:
        try:
            code = CONDITION_CODES[condition]
        except KeyError as exc:
            raise ValueError(f"unknown condition {condition!r}") from exc
        self._emit(0x0F, 0x80 + code)
        self._rel32_to(label)

    def call(self, label: str) -> None:
        self._emit(0xE8)
        self._rel32_to(label)

    def call_import(self, symbol: str) -> None:
        """call dword [<IAT slot>] -- FF /2 with mod=00 rm=101 (absolute)."""
        self._emit(0xFF, _modrm(0, 2, 5))
        self._abs32_to(symbol)

    def call_local(self, disp: int) -> None:
        """call dword [ebp+disp] -- an indirect call through a stack slot."""
        self._emit(0xFF)
        self._emit_bytes(_mem_ebp(2, disp))
