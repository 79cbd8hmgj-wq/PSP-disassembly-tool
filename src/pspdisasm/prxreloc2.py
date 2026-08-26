from __future__ import annotations

from dataclasses import dataclass

from .errors import ParseError
from .model import ElfImage, ProgramHeader, Relocation


PT_LOAD = 1
PT_PRXRELOC2 = 0x700000A1
MAX_DECODED_RELOCATIONS = 1_000_000

_RELOC_NAMES = {
    0: "R_MIPS_NONE",
    1: "R_MIPS_16",
    2: "R_MIPS_32",
    4: "R_MIPS_26",
    5: "R_MIPS_HI16",
    6: "R_MIPS_LO16",
    13: "R_MIPS_X_HI16",
    14: "R_MIPS_X_J26",
    15: "R_MIPS_X_JAL26",
}

# Expand this mapping only after each compact operation has a behavioral test.
_COMPACT_TYPE_MAP = {2: 2}


@dataclass(slots=True)
class _StreamReader:
    data: bytes
    start: int
    end: int
    pos: int

    @classmethod
    def bounded(cls, data: bytes, start: int, size: int) -> _StreamReader:
        if start < 0 or size < 0 or start + size > len(data):
            raise ParseError("PT_PRXRELOC2 segment extends beyond the input")
        return cls(data=data, start=start, end=start + size, pos=start)

    def remaining(self) -> int:
        return self.end - self.pos

    def _require(self, size: int, what: str) -> None:
        if size < 0 or self.pos + size > self.end:
            raise ParseError(f"truncated PT_PRXRELOC2 {what}")

    def read_u8(self, what: str) -> int:
        self._require(1, what)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_u16(self, what: str) -> int:
        self._require(2, what)
        value = int.from_bytes(self.data[self.pos : self.pos + 2], "little")
        self.pos += 2
        return value

    def read_u32(self, what: str) -> int:
        self._require(4, what)
        value = int.from_bytes(self.data[self.pos : self.pos + 4], "little")
        self.pos += 4
        return value

    def read_table(self, what: str) -> bytes:
        self._require(1, f"{what} table")
        size = self.data[self.pos]
        if size < 1:
            raise ParseError(f"invalid PT_PRXRELOC2 {what} table size 0")
        self._require(size, f"{what} table")
        table = self.data[self.pos : self.pos + size]
        self.pos += size
        return table


def _segment(elf: ElfImage, index: int, role: str) -> ProgramHeader:
    if index < 0 or index >= len(elf.program_headers):
        raise ParseError(f"PT_PRXRELOC2 {role} segment index {index} is out of range")
    segment = elf.program_headers[index]
    if segment.type != PT_LOAD:
        raise ParseError(f"PT_PRXRELOC2 {role} segment {index} is not PT_LOAD")
    return segment


def _lookup(table: bytes, index: int, what: str) -> int:
    if index < 0 or index >= len(table):
        raise ParseError(
            f"PT_PRXRELOC2 {what} table index {index} is out of range for size {len(table)}"
        )
    return table[index]


def _mask(bits: int) -> int:
    return (1 << bits) - 1 if bits else 0


def _signed_compact_delta(command: int, shift: int) -> int:
    signed = command - 0x10000 if command & 0x8000 else command
    return signed >> shift


def _signed_extended_delta(command: int, shift: int, low_half: int) -> int:
    high = _signed_compact_delta(command, shift)
    return (high << 16) | low_half


def decode_prxreloc2(
    data: bytes,
    elf: ElfImage,
    relocation_segment_index: int,
) -> list[Relocation]:
    if elf.endianness != "little":
        raise ParseError("PT_PRXRELOC2 decoding requires a little-endian ELF")
    if relocation_segment_index < 0 or relocation_segment_index >= len(elf.program_headers):
        raise ParseError(
            f"PT_PRXRELOC2 program-header index {relocation_segment_index} is out of range"
        )

    relocation_segment = elf.program_headers[relocation_segment_index]
    if relocation_segment.type != PT_PRXRELOC2:
        raise ParseError(
            f"program header {relocation_segment_index} is not PT_PRXRELOC2"
        )

    reader = _StreamReader.bounded(
        data,
        relocation_segment.offset,
        relocation_segment.filesz,
    )
    reader._require(4, "header")
    reader.read_u8("header reserved byte 0")
    reader.read_u8("header reserved byte 1")
    flag_bits = reader.read_u8("flag-bit count")
    type_bits = reader.read_u8("type-bit count")

    seg_bits = 1
    while (1 << seg_bits) < relocation_segment_index:
        seg_bits += 1

    if flag_bits + seg_bits + type_bits > 16:
        raise ParseError(
            "PT_PRXRELOC2 command bit widths exceed 16 bits: "
            f"flag={flag_bits}, segment={seg_bits}, type={type_bits}"
        )

    flag_table = reader.read_table("flag")
    type_table = reader.read_table("type")

    flag_mask = _mask(flag_bits)
    segment_mask = _mask(seg_bits)
    type_mask = _mask(type_bits)
    type_shift = flag_bits + seg_bits
    payload_shift = type_shift + type_bits

    source_segment_index = 0
    relocation_base = 0
    relocations: list[Relocation] = []

    while reader.pos < reader.end:
        command_stream_offset = reader.pos - relocation_segment.offset
        command = reader.read_u16("command")

        flag_index = command & flag_mask
        segment_index = (command >> flag_bits) & segment_mask
        type_index = (command >> type_shift) & type_mask
        flag = _lookup(flag_table, flag_index, "flag")
        compact_type = _lookup(type_table, type_index, "type")

        if (flag & 0x01) == 0:
            source_segment_index = segment_index
            offset_mode = flag & 0x06
            if offset_mode == 0x00:
                relocation_base = command >> (flag_bits + seg_bits)
            elif offset_mode == 0x04:
                relocation_base = reader.read_u32("absolute state base")
            else:
                raise ParseError(
                    f"unsupported PT_PRXRELOC2 state offset mode 0x{offset_mode:02X}"
                )
            continue

        normalized_type = _COMPACT_TYPE_MAP.get(compact_type)
        if normalized_type is None:
            raise ParseError(
                f"unsupported PT_PRXRELOC2 compact relocation type {compact_type}"
            )

        source_segment = _segment(elf, source_segment_index, "source")
        _segment(elf, segment_index, "target")

        offset_mode = flag & 0x06
        if offset_mode == 0x00:
            relocation_base += _signed_compact_delta(command, payload_shift)
        elif offset_mode == 0x02:
            low_half = reader.read_u16("extended relocation delta")
            relocation_base += _signed_extended_delta(command, payload_shift, low_half)
        elif offset_mode == 0x04:
            relocation_base = reader.read_u32("absolute relocation offset")
        else:
            raise ParseError(
                f"unsupported PT_PRXRELOC2 relocation offset mode 0x{offset_mode:02X}"
            )

        if relocation_base < 0 or relocation_base + 4 > source_segment.memsz:
            raise ParseError(
                f"PT_PRXRELOC2 source offset 0x{relocation_base:X} cannot address a 32-bit word "
                f"inside PT_LOAD segment {source_segment_index} (memsz=0x{source_segment.memsz:X})"
            )

        lo16_mode = flag & 0x38
        if lo16_mode != 0x00:
            raise ParseError(
                f"unsupported PT_PRXRELOC2 lo16 mode 0x{lo16_mode:02X}"
            )

        info = normalized_type | (source_segment_index << 8) | (segment_index << 16)
        relocations.append(
            Relocation(
                section=f"PT_PRXRELOC2[{relocation_segment_index}]",
                offset=relocation_base,
                info=info,
                type=normalized_type,
                type_name=_RELOC_NAMES[normalized_type],
                symbol_index=info >> 8,
                target_section_index=None,
                source="program_header_rel2",
                source_segment_index=source_segment_index,
                target_segment_index=segment_index,
                stream_offset=command_stream_offset,
                addend=0,
                encoding_flags=flag,
            )
        )
        if len(relocations) > MAX_DECODED_RELOCATIONS:
            raise ParseError(
                f"PT_PRXRELOC2 decoded relocation count exceeds {MAX_DECODED_RELOCATIONS}"
            )

    return relocations
