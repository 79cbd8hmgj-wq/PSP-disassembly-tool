from __future__ import annotations

from pspdisasm.model import ElfHeader, ElfImage, ProgramHeader, Relocation
from pspdisasm.prxreloc2 import decode_prxreloc2


PT_LOAD = 1
PT_PRXRELOC2 = 0x700000A1


def _reloc2_elf(stream: bytes) -> tuple[bytes, ElfImage]:
    reloc_offset = 0x300
    blob = bytearray(reloc_offset + len(stream))
    blob[reloc_offset:] = stream
    header = ElfHeader(
        file_type=0xFFA0,
        machine=8,
        version=1,
        entry=0,
        phoff=0,
        shoff=0,
        flags=0,
        ehsize=0x34,
        phentsize=0x20,
        phnum=3,
        shentsize=0x28,
        shnum=0,
        shstrndx=0,
    )
    program_headers = [
        ProgramHeader(0, PT_LOAD, 0x100, 0, 0, 0x20, 0x20, 5, 0x10),
        ProgramHeader(1, PT_LOAD, 0x200, 0x100, 0x100, 0x20, 0x20, 6, 0x10),
        ProgramHeader(2, PT_PRXRELOC2, reloc_offset, 0, 0, len(stream), len(stream), 4, 4),
    ]
    return bytes(blob), ElfImage(header, "little", program_headers, [], bytes(blob))


def test_relocation_keeps_legacy_constructor_and_adds_optional_prxreloc2_provenance():
    legacy = Relocation(
        section=".rel.text",
        offset=4,
        info=2,
        type=2,
        type_name="R_MIPS_32",
        symbol_index=0,
        target_section_index=1,
    )

    assert legacy.source_segment_index is None
    assert legacy.target_segment_index is None
    assert legacy.stream_offset is None
    assert legacy.addend is None
    assert legacy.encoding_flags is None


def test_decode_prxreloc2_minimal_r_mips_32_stream():
    # rel segment index 2 => seg_bits=1.  The flag table indexes 1=state, 2=reloc;
    # the type table indexes 1=compact type 2 (R_MIPS_32).
    stream = bytes.fromhex(
        "00 00 02 01"  # header: flag_bits=2, type_bits=1
        "03 00 01"     # flag table: size=3, state=0, relocation=1
        "02 02"        # type table: size=2, compact R_MIPS_32 at index 1
        "01 00"        # state: source segment 0, base offset 0
        "4E 00"        # reloc: target segment 1, type index 1, +4 byte delta
    )
    data, elf = _reloc2_elf(stream)

    relocations = decode_prxreloc2(data, elf, 2)

    assert len(relocations) == 1
    reloc = relocations[0]
    assert reloc.section == "PT_PRXRELOC2[2]"
    assert reloc.offset == 4
    assert reloc.type == 2
    assert reloc.type_name == "R_MIPS_32"
    assert reloc.source == "program_header_rel2"
    assert reloc.source_segment_index == 0
    assert reloc.target_segment_index == 1
    assert reloc.stream_offset == 11
    assert reloc.encoding_flags == 1
    assert reloc.info == (2 | (0 << 8) | (1 << 16))


def test_decode_prxreloc2_extended_positive_delta():
    stream = bytes.fromhex(
        "00 00 02 01"
        "03 00 03"     # relocation flag 0x03 => extended signed delta
        "02 02"
        "01 00"        # base = 0
        "0E 00 04 00"  # high delta = 0, low u16 = 4
    )
    data, elf = _reloc2_elf(stream)

    relocations = decode_prxreloc2(data, elf, 2)

    assert [reloc.offset for reloc in relocations] == [4]
    assert relocations[0].encoding_flags == 0x03


def test_decode_prxreloc2_extended_negative_delta():
    stream = bytes.fromhex(
        "00 00 02 01"
        "03 00 03"
        "02 02"
        "41 00"        # compact state command: base = 8
        "FE FF FC FF"  # signed high half -1 + low half 0xFFFC => delta -4
    )
    data, elf = _reloc2_elf(stream)

    relocations = decode_prxreloc2(data, elf, 2)

    assert [reloc.offset for reloc in relocations] == [4]
