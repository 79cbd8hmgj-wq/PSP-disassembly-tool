from __future__ import annotations

import pytest

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
    stream = bytes.fromhex(
        "00 00 02 01"
        "03 00 01"
        "02 02"
        "01 00"
        "4E 00"
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
    stream = bytes.fromhex("00 00 02 01" "03 00 03" "02 02" "01 00" "0E 00 04 00")
    data, elf = _reloc2_elf(stream)
    relocations = decode_prxreloc2(data, elf, 2)
    assert [reloc.offset for reloc in relocations] == [4]
    assert relocations[0].encoding_flags == 0x03


def test_decode_prxreloc2_extended_negative_delta():
    stream = bytes.fromhex("00 00 02 01" "03 00 03" "02 02" "41 00" "FE FF FC FF")
    data, elf = _reloc2_elf(stream)
    relocations = decode_prxreloc2(data, elf, 2)
    assert [reloc.offset for reloc in relocations] == [4]


def test_decode_prxreloc2_absolute_state_base():
    stream = bytes.fromhex(
        "00 00 02 01" "03 04 01" "02 02" "01 00 08 00 00 00" "4E 00"
    )
    data, elf = _reloc2_elf(stream)
    relocations = decode_prxreloc2(data, elf, 2)
    assert [reloc.offset for reloc in relocations] == [12]


def test_decode_prxreloc2_absolute_relocation_offset():
    stream = bytes.fromhex(
        "00 00 02 01" "03 00 05" "02 02" "01 00" "0E 00 0C 00 00 00"
    )
    data, elf = _reloc2_elf(stream)
    relocations = decode_prxreloc2(data, elf, 2)
    assert [reloc.offset for reloc in relocations] == [12]
    assert relocations[0].encoding_flags == 0x05


@pytest.mark.parametrize(
    ("compact_type", "normalized_type", "type_name"),
    [
        (0, 0, "R_MIPS_NONE"),
        (1, 1, "R_MIPS_16"),
        (2, 2, "R_MIPS_32"),
        (3, 4, "R_MIPS_26"),
        (4, 5, "R_MIPS_HI16"),
        (5, 6, "R_MIPS_LO16"),
        (6, 14, "R_MIPS_X_J26"),
        (7, 15, "R_MIPS_X_JAL26"),
    ],
)
def test_decode_prxreloc2_maps_supported_compact_types(
    compact_type: int,
    normalized_type: int,
    type_name: str,
):
    stream = bytes.fromhex("00 00 02 01" "03 00 01") + bytes(
        [2, compact_type]
    ) + bytes.fromhex("01 00 4E 00")
    data, elf = _reloc2_elf(stream)

    relocations = decode_prxreloc2(data, elf, 2)

    assert len(relocations) == 1
    assert relocations[0].type == normalized_type
    assert relocations[0].type_name == type_name


def test_decode_prxreloc2_hi16_explicit_signed_low_half():
    stream = bytes.fromhex(
        "00 00 02 01"
        "03 00 11"     # relocation flag 0x11 => explicit signed low-half follows
        "02 04"        # compact type 4 => R_MIPS_HI16 at type index 1
        "01 00"
        "4E 00 FC FF"  # compact +4 source delta, explicit low half -4
    )
    data, elf = _reloc2_elf(stream)

    relocations = decode_prxreloc2(data, elf, 2)

    assert len(relocations) == 1
    assert relocations[0].type == 5
    assert relocations[0].type_name == "R_MIPS_HI16"
    assert relocations[0].addend == -4
    assert relocations[0].encoding_flags == 0x11
