import struct

import pytest

from pspdisasm.errors import ParseError
from pspdisasm.psp_container import parse_psp_container_header


def make_header() -> bytes:
    data = bytearray(0x150)
    data[0:4] = b"~PSP"
    struct.pack_into("<H", data, 0x04, 0x1000)
    struct.pack_into("<H", data, 0x06, 0x0200)
    data[0x08] = 2
    data[0x09] = 1
    data[0x0A:0x0A + 8] = b"TESTMOD\x00"
    data[0x26] = 3
    data[0x27] = 2
    struct.pack_into("<I", data, 0x28, 0x123456)
    struct.pack_into("<I", data, 0x2C, 0x654321)
    struct.pack_into("<I", data, 0x30, 0x80)
    struct.pack_into("<i", data, 0x34, -0x40)
    struct.pack_into("<I", data, 0x38, 0x900)
    struct.pack_into("<4H", data, 0x3C, 0x10, 0x20, 0, 0)
    struct.pack_into("<4I", data, 0x44, 0x08800000, 0x08900000, 0, 0)
    struct.pack_into("<4I", data, 0x54, 0x1000, 0x2000, 0, 0)
    struct.pack_into("<I", data, 0x78, 0x06060010)
    data[0x7C] = 9
    struct.pack_into("<H", data, 0x7E, 0x20)
    struct.pack_into("<I", data, 0xB0, 0x3333)
    struct.pack_into("<I", data, 0xD0, 0xD91610F0)
    return bytes(data)


def test_parses_psp_outer_header():
    header = parse_psp_container_header(make_header())
    assert header.module_attribute == 0x1000
    assert header.compression_attribute == 0x0200
    assert header.module_version == (1, 2)
    assert header.module_name == "TESTMOD"
    assert header.segment_count == 2
    assert header.elf_size == 0x123456
    assert header.psp_size == 0x654321
    assert header.boot_entry == 0x80
    assert header.module_info_offset == -0x40
    assert header.bss_size == 0x900
    assert header.segment_alignments[:2] == [0x10, 0x20]
    assert header.segment_addresses[:2] == [0x08800000, 0x08900000]
    assert header.segment_sizes[:2] == [0x1000, 0x2000]
    assert header.devkit_version == 0x06060010
    assert header.decrypt_mode == 9
    assert header.overlap_size == 0x20
    assert header.compressed_size == 0x3333
    assert header.subtype == 0xD91610F0


def test_rejects_truncated_psp_header():
    with pytest.raises(ParseError, match="0x150"):
        parse_psp_container_header(b"~PSP" + b"\x00" * 20)


def test_rejects_wrong_psp_magic():
    with pytest.raises(ParseError, match="magic"):
        parse_psp_container_header(b"NOPE" + b"\x00" * (0x150 - 4))
