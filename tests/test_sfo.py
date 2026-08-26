import struct

import pytest

from pspdisasm.errors import ParseError
from pspdisasm.sfo import parse_param_sfo


HEADER = struct.Struct("<4sIIII")
ENTRY = struct.Struct("<HHIII")


def build_sfo(values: dict[str, object]) -> bytes:
    keys = bytearray()
    data = bytearray()
    entries: list[tuple[int, int, int, int, int]] = []

    for key, value in values.items():
        key_offset = len(keys)
        keys.extend(key.encode("utf-8") + b"\0")
        while len(data) % 4:
            data.append(0)
        data_offset = len(data)
        if isinstance(value, int):
            fmt = 0x0404
            encoded = struct.pack("<I", value)
        else:
            fmt = 0x0204
            encoded = str(value).encode("utf-8") + b"\0"
        data.extend(encoded)
        entries.append((key_offset, fmt, len(encoded), len(encoded), data_offset))

    key_table_offset = HEADER.size + ENTRY.size * len(entries)
    data_table_offset = key_table_offset + len(keys)
    header = HEADER.pack(b"\x00PSF", 0x00000101, key_table_offset, data_table_offset, len(entries))
    index = b"".join(ENTRY.pack(*entry) for entry in entries)
    return header + index + keys + data


def test_parse_param_sfo_reads_strings_and_integers():
    values = parse_param_sfo(
        build_sfo(
            {
                "TITLE": "Test Game",
                "DISC_ID": "ULUS12345",
                "MEMSIZE": 1,
            }
        )
    )

    assert values["TITLE"] == "Test Game"
    assert values["DISC_ID"] == "ULUS12345"
    assert values["MEMSIZE"] == 1


def test_parse_param_sfo_preserves_unknown_formats_as_bytes():
    image = bytearray(build_sfo({"TITLE": "Test"}))
    fmt_offset = HEADER.size + 2
    struct.pack_into("<H", image, fmt_offset, 0x0004)

    values = parse_param_sfo(bytes(image))

    assert values["TITLE"] == b"Test\0"


def test_parse_param_sfo_rejects_wrong_magic():
    with pytest.raises(ParseError, match="PSF"):
        parse_param_sfo(b"BAD!" + b"\0" * 64)


def test_parse_param_sfo_rejects_out_of_bounds_data_entry():
    image = bytearray(build_sfo({"TITLE": "Test"}))
    data_offset_field = HEADER.size + 12
    struct.pack_into("<I", image, data_offset_field, 0x7FFFFFF0)

    with pytest.raises(ParseError, match="data"):
        parse_param_sfo(bytes(image))
