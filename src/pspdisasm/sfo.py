from __future__ import annotations

import struct

from .errors import ParseError


_HEADER = struct.Struct("<4sIIII")
_ENTRY = struct.Struct("<HHIII")
_MAGIC = b"\x00PSF"
_FMT_UTF8 = 0x0204
_FMT_UINT32 = 0x0404


def parse_param_sfo(data: bytes) -> dict[str, object]:
    if len(data) < _HEADER.size:
        raise ParseError("Truncated PSF header")

    magic, _version, key_table_offset, data_table_offset, entry_count = _HEADER.unpack_from(data, 0)
    if magic != _MAGIC:
        raise ParseError("Invalid PSF magic")

    index_start = _HEADER.size
    index_end = index_start + entry_count * _ENTRY.size
    if index_end > len(data):
        raise ParseError("PSF index table exceeds file size")
    if key_table_offset < index_end or key_table_offset > len(data):
        raise ParseError("PSF key table offset is invalid")
    if data_table_offset < key_table_offset or data_table_offset > len(data):
        raise ParseError("PSF data table offset is invalid")

    result: dict[str, object] = {}
    for index in range(entry_count):
        entry_offset = index_start + index * _ENTRY.size
        key_offset, fmt, data_len, data_max_len, data_offset = _ENTRY.unpack_from(data, entry_offset)

        key_start = key_table_offset + key_offset
        if key_start < key_table_offset or key_start >= data_table_offset:
            raise ParseError(f"PSF key offset for entry {index} is invalid")
        key_end = data.find(b"\0", key_start, data_table_offset)
        if key_end < 0:
            raise ParseError(f"PSF key for entry {index} is not NUL terminated")
        try:
            key = data[key_start:key_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ParseError(f"PSF key for entry {index} is not valid UTF-8") from exc
        if not key:
            raise ParseError(f"PSF key for entry {index} is empty")

        if data_len > data_max_len:
            raise ParseError(f"PSF data length exceeds maximum length for key {key}")
        value_start = data_table_offset + data_offset
        value_end = value_start + data_len
        if value_start < data_table_offset or value_end < value_start or value_end > len(data):
            raise ParseError(f"PSF data for key {key} exceeds file size")
        raw_value = data[value_start:value_end]

        if fmt == _FMT_UTF8:
            text = raw_value.split(b"\0", 1)[0]
            try:
                result[key] = text.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ParseError(f"PSF string value for key {key} is not valid UTF-8") from exc
        elif fmt == _FMT_UINT32:
            if len(raw_value) < 4:
                raise ParseError(f"PSF integer value for key {key} is truncated")
            result[key] = struct.unpack_from("<I", raw_value, 0)[0]
        else:
            result[key] = bytes(raw_value)

    return result
