from __future__ import annotations

import struct
import zlib
from pathlib import Path

from pspdisasm.game_image import (
    analyze_game_image,
    extract_game_executables,
    parse_param_sfo,
    read_game_file,
)


SECTOR = 2048
EBOOT_BYTES = b"~PSP" + b"\x00" * 60


def _both16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _record(extent: int, size: int, name: bytes, *, directory: bool) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:10] = _both32(extent)
    record[10:18] = _both32(size)
    record[18:25] = bytes((126, 8, 26, 9, 0, 0, 0))
    record[25] = 0x02 if directory else 0x00
    record[28:32] = _both16(1)
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def _directory(entries: list[bytes]) -> bytes:
    data = bytearray(SECTOR)
    cursor = 0
    for entry in entries:
        data[cursor : cursor + len(entry)] = entry
        cursor += len(entry)
    return bytes(data)


def _build_psp_iso(param_sfo: bytes | None = None) -> bytes:
    sectors = [bytearray(SECTOR) for _ in range(28)]

    root_extent = 20
    game_extent = 21
    sysdir_extent = 22
    eboot_extent = 23
    sfo_extent = 24

    pvd = sectors[16]
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[80:88] = _both32(len(sectors))
    pvd[128:132] = _both16(SECTOR)
    root_record = _record(root_extent, SECTOR, b"\x00", directory=True)
    pvd[156 : 156 + len(root_record)] = root_record

    terminator = sectors[17]
    terminator[0] = 255
    terminator[1:6] = b"CD001"
    terminator[6] = 1

    sectors[root_extent][:] = _directory(
        [
            _record(root_extent, SECTOR, b"\x00", directory=True),
            _record(root_extent, SECTOR, b"\x01", directory=True),
            _record(game_extent, SECTOR, b"PSP_GAME", directory=True),
        ]
    )
    game_entries = [
        _record(game_extent, SECTOR, b"\x00", directory=True),
        _record(root_extent, SECTOR, b"\x01", directory=True),
        _record(sysdir_extent, SECTOR, b"SYSDIR", directory=True),
    ]
    if param_sfo is not None:
        game_entries.append(_record(sfo_extent, len(param_sfo), b"PARAM.SFO;1", directory=False))
        sectors[sfo_extent][: len(param_sfo)] = param_sfo
    sectors[game_extent][:] = _directory(game_entries)
    sectors[sysdir_extent][:] = _directory(
        [
            _record(sysdir_extent, SECTOR, b"\x00", directory=True),
            _record(game_extent, SECTOR, b"\x01", directory=True),
            _record(eboot_extent, len(EBOOT_BYTES), b"EBOOT.BIN;1", directory=False),
        ]
    )
    sectors[eboot_extent][: len(EBOOT_BYTES)] = EBOOT_BYTES
    return b"".join(sectors)


def _deflate_raw(block: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(block) + compressor.flush()


def _build_cso_v1(iso: bytes) -> bytes:
    assert len(iso) % SECTOR == 0
    blocks = [iso[offset : offset + SECTOR] for offset in range(0, len(iso), SECTOR)]
    header_size = 24
    index_size = 4 * (len(blocks) + 1)
    cursor = header_size + index_size
    indices: list[int] = []
    payloads: list[bytes] = []

    for block in blocks:
        compressed = _deflate_raw(block)
        if len(compressed) >= len(block):
            indices.append(cursor | 0x80000000)
            payload = block
        else:
            indices.append(cursor)
            payload = compressed
        payloads.append(payload)
        cursor += len(payload)
    indices.append(cursor)

    header = struct.pack("<4sIQIBB2s", b"CISO", header_size, len(iso), SECTOR, 1, 0, b"\x00\x00")
    return header + b"".join(struct.pack("<I", value) for value in indices) + b"".join(payloads)


def _build_param_sfo() -> bytes:
    entries = [
        ("DISC_ID", 0x0204, b"ULUS12345\x00"),
        ("TITLE", 0x0204, b"Fixture Game\x00"),
        ("MEMSIZE", 0x0404, struct.pack("<I", 1)),
    ]
    keys = bytearray()
    data = bytearray()
    index = bytearray()
    key_offsets: list[int] = []
    data_offsets: list[int] = []

    for key, _fmt, value in entries:
        key_offsets.append(len(keys))
        keys.extend(key.encode("ascii") + b"\x00")
        while len(data) % 4:
            data.append(0)
        data_offsets.append(len(data))
        data.extend(value)

    key_start = 20 + 16 * len(entries)
    data_start = key_start + len(keys)
    while data_start % 4:
        keys.append(0)
        data_start += 1

    for (key, fmt, value), key_offset, data_offset in zip(entries, key_offsets, data_offsets, strict=True):
        max_len = 4 if fmt == 0x0404 else len(value)
        index.extend(struct.pack("<HHIII", key_offset, fmt, len(value), max_len, data_offset))

    header = struct.pack("<4sIIII", b"\x00PSF", 0x00000101, key_start, data_start, len(entries))
    return header + bytes(index) + bytes(keys) + bytes(data)


def test_analyze_game_image_discovers_psp_boot_executable(tmp_path: Path) -> None:
    image = tmp_path / "game.iso"
    image.write_bytes(_build_psp_iso())

    result = analyze_game_image(image)

    assert result.image_format == "iso"
    assert result.boot_path == "/PSP_GAME/SYSDIR/EBOOT.BIN"
    assert result.file_count == 3
    assert [(entry.path, entry.kind) for entry in result.executables] == [
        ("/PSP_GAME/SYSDIR/EBOOT.BIN", "encrypted_psp_container")
    ]


def test_analyze_game_image_reads_standard_cso_v1_blocks(tmp_path: Path) -> None:
    iso = _build_psp_iso()
    image = tmp_path / "game.cso"
    image.write_bytes(_build_cso_v1(iso))

    result = analyze_game_image(image)

    assert result.image_format == "cso"
    assert result.logical_size == len(iso)
    assert result.boot_path == "/PSP_GAME/SYSDIR/EBOOT.BIN"


def test_parse_param_sfo_decodes_strings_and_integer_values() -> None:
    metadata = parse_param_sfo(_build_param_sfo())

    assert metadata == {
        "DISC_ID": "ULUS12345",
        "MEMSIZE": 1,
        "TITLE": "Fixture Game",
    }


def test_analyze_game_image_reads_param_sfo_metadata(tmp_path: Path) -> None:
    image = tmp_path / "game.iso"
    image.write_bytes(_build_psp_iso(_build_param_sfo()))

    result = analyze_game_image(image)

    assert result.param_sfo["DISC_ID"] == "ULUS12345"
    assert result.param_sfo["TITLE"] == "Fixture Game"
    assert result.param_sfo["MEMSIZE"] == 1


def test_read_and_extract_executable_from_cso_without_full_unpack(tmp_path: Path) -> None:
    image = tmp_path / "game.cso"
    image.write_bytes(_build_cso_v1(_build_psp_iso()))

    assert read_game_file(image, "/PSP_GAME/SYSDIR/EBOOT.BIN") == EBOOT_BYTES

    output = tmp_path / "extracted"
    extracted = extract_game_executables(image, output)

    expected = output / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN"
    assert extracted == [expected]
    assert expected.read_bytes() == EBOOT_BYTES
