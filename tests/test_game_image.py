from __future__ import annotations

import struct
from pathlib import Path

from pspdisasm.game_image import analyze_game_image


SECTOR = 2048


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


def _build_psp_iso() -> bytes:
    sectors = [bytearray(SECTOR) for _ in range(28)]

    root_extent = 20
    game_extent = 21
    sysdir_extent = 22
    eboot_extent = 23
    eboot = b"~PSP" + b"\x00" * 60

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
    sectors[game_extent][:] = _directory(
        [
            _record(game_extent, SECTOR, b"\x00", directory=True),
            _record(root_extent, SECTOR, b"\x01", directory=True),
            _record(sysdir_extent, SECTOR, b"SYSDIR", directory=True),
        ]
    )
    sectors[sysdir_extent][:] = _directory(
        [
            _record(sysdir_extent, SECTOR, b"\x00", directory=True),
            _record(game_extent, SECTOR, b"\x01", directory=True),
            _record(eboot_extent, len(eboot), b"EBOOT.BIN;1", directory=False),
        ]
    )
    sectors[eboot_extent][: len(eboot)] = eboot
    return b"".join(sectors)


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
