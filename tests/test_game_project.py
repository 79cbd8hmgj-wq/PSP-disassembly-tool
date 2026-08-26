from __future__ import annotations

import io
import json
import struct

import pycdlib

from pspdisasm.game_project import generate_game_project
from tests.fixtures import build_allegrex_elf32, build_psp_container_header


SFO_HEADER = struct.Struct("<4sIIII")
SFO_ENTRY = struct.Struct("<HHIII")


def _build_sfo(values: dict[str, object]) -> bytes:
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

    key_table_offset = SFO_HEADER.size + SFO_ENTRY.size * len(entries)
    data_table_offset = key_table_offset + len(keys)
    header = SFO_HEADER.pack(
        b"\x00PSF",
        0x00000101,
        key_table_offset,
        data_table_offset,
        len(entries),
    )
    index = b"".join(SFO_ENTRY.pack(*entry) for entry in entries)
    return header + index + keys + data


def _build_game_iso(path, *, eboot: bytes, modules: dict[str, bytes] | None = None) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_directory(iso_path="/PSP_GAME")
    iso.add_directory(iso_path="/PSP_GAME/SYSDIR")
    iso.add_directory(iso_path="/PSP_GAME/USRDIR")

    files: list[tuple[str, bytes]] = [
        (
            "/PSP_GAME/PARAM.SFO;1",
            _build_sfo(
                {
                    "TITLE": "Synthetic PSP Game",
                    "DISC_ID": "ULUS12345",
                    "DISC_VERSION": "1.00",
                    "PSP_SYSTEM_VER": "6.60",
                }
            ),
        ),
        ("/PSP_GAME/SYSDIR/EBOOT.BIN;1", eboot),
    ]
    for logical_path, payload in sorted((modules or {}).items()):
        files.append((f"/{logical_path};1", payload))

    for iso_path, payload in files:
        iso.add_fp(io.BytesIO(payload), len(payload), iso_path=iso_path)
    iso.write(str(path))
    iso.close()


def test_generate_game_project_analyzes_decrypted_boot_and_records_encrypted_module(tmp_path):
    image = tmp_path / "game.iso"
    output = tmp_path / "game_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        modules={
            "PSP_GAME/USRDIR/LOCKED.PRX": build_psp_container_header(),
        },
    )

    result = generate_game_project(image, output)

    assert result.module_count == 2
    assert result.analyzed_count == 1
    assert result.needs_decryption_count == 1
    assert result.failed_count == 0
    assert (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").exists()
    assert not (output / "projects/PSP_GAME/USRDIR/LOCKED.PRX").exists()

    analysis = json.loads((output / "metadata/game_analysis.json").read_text(encoding="utf-8"))
    modules = {record["path"]: record for record in analysis["modules"]}

    boot = modules["PSP_GAME/SYSDIR/EBOOT.BIN"]
    assert boot["status"] == "analyzed"
    assert boot["is_boot"] is True
    assert boot["project_path"] == "projects/PSP_GAME/SYSDIR/EBOOT.BIN"
    assert boot["function_count"] > 0

    locked = modules["PSP_GAME/USRDIR/LOCKED.PRX"]
    assert locked["status"] == "needs_decryption"
    assert locked["project_path"] is None
    assert locked["module_name"] == "GAMEBOOT"
    assert any("decryption" in warning.lower() for warning in locked["warnings"])
