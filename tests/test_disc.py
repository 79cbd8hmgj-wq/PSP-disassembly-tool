import io
import json
import struct

import pycdlib

from pspdisasm.disc import scan_game_disc


SFO_HEADER = struct.Struct("<4sIIII")
SFO_ENTRY = struct.Struct("<HHIII")


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
    key_table_offset = SFO_HEADER.size + SFO_ENTRY.size * len(entries)
    data_table_offset = key_table_offset + len(keys)
    header = SFO_HEADER.pack(b"\x00PSF", 0x00000101, key_table_offset, data_table_offset, len(entries))
    index = b"".join(SFO_ENTRY.pack(*entry) for entry in entries)
    return header + index + keys + data


def build_psp_iso(path, *, eboot: bytes, boot: bytes | None = None) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_directory(iso_path="/PSP_GAME")
    iso.add_directory(iso_path="/PSP_GAME/SYSDIR")
    iso.add_directory(iso_path="/PSP_GAME/USRDIR")

    files = [
        (
            "/PSP_GAME/PARAM.SFO;1",
            build_sfo(
                {
                    "TITLE": "Synthetic PSP Game",
                    "DISC_ID": "ULUS12345",
                    "DISC_VERSION": "1.00",
                    "PSP_SYSTEM_VER": "6.60",
                    "MEMSIZE": 1,
                }
            ),
        ),
        ("/PSP_GAME/SYSDIR/EBOOT.BIN;1", eboot),
        ("/PSP_GAME/USRDIR/PLUGIN.PRX;1", b"~PSP" + b"P" * 60),
        ("/PSP_GAME/USRDIR/TEXTURE.GIM;1", b"MIG.00.1PSP" + b"R" * 32),
    ]
    if boot is not None:
        files.append(("/PSP_GAME/SYSDIR/BOOT.BIN;1", boot))

    for iso_path, payload in files:
        iso.add_fp(io.BytesIO(payload), len(payload), iso_path=iso_path)
    iso.write(str(path))
    iso.close()


def test_scan_game_disc_builds_manifest_and_extracts_executables(tmp_path):
    image = tmp_path / "game.iso"
    output = tmp_path / "project"
    build_psp_iso(image, eboot=b"\x7fELF" + b"E" * 60)

    manifest = scan_game_disc(image, output)

    assert manifest.image_format == "iso"
    assert manifest.title == "Synthetic PSP Game"
    assert manifest.disc_id == "ULUS12345"
    assert manifest.disc_version == "1.00"
    assert manifest.psp_system_version == "6.60"
    assert manifest.boot_path == "PSP_GAME/SYSDIR/EBOOT.BIN"

    paths = [record.path for record in manifest.files]
    assert paths == sorted(paths, key=str.casefold)
    by_path = {record.path: record for record in manifest.files}
    assert by_path["PSP_GAME/SYSDIR/EBOOT.BIN"].classification == "boot"
    assert by_path["PSP_GAME/USRDIR/PLUGIN.PRX"].classification == "module"
    assert by_path["PSP_GAME/USRDIR/TEXTURE.GIM"].classification == "resource"

    modules = {record.path: record for record in manifest.modules}
    assert modules["PSP_GAME/SYSDIR/EBOOT.BIN"].executable_kind == "elf"
    assert modules["PSP_GAME/SYSDIR/EBOOT.BIN"].is_boot is True
    assert modules["PSP_GAME/USRDIR/PLUGIN.PRX"].executable_kind == "psp_container"
    assert modules["PSP_GAME/USRDIR/PLUGIN.PRX"].is_boot is False

    assert (output / "modules" / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN").read_bytes().startswith(b"\x7fELF")
    assert (output / "modules" / "PSP_GAME" / "USRDIR" / "PLUGIN.PRX").read_bytes().startswith(b"~PSP")
    assert not (output / "modules" / "PSP_GAME" / "USRDIR" / "TEXTURE.GIM").exists()

    disc_json = json.loads((output / "metadata" / "disc.json").read_text(encoding="utf-8"))
    sfo_json = json.loads((output / "metadata" / "param_sfo.json").read_text(encoding="utf-8"))
    assert disc_json["boot_path"] == "PSP_GAME/SYSDIR/EBOOT.BIN"
    assert sfo_json["DISC_ID"] == "ULUS12345"


def test_scan_game_disc_falls_back_to_boot_bin_when_eboot_is_not_executable(tmp_path):
    image = tmp_path / "fallback.iso"
    build_psp_iso(image, eboot=b"stub" + b"X" * 60, boot=b"\x7fELF" + b"B" * 60)

    manifest = scan_game_disc(image)

    assert manifest.boot_path == "PSP_GAME/SYSDIR/BOOT.BIN"
    by_path = {record.path: record for record in manifest.files}
    assert by_path["PSP_GAME/SYSDIR/BOOT.BIN"].classification == "boot"
    assert by_path["PSP_GAME/SYSDIR/EBOOT.BIN"].classification == "resource"
