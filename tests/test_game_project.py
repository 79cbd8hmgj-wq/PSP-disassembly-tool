from __future__ import annotations

import io
import json
import struct

import pycdlib
import pytest

import pspdisasm.game_project as game_project
from pspdisasm import generate_game_project
from pspdisasm.disc import GameDiscManifest, GameModuleRecord
from pspdisasm.errors import DisassemblyError
from pspdisasm.linker import ModuleAnalysisInput
from pspdisasm.model import ModuleLinkAnalysis
from pspdisasm.resource_containers import ContainerEntry, ContainerInspection
from tests.fixtures import build_allegrex_elf32, build_psp_container_header


SFO_HEADER = struct.Struct("<4sIIII")
SFO_ENTRY = struct.Struct("<HHIII")
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"


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


def _build_game_iso(
    path,
    *,
    eboot: bytes,
    modules: dict[str, bytes] | None = None,
    resources: dict[str, bytes] | None = None,
) -> None:
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
    for logical_path, payload in sorted((resources or {}).items()):
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


def test_generate_game_project_links_all_successfully_analyzed_modules(tmp_path, monkeypatch):
    image = tmp_path / "linked.iso"
    output = tmp_path / "linked_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        modules={
            "PSP_GAME/USRDIR/SECOND.PRX": build_allegrex_elf32(),
        },
    )

    captured: list[list[ModuleAnalysisInput]] = []

    def record_links(units, database=None):
        materialized = list(units)
        captured.append(materialized)
        return ModuleLinkAnalysis(modules=[unit.model.source_name for unit in materialized])

    monkeypatch.setattr(game_project, "link_modules", record_links)

    result = generate_game_project(image, output)

    assert result.analyzed_count == 2
    assert len(captured) == 1
    assert len(captured[0]) == 2
    assert all(isinstance(unit, ModuleAnalysisInput) for unit in captured[0])
    sources = [unit.model.source_name for unit in captured[0]]
    assert sources[0].endswith("modules/PSP_GAME/SYSDIR/EBOOT.BIN")
    assert sources[1].endswith("modules/PSP_GAME/USRDIR/SECOND.PRX")


def test_generate_game_project_isolates_secondary_disassembly_failure(tmp_path, monkeypatch):
    image = tmp_path / "failure.iso"
    output = tmp_path / "failure_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        modules={
            "PSP_GAME/USRDIR/BROKEN.PRX": build_allegrex_elf32(),
        },
    )

    original_disassemble = game_project.disassemble_file

    def fail_secondary(path):
        if str(path).endswith("BROKEN.PRX"):
            raise DisassemblyError("synthetic failure")
        return original_disassemble(path)

    monkeypatch.setattr(game_project, "disassemble_file", fail_secondary)

    result = generate_game_project(image, output)

    assert result.analyzed_count == 1
    assert result.failed_count == 1
    assert (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").exists()

    analysis = json.loads((output / "metadata/game_analysis.json").read_text(encoding="utf-8"))
    modules = {record["path"]: record for record in analysis["modules"]}
    broken = modules["PSP_GAME/USRDIR/BROKEN.PRX"]
    assert broken["status"] == "failed"
    assert broken["project_path"] is None
    assert any("synthetic failure" in warning for warning in broken["warnings"])


def test_generate_game_project_rejects_unsafe_mirrored_project_path(tmp_path, monkeypatch):
    output = tmp_path / "unsafe_decomp"
    extracted = output / "modules" / "safe.bin"
    extracted.parent.mkdir(parents=True)
    payload = build_allegrex_elf32()
    extracted.write_bytes(payload)

    manifest = GameDiscManifest(
        source_name="synthetic.iso",
        image_format="iso",
        title="Synthetic PSP Game",
        boot_path="../escape",
        modules=[
            GameModuleRecord(
                path="../escape",
                size=len(payload),
                executable_kind="elf",
                output_path="modules/safe.bin",
                is_boot=True,
            )
        ],
    )
    monkeypatch.setattr(game_project, "scan_game_disc", lambda source, output_dir: manifest)

    with pytest.raises(ValueError, match="Unsafe game project path"):
        generate_game_project("synthetic.iso", output)


def test_generate_game_project_analyzes_whole_disc_resources(tmp_path):
    image = tmp_path / "resources.iso"
    output = tmp_path / "game_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        resources={
            "PSP_GAME/USRDIR/TEXTURE.PNG": PNG,
            "PSP_GAME/USRDIR/DATA.BIN": b"opaque proprietary payload",
        },
    )

    result = generate_game_project(image, output)

    assert result.analyzed_count == 1
    assert result.resource_count == 2
    assert result.known_resource_count == 1
    assert result.unknown_resource_count == 1
    assert result.embedded_resource_count == 0
    assert result.container_candidate_count == 1
    assert result.container_inspection_count == 0
    assert result.container_entry_count == 0
    assert result.resources_path == output / "metadata" / "game_resources.json"
    assert result.containers_path == output / "metadata" / "container_candidates.json"
    assert (output / "metadata/game_resources.json").exists()
    assert (output / "metadata/embedded_resources.json").exists()
    assert (output / "metadata/container_candidates.json").exists()
    assert (output / "metadata/container_inspections.json").exists()
    assert (output / "reports/game_resources.csv").exists()
    assert (output / "reports/container_candidates.csv").exists()
    assert (output / "reports/container_entries.csv").exists()
    assert (output / "resources/files/PSP_GAME/USRDIR/TEXTURE.PNG").read_bytes() == PNG
    assert (output / "resources/files/PSP_GAME/USRDIR/DATA.BIN").read_bytes() == b"opaque proprietary payload"


class _PackParser:
    name = "synthetic-pack"

    def probe(self, prefix: bytes, path: str) -> float:
        return 0.99 if prefix.startswith(b"PACK") else 0.0

    def inspect(self, path):
        return ContainerInspection(
            parser_name=self.name,
            format_name="synthetic_pack",
            confidence=0.99,
            entries=[ContainerEntry(path="textures/icon.png", offset=4, size=len(PNG))],
        )


def test_generate_game_project_forwards_custom_container_parsers(tmp_path):
    image = tmp_path / "containers.iso"
    output = tmp_path / "container_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        resources={
            "PSP_GAME/USRDIR/DATA.DAT": b"PACK" + PNG,
        },
    )

    result = generate_game_project(
        image,
        output,
        container_parsers=[_PackParser()],
    )

    assert result.container_candidate_count == 1
    assert result.container_inspection_count == 1
    assert result.container_entry_count == 1
    assert (
        output
        / "resources/containers/PSP_GAME/USRDIR/DATA.DAT/textures/icon.png"
    ).read_bytes() == PNG
