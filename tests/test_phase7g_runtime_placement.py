from __future__ import annotations

import json

import yaml

from pspdisasm import generate_game_project
from tests.fixtures import build_allegrex_elf32, build_prx_elf32
from tests.test_game_project import _build_game_iso


def _module_record(output, path: str) -> dict[str, object]:
    analysis = json.loads((output / "metadata/game_analysis.json").read_text(encoding="utf-8"))
    return {record["path"]: record for record in analysis["modules"]}[path]


def test_game_project_records_fixed_et_exec_placement_without_relocation(tmp_path):
    image = tmp_path / "fixed.iso"
    output = tmp_path / "fixed_decomp"
    _build_game_iso(image, eboot=build_allegrex_elf32())

    generate_game_project(image, output)

    boot = _module_record(output, "PSP_GAME/SYSDIR/EBOOT.BIN")
    assert boot.get("load_address") == 0x08800000
    assert boot.get("placement_kind") == "fixed"
    assert boot.get("placement_confidence") == 1.0
    assert boot.get("runtime_address_claim") is True

    config = yaml.safe_load(
        (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").read_text(encoding="utf-8")
    )
    assert config["segments"][0]["vram"] == 0x08800000


def test_game_project_places_relocatable_boot_at_first_psp_user_allocation(tmp_path):
    image = tmp_path / "relocatable.iso"
    output = tmp_path / "relocatable_decomp"
    _build_game_iso(image, eboot=build_prx_elf32())

    generate_game_project(image, output)

    boot = _module_record(output, "PSP_GAME/SYSDIR/EBOOT.BIN")
    assert boot.get("load_address") == 0x08804000
    assert boot.get("placement_kind") == "boot_inferred"
    assert boot.get("placement_confidence") == 0.95
    assert boot.get("runtime_address_claim") is True
    assert any("0x08804000" in item for item in boot.get("placement_evidence", []))

    config = yaml.safe_load(
        (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").read_text(encoding="utf-8")
    )
    assert config["segments"][0]["vram"] == 0x08804000

    placements = json.loads(
        (output / "metadata/module_placements.json").read_text(encoding="utf-8")
    )
    assert placements == [
        {
            "alignment": 16,
            "image_end": 0x08804120,
            "image_size": 0x120,
            "load_address": 0x08804000,
            "original_image_base": 0,
            "path": "PSP_GAME/SYSDIR/EBOOT.BIN",
            "placement_confidence": 0.95,
            "placement_evidence": [
                "Relocatable boot module uses the PSP low-allocation path; user memory starts at 0x08800000 and the initial 0x4000 bytes are reserved, making 0x08804000 the first default allocation."
            ],
            "placement_kind": "boot_inferred",
            "requires_relocation": True,
            "runtime_address_claim": True,
        }
    ]


def test_secondary_prxs_receive_unique_aligned_analysis_only_placements(tmp_path):
    image = tmp_path / "secondary.iso"
    output = tmp_path / "secondary_decomp"
    _build_game_iso(
        image,
        eboot=build_prx_elf32(),
        modules={
            "PSP_GAME/USRDIR/A.PRX": build_prx_elf32(),
            "PSP_GAME/USRDIR/B.PRX": build_prx_elf32(),
        },
    )

    generate_game_project(image, output)

    boot = _module_record(output, "PSP_GAME/SYSDIR/EBOOT.BIN")
    first = _module_record(output, "PSP_GAME/USRDIR/A.PRX")
    second = _module_record(output, "PSP_GAME/USRDIR/B.PRX")

    assert boot.get("load_address") == 0x08804000
    assert first.get("load_address") == 0x08804120
    assert second.get("load_address") == 0x08804240
    assert first.get("placement_kind") == "analysis"
    assert second.get("placement_kind") == "analysis"
    assert first.get("placement_confidence") == 0.50
    assert second.get("placement_confidence") == 0.50
    assert first.get("runtime_address_claim") is False
    assert second.get("runtime_address_claim") is False
    assert any("not encoded on disc" in item for item in first.get("placement_evidence", []))

    for path, expected in (
        ("PSP_GAME/USRDIR/A.PRX", 0x08804120),
        ("PSP_GAME/USRDIR/B.PRX", 0x08804240),
    ):
        config = yaml.safe_load((output / "projects" / path / "splat.yaml").read_text(encoding="utf-8"))
        assert config["segments"][0]["vram"] == expected
