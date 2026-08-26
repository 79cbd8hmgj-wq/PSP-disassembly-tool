from __future__ import annotations

import csv
import json
from pathlib import Path

import pspdisasm
from pspdisasm.project import generate_project
from tests.fixtures import build_allegrex_elf32


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"
GIM = b"MIG.00.1PSP\x00" + b"\x00" * 20
RODATA_OFFSET = 0x200
RODATA_ADDRESS = 0x08800100


def _elf_with_rodata(payload: bytes) -> bytes:
    assert len(payload) <= 0x20
    data = bytearray(build_allegrex_elf32())
    data[RODATA_OFFSET : RODATA_OFFSET + 0x20] = payload.ljust(0x20, b"\x00")
    return bytes(data)


def test_project_writes_phase6d_metadata_csv_and_safe_extraction(tmp_path: Path):
    source = tmp_path / "asset.elf"
    output = tmp_path / "project"
    source.write_bytes(_elf_with_rodata(PNG))

    generate_project(source, output)

    expected = {
        "metadata/asset_discovery.json",
        "metadata/assets.json",
        "metadata/asset_references.json",
        "reports/assets.csv",
    }
    for relative in expected:
        assert (output / relative).exists(), relative

    complete = json.loads((output / "metadata" / "asset_discovery.json").read_text(encoding="utf-8"))
    assets = json.loads((output / "metadata" / "assets.json").read_text(encoding="utf-8"))
    references = json.loads((output / "metadata" / "asset_references.json").read_text(encoding="utf-8"))
    assert complete["assets"] == assets
    assert complete["references"] == references
    assert assets == [
        {
            "address": RODATA_ADDRESS,
            "confidence": 1.0,
            "evidence": ["png_signature", "png_iend", "bounded_extent"],
            "extractable": True,
            "file_offset": RODATA_OFFSET,
            "format": "png",
            "kind": "image",
            "metadata": {"chunk_count": 1},
            "section": ".rodata",
            "size": len(PNG),
            "suggested_extension": "png",
        }
    ]
    assert any(reference["asset_address"] == RODATA_ADDRESS for reference in references)

    extracted = output / "assets" / "08800100_png.png"
    assert extracted.read_bytes() == PNG

    with (output / "reports" / "assets.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert list(rows[0]) == [
        "address",
        "file_offset",
        "section",
        "format",
        "kind",
        "size",
        "confidence",
        "extractable",
        "reference_count",
        "suggested_extension",
    ]
    assert rows == sorted(rows, key=lambda row: (int(row["address"], 0), row["format"]))
    assert rows[0]["address"] == "0x08800100"
    assert rows[0]["file_offset"] == "0x00000200"
    assert rows[0]["reference_count"] == str(len(references))


def test_recognized_unbounded_asset_is_not_physically_carved(tmp_path: Path):
    source = tmp_path / "gim.elf"
    output = tmp_path / "project"
    source.write_bytes(_elf_with_rodata(GIM))

    generate_project(source, output)

    assets = json.loads((output / "metadata" / "assets.json").read_text(encoding="utf-8"))
    assert len(assets) == 1
    assert assets[0]["format"] == "gim"
    assert assets[0]["extractable"] is False
    assert assets[0]["size"] is None
    assert list((output / "assets").iterdir()) == []


def test_phase6d_is_public_api_at_current_version():
    assert callable(pspdisasm.analyze_assets)
    assert pspdisasm.__version__ == "0.10.0"
