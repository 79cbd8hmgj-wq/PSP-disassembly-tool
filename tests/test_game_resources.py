from __future__ import annotations

import csv
import json

import pytest

import pspdisasm.game_resources as game_resources
from pspdisasm.disc import DiscResourceRecord
from pspdisasm.game_resources import analyze_game_resources


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"


def _resource(output, logical_path: str, payload: bytes) -> DiscResourceRecord:
    relative = f"resources/files/{logical_path}"
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return DiscResourceRecord(path=logical_path, size=len(payload), output_path=relative)


def test_analyze_game_resources_classifies_known_and_preserves_unknown_files(tmp_path):
    output = tmp_path / "project"
    records = [
        _resource(output, "PSP_GAME/USRDIR/TEXTURE.PNG", PNG),
        _resource(output, "PSP_GAME/USRDIR/DATA.BIN", b"opaque proprietary payload"),
    ]

    analysis = analyze_game_resources("game.iso", output, records)

    assert [record.path for record in analysis.resources] == [
        "PSP_GAME/USRDIR/DATA.BIN",
        "PSP_GAME/USRDIR/TEXTURE.PNG",
    ]
    by_path = {record.path: record for record in analysis.resources}
    known = by_path["PSP_GAME/USRDIR/TEXTURE.PNG"]
    assert (known.detected_format, known.kind, known.confidence) == ("png", "image", 1.0)
    assert known.extracted_path == "resources/files/PSP_GAME/USRDIR/TEXTURE.PNG"
    assert known.embedded_count == 0

    unknown = by_path["PSP_GAME/USRDIR/DATA.BIN"]
    assert (unknown.detected_format, unknown.kind, unknown.confidence) == ("unknown", "unknown", 0.0)
    assert unknown.evidence == []

    metadata = json.loads((output / "metadata/game_resources.json").read_text(encoding="utf-8"))
    embedded = json.loads((output / "metadata/embedded_resources.json").read_text(encoding="utf-8"))
    assert len(metadata["resources"]) == 2
    assert embedded == []

    with (output / "reports/game_resources.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["path"] for row in rows] == [
        "PSP_GAME/USRDIR/DATA.BIN",
        "PSP_GAME/USRDIR/TEXTURE.PNG",
    ]


def test_analyze_game_resources_discovers_and_extracts_bounded_embedded_resource(tmp_path):
    output = tmp_path / "project"
    payload = b"JUNK" + PNG + b"TAIL"
    records = [_resource(output, "PSP_GAME/USRDIR/DATA.BIN", payload)]

    analysis = analyze_game_resources("game.iso", output, records)

    assert len(analysis.embedded_resources) == 1
    embedded = analysis.embedded_resources[0]
    assert (embedded.parent_path, embedded.file_offset, embedded.format, embedded.kind) == (
        "PSP_GAME/USRDIR/DATA.BIN",
        4,
        "png",
        "image",
    )
    assert embedded.size == len(PNG)
    assert embedded.extracted_path == (
        "resources/embedded/PSP_GAME/USRDIR/DATA.BIN/00000004_png.png"
    )
    assert (output / embedded.extracted_path).read_bytes() == PNG
    assert analysis.resources[0].embedded_count == 1


def test_analyze_game_resources_skips_oversized_embedded_scan_but_keeps_inventory(tmp_path, monkeypatch):
    output = tmp_path / "project"
    monkeypatch.setattr(game_resources, "MAX_EMBEDDED_SCAN_BYTES", 8)
    records = [_resource(output, "PSP_GAME/USRDIR/LARGE.BIN", b"0123456789ABCDEF")]

    analysis = analyze_game_resources("game.iso", output, records)

    assert len(analysis.resources) == 1
    record = analysis.resources[0]
    assert record.detected_format == "unknown"
    assert record.embedded_count == 0
    assert any("embedded scanning skipped" in warning.lower() for warning in record.warnings)
    assert analysis.embedded_resources == []


def test_analyze_game_resources_isolates_malformed_known_signature_as_unknown(tmp_path):
    output = tmp_path / "project"
    malformed = b"RIFF" + (0x1000).to_bytes(4, "little") + b"WAVEfmt " + b"\x00" * 8
    records = [_resource(output, "PSP_GAME/USRDIR/BROKEN.WAV", malformed)]

    analysis = analyze_game_resources("game.iso", output, records)

    assert len(analysis.resources) == 1
    assert analysis.resources[0].detected_format == "unknown"
    assert analysis.embedded_resources == []


def test_analyze_game_resources_rejects_unsafe_extracted_paths(tmp_path):
    output = tmp_path / "project"
    records = [
        DiscResourceRecord(
            path="PSP_GAME/USRDIR/DATA.BIN",
            size=4,
            output_path="../escape.bin",
        )
    ]

    with pytest.raises(ValueError, match="Unsafe game resource path"):
        analyze_game_resources("game.iso", output, records)
