from __future__ import annotations

import csv
import json

import pytest

import pspdisasm.game_resources as game_resources
from pspdisasm.disc import DiscResourceRecord
from pspdisasm.game_resources import analyze_game_resources
from pspdisasm.resource_containers import ContainerEntry, ContainerInspection


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


def test_analyze_game_resources_profiles_unknown_container_families(tmp_path):
    output = tmp_path / "project"
    records = [
        _resource(output, "PSP_GAME/USRDIR/B.DAT", b"PACKbbbb"),
        _resource(output, "PSP_GAME/USRDIR/TEXTURE.PNG", PNG),
        _resource(output, "PSP_GAME/USRDIR/A.DAT", b"PACKaaaa"),
    ]

    analysis = analyze_game_resources("game.iso", output, records)

    assert [profile.path for profile in analysis.container_candidates] == [
        "PSP_GAME/USRDIR/A.DAT",
        "PSP_GAME/USRDIR/B.DAT",
    ]
    assert len(analysis.container_families) == 1
    family = analysis.container_families[0]
    assert family.family_key == ".dat:5041434b"
    assert family.member_paths == [
        "PSP_GAME/USRDIR/A.DAT",
        "PSP_GAME/USRDIR/B.DAT",
    ]

    candidate_json = json.loads(
        (output / "metadata/container_candidates.json").read_text(encoding="utf-8")
    )
    assert [record["path"] for record in candidate_json] == [
        "PSP_GAME/USRDIR/A.DAT",
        "PSP_GAME/USRDIR/B.DAT",
    ]
    with (output / "reports/container_candidates.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["path"] for row in rows] == [
        "PSP_GAME/USRDIR/A.DAT",
        "PSP_GAME/USRDIR/B.DAT",
    ]


class _SyntheticContainerParser:
    name = "synthetic-pack"

    def __init__(self, entries: list[ContainerEntry] | None = None, *, fail_inspect: bool = False):
        self.entries = entries or []
        self.fail_inspect = fail_inspect

    def probe(self, prefix: bytes, path: str) -> float:
        return 0.99 if prefix.startswith(b"PACK") else 0.0

    def inspect(self, path):
        if self.fail_inspect:
            raise RuntimeError("synthetic inspect failure")
        return ContainerInspection(
            parser_name=self.name,
            format_name="synthetic_pack",
            confidence=0.99,
            entries=list(self.entries),
        )


def test_analyze_game_resources_extracts_and_classifies_bounded_container_entry(tmp_path):
    output = tmp_path / "project"
    payload = b"PACK" + PNG + b"TAIL"
    records = [_resource(output, "PSP_GAME/USRDIR/DATA.DAT", payload)]
    parser = _SyntheticContainerParser(
        [ContainerEntry(path="textures/icon.png", offset=4, size=len(PNG))]
    )

    analysis = analyze_game_resources(
        "game.iso",
        output,
        records,
        container_parsers=[parser],
    )

    assert len(analysis.container_inspections) == 1
    inspection = analysis.container_inspections[0]
    assert (inspection.parser_name, inspection.format_name, inspection.confidence) == (
        "synthetic-pack",
        "synthetic_pack",
        0.99,
    )
    assert len(analysis.container_entries) == 1
    entry = analysis.container_entries[0]
    assert (entry.parent_path, entry.inner_path, entry.offset, entry.size) == (
        "PSP_GAME/USRDIR/DATA.DAT",
        "textures/icon.png",
        4,
        len(PNG),
    )
    assert entry.detected_format == "png"
    assert entry.kind == "image"
    assert entry.extracted_path == (
        "resources/containers/PSP_GAME/USRDIR/DATA.DAT/textures/icon.png"
    )
    assert (output / entry.extracted_path).read_bytes() == PNG
    assert analysis.resources[0].container_parser == "synthetic-pack"
    assert analysis.resources[0].container_entry_count == 1

    inspections_json = json.loads(
        (output / "metadata/container_inspections.json").read_text(encoding="utf-8")
    )
    assert inspections_json[0]["parser_name"] == "synthetic-pack"
    with (output / "reports/container_entries.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["inner_path"] == "textures/icon.png"


def test_analyze_game_resources_rejects_out_of_bounds_entry_as_warning(tmp_path):
    output = tmp_path / "project"
    payload = b"PACKpayload"
    records = [_resource(output, "PSP_GAME/USRDIR/DATA.DAT", payload)]
    parser = _SyntheticContainerParser(
        [ContainerEntry(path="bad.bin", offset=4, size=999)]
    )

    analysis = analyze_game_resources(
        "game.iso",
        output,
        records,
        container_parsers=[parser],
    )

    assert analysis.container_entries == []
    assert any("out of bounds" in warning.lower() for warning in analysis.resources[0].warnings)
    assert not (output / "resources/containers/PSP_GAME/USRDIR/DATA.DAT/bad.bin").exists()


def test_analyze_game_resources_isolates_container_inspect_failure(tmp_path):
    output = tmp_path / "project"
    records = [_resource(output, "PSP_GAME/USRDIR/DATA.DAT", b"PACKpayload")]

    analysis = analyze_game_resources(
        "game.iso",
        output,
        records,
        container_parsers=[_SyntheticContainerParser(fail_inspect=True)],
    )

    assert analysis.container_inspections == []
    assert analysis.container_entries == []
    assert any("inspect failed" in warning.lower() for warning in analysis.resources[0].warnings)


def test_analyze_game_resources_rejects_unsafe_container_entry_path(tmp_path):
    output = tmp_path / "project"
    records = [_resource(output, "PSP_GAME/USRDIR/DATA.DAT", b"PACKpayload")]
    parser = _SyntheticContainerParser(
        [ContainerEntry(path="../escape.bin", offset=4, size=4)]
    )

    with pytest.raises(ValueError, match="Unsafe container entry path"):
        analyze_game_resources(
            "game.iso",
            output,
            records,
            container_parsers=[parser],
        )
