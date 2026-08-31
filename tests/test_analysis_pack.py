from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from pspdisasm.analysis_pack import AnalysisPackError, create_analysis_pack
from pspdisasm.workspace import analyze_game_workspace, prepare_game_workspace
from tests.test_workspace import _build_extracted_game


def _analyzed_workspace(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)
    prepare_game_workspace(source, workspace)
    analyze_game_workspace(workspace)
    return workspace


def _read_pack_manifest(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        return json.loads(archive.read("pack-manifest.json"))


def test_module_pack_is_byte_deterministic_and_provenance_locked(tmp_path):
    workspace = _analyzed_workspace(tmp_path)
    first_path = tmp_path / "first.zip"
    second_path = tmp_path / "second.zip"

    first = create_analysis_pack(
        workspace,
        first_path,
        module="PSP_GAME/SYSDIR/EBOOT.BIN",
    )
    second = create_analysis_pack(
        workspace,
        second_path,
        module="PSP_GAME/SYSDIR/EBOOT.BIN",
    )

    assert first_path.read_bytes() == second_path.read_bytes()
    assert first.artifact_count == second.artifact_count
    assert first.manifest_sha256 == second.manifest_sha256

    manifest = _read_pack_manifest(first_path)
    workspace_manifest = json.loads((workspace / "workspace.json").read_text(encoding="utf-8"))
    source_files = json.loads((workspace / "manifests/files.json").read_text(encoding="utf-8"))
    eboot = next(record for record in source_files if record["path"] == "PSP_GAME/SYSDIR/EBOOT.BIN")

    assert manifest["selector"] == {
        "kind": "module",
        "value": "PSP_GAME/SYSDIR/EBOOT.BIN",
    }
    assert manifest["source_identity"] == workspace_manifest["source_identity"]
    assert manifest["source"] == {
        "path": "PSP_GAME/SYSDIR/EBOOT.BIN",
        "size": eboot["size"],
        "sha256": eboot["sha256"],
    }
    assert manifest["artifacts"]
    for artifact in manifest["artifacts"]:
        assert not Path(artifact["path"]).is_absolute()
        assert len(artifact["sha256"]) == 64

    encoded = first_path.read_bytes()
    assert str(workspace.resolve()).encode() not in encoded
    assert str((tmp_path / "source").resolve()).encode() not in encoded


def test_function_pack_contains_only_selected_function_evidence(tmp_path):
    workspace = _analyzed_workspace(tmp_path)
    functions_path = (
        workspace
        / "analysis/game_project/projects/PSP_GAME/SYSDIR/EBOOT.BIN/metadata/functions.json"
    )
    functions = json.loads(functions_path.read_text(encoding="utf-8"))
    selected = functions[0]
    output = tmp_path / "function.zip"

    result = create_analysis_pack(
        workspace,
        output,
        module="PSP_GAME/SYSDIR/EBOOT.BIN",
        function=selected["name"],
        context_bytes=32,
    )

    assert result.selector_kind == "function"
    with zipfile.ZipFile(output) as archive:
        selected_payload = json.loads(archive.read("evidence/function.json"))
        instructions = json.loads(archive.read("evidence/instructions.json"))
        assert selected_payload["name"] == selected["name"]
        assert all(
            selected["address"] <= instruction["address"] < selected["address"] + selected["size"]
            for instruction in instructions
        )
        assert "evidence/context.bin" in archive.namelist()


def test_resource_pack_includes_record_and_bounded_sample(tmp_path):
    workspace = _analyzed_workspace(tmp_path)
    output = tmp_path / "resource.zip"

    result = create_analysis_pack(
        workspace,
        output,
        resource="PSP_GAME/USRDIR/TEXTURE.PNG",
        context_bytes=8,
    )

    assert result.selector_kind == "resource"
    with zipfile.ZipFile(output) as archive:
        record = json.loads(archive.read("evidence/resource.json"))
        sample = archive.read("evidence/resource-sample.bin")
        assert record["path"] == "PSP_GAME/USRDIR/TEXTURE.PNG"
        assert sample == b"\x89PNG\r\n\x1a\n"


def test_pack_rejects_unsafe_selector_and_too_small_budget(tmp_path):
    workspace = _analyzed_workspace(tmp_path)

    with pytest.raises(AnalysisPackError, match="Unsafe"):
        create_analysis_pack(workspace, tmp_path / "unsafe.zip", module="../EBOOT.BIN")

    with pytest.raises(AnalysisPackError, match="budget"):
        create_analysis_pack(
            workspace,
            tmp_path / "tiny.zip",
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            max_bytes=64,
        )
    assert not (tmp_path / "tiny.zip").exists()


def test_pack_manifest_hash_matches_manifest_member(tmp_path):
    workspace = _analyzed_workspace(tmp_path)
    output = tmp_path / "pack.zip"
    result = create_analysis_pack(
        workspace,
        output,
        resource="PSP_GAME/USRDIR/TEXTURE.PNG",
    )

    with zipfile.ZipFile(output) as archive:
        raw = archive.read("pack-manifest.json")
    assert hashlib.sha256(raw).hexdigest() == result.manifest_sha256
