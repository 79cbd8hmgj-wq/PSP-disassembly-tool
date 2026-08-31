from __future__ import annotations

import json
from pathlib import Path

import pytest

import pspdisasm.workspace as workspace_module
from pspdisasm.workspace import analyze_game_workspace, prepare_game_workspace
from tests.fixtures import build_allegrex_elf32
from tests.test_game_project import PNG, _build_sfo


def _build_extracted_game(root: Path, *, extra_payload: bytes = b"opaque payload") -> None:
    (root / "PSP_GAME/SYSDIR").mkdir(parents=True)
    (root / "PSP_GAME/USRDIR/NESTED").mkdir(parents=True)
    (root / "PSP_GAME/PARAM.SFO").write_bytes(
        _build_sfo(
            {
                "TITLE": "Synthetic PSP Game",
                "DISC_ID": "ULUS12345",
                "DISC_VERSION": "1.00",
                "PSP_SYSTEM_VER": "6.60",
            }
        )
    )
    (root / "PSP_GAME/SYSDIR/EBOOT.BIN").write_bytes(build_allegrex_elf32())
    (root / "PSP_GAME/USRDIR/TEXTURE.PNG").write_bytes(PNG)
    (root / "PSP_GAME/USRDIR/NESTED/DATA.BIN").write_bytes(extra_payload)


def test_prepare_directory_workspace_writes_portable_deterministic_manifest(tmp_path):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)

    manifest = prepare_game_workspace(source, workspace)

    assert manifest.schema_version == 1
    assert manifest.source_kind == "directory"
    assert manifest.source_name == source.name
    assert len(manifest.source_identity) == 64
    assert [record.path for record in manifest.files] == sorted(
        [record.path for record in manifest.files], key=str.casefold
    )
    assert all(len(record.sha256) == 64 for record in manifest.files)
    assert all(record.source_kind == "directory" for record in manifest.files)
    assert all(not Path(record.path).is_absolute() for record in manifest.files)

    workspace_json = (workspace / "workspace.json").read_text(encoding="utf-8")
    files_json = (workspace / "manifests/files.json").read_text(encoding="utf-8")
    local_json = (workspace / ".pspdisasm-local.json").read_text(encoding="utf-8")

    assert str(source.resolve()) not in workspace_json
    assert str(source.resolve()) not in files_json
    assert str(source.resolve()) in local_json


def test_portable_manifest_is_independent_of_absolute_source_and_workspace_paths(tmp_path):
    source_a = tmp_path / "a/source"
    source_b = tmp_path / "different/root/source"
    workspace_a = tmp_path / "a/workspace"
    workspace_b = tmp_path / "elsewhere/workspace"
    _build_extracted_game(source_a)
    _build_extracted_game(source_b)

    prepare_game_workspace(source_a, workspace_a)
    prepare_game_workspace(source_b, workspace_b)

    assert (workspace_a / "workspace.json").read_bytes() == (workspace_b / "workspace.json").read_bytes()
    assert (workspace_a / "manifests/files.json").read_bytes() == (
        workspace_b / "manifests/files.json"
    ).read_bytes()


def test_prepare_workspace_changes_identity_when_source_content_changes(tmp_path):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)

    first = prepare_game_workspace(source, workspace)
    (source / "PSP_GAME/USRDIR/NESTED/DATA.BIN").write_bytes(b"changed payload")
    second = prepare_game_workspace(source, workspace)

    assert first.source_identity != second.source_identity


def test_analyze_workspace_reuses_matching_analysis_key(tmp_path, monkeypatch):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)
    prepare_game_workspace(source, workspace)

    calls = []
    real_generate = workspace_module.generate_game_project

    def record_generate(*args, **kwargs):
        calls.append((args, kwargs))
        return real_generate(*args, **kwargs)

    monkeypatch.setattr(workspace_module, "generate_game_project", record_generate)

    first = analyze_game_workspace(workspace)
    second = analyze_game_workspace(workspace)

    assert first.reused is False
    assert second.reused is True
    assert first.analysis_key == second.analysis_key
    assert len(calls) == 1
    assert (workspace / "analysis/state.json").exists()


def test_analyze_workspace_rejects_unsupported_schema_without_writing_state(tmp_path):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)
    prepare_game_workspace(source, workspace)

    payload = json.loads((workspace / "workspace.json").read_text(encoding="utf-8"))
    payload["schema_version"] = 999
    (workspace / "workspace.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(workspace_module.WorkspaceError, match="schema"):
        analyze_game_workspace(workspace)

    assert not (workspace / "analysis/state.json").exists()
