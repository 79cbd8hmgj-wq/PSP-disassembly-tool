from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from pspdisasm.analysis_pack import AnalysisPackError, create_analysis_pack
from pspdisasm.workspace import _HASH_CHUNK_BYTES, _sha256_stream, analyze_game_workspace, prepare_game_workspace
from tests.test_analysis_pack import _analyzed_workspace
from tests.test_workspace import _build_extracted_game


class _BoundedReader(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        assert 0 < size <= _HASH_CHUNK_BYTES
        return super().read(size)


def test_workspace_hashing_is_bounded():
    payload = b"A" * (_HASH_CHUNK_BYTES * 2 + 17)
    reader = _BoundedReader(payload)

    digest = _sha256_stream(reader)

    assert digest == hashlib.sha256(payload).hexdigest()
    assert reader.read_sizes
    assert all(size == _HASH_CHUNK_BYTES for size in reader.read_sizes)


def test_prepare_game_rejects_source_symlinks(tmp_path: Path):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)
    target = source / "PSP_GAME/USRDIR/NESTED/DATA.BIN"
    link = source / "PSP_GAME/USRDIR/LINK.BIN"
    link.symlink_to(target)

    with pytest.raises(Exception, match="Symlinks"):
        prepare_game_workspace(source, workspace)


def test_analyze_workspace_rejects_missing_machine_local_source_without_state(tmp_path: Path):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _build_extracted_game(source)
    prepare_game_workspace(source, workspace)
    local_path = workspace / ".pspdisasm-local.json"
    local = json.loads(local_path.read_text(encoding="utf-8"))
    local["source_path"] = str(tmp_path / "missing")
    local_path.write_text(json.dumps(local), encoding="utf-8")

    with pytest.raises(Exception, match="no longer available"):
        analyze_game_workspace(workspace)
    assert not (workspace / "analysis/state.json").exists()


def test_pack_rejects_symlinked_output_parent(tmp_path: Path):
    workspace = _analyzed_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-output"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(AnalysisPackError, match="symlink"):
        create_analysis_pack(
            workspace,
            link / "pack.zip",
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
        )
    assert not (outside / "pack.zip").exists()
