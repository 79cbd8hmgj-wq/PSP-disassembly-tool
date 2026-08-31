from __future__ import annotations

from pathlib import Path

from pspdisasm.cli import main
from tests.test_workspace import _build_extracted_game


def test_workspace_cli_prepare_analyze_and_make_pack(tmp_path: Path, capsys):
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    pack = tmp_path / "eboot.zip"
    _build_extracted_game(source)

    assert main(["prepare-game", str(source), str(workspace)]) == 0
    prepare_stdout = capsys.readouterr().out
    assert "Source kind: directory" in prepare_stdout
    assert "Files: 4" in prepare_stdout
    assert "Source identity:" in prepare_stdout

    assert main(["analyze-workspace", str(workspace)]) == 0
    analyze_stdout = capsys.readouterr().out
    assert "Reused: no" in analyze_stdout
    assert "Analyzed modules: 1" in analyze_stdout
    assert "Resources: 2" in analyze_stdout

    assert main(["analyze-workspace", str(workspace)]) == 0
    reused_stdout = capsys.readouterr().out
    assert "Reused: yes" in reused_stdout

    assert main([
        "make-pack",
        str(workspace),
        "--module",
        "PSP_GAME/SYSDIR/EBOOT.BIN",
        "--output",
        str(pack),
    ]) == 0
    pack_stdout = capsys.readouterr().out
    assert pack.exists()
    assert "Artifacts:" in pack_stdout
    assert "Total bytes:" in pack_stdout
    assert "Manifest SHA-256:" in pack_stdout
