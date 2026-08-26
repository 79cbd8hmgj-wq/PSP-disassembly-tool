from __future__ import annotations

from pspdisasm.cli import main
from tests.fixtures import build_allegrex_elf32
from tests.test_game_project import _build_game_iso


def test_cli_game_project_analyzes_disc_and_reports_counts(tmp_path, capsys):
    image = tmp_path / "game.iso"
    output = tmp_path / "game_decomp"
    _build_game_iso(image, eboot=build_allegrex_elf32())

    code = main(["game-project", str(image), str(output)])

    assert code == 0
    assert (output / "metadata" / "game_analysis.json").exists()
    assert (output / "metadata" / "module_links.json").exists()

    stdout = capsys.readouterr().out
    assert "Game: Synthetic PSP Game" in stdout
    assert "Disc ID: ULUS12345" in stdout
    assert "Executable candidates: 1" in stdout
    assert "Analyzed modules: 1" in stdout
    assert "Needs decryption: 0" in stdout
    assert "Failed modules: 0" in stdout
    assert "Cross-module links: 0" in stdout
    assert "Game analysis:" in stdout
