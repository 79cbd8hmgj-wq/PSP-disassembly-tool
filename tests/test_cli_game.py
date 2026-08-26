from __future__ import annotations

import json

from pspdisasm.cli import main
from tests.test_game_image import _build_param_sfo, _build_psp_iso


def test_cli_game_reports_metadata_and_extracts_executables(tmp_path, capsys):
    image = tmp_path / "game.iso"
    image.write_bytes(_build_psp_iso(_build_param_sfo()))
    output = tmp_path / "modules"

    code = main(["game", str(image), "--json", "-", "--extract", str(output)])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["image_format"] == "iso"
    assert payload["boot_path"] == "/PSP_GAME/SYSDIR/EBOOT.BIN"
    assert payload["param_sfo"]["DISC_ID"] == "ULUS12345"
    assert payload["param_sfo"]["TITLE"] == "Fixture Game"
    assert payload["file_count"] == 4
    assert payload["extracted_files"] == ["PSP_GAME/SYSDIR/EBOOT.BIN"]
    assert (output / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN").exists()
