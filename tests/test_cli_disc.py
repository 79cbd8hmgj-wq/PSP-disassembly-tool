import json

from pspdisasm.cli import main
from tests.test_disc import build_psp_iso


def test_cli_game_creates_disc_metadata_and_extracts_boot(tmp_path, capsys):
    image = tmp_path / "game.iso"
    output = tmp_path / "game_project"
    build_psp_iso(image, eboot=b"\x7fELF" + b"E" * 60)

    code = main(["game", str(image), str(output)])

    assert code == 0
    summary = capsys.readouterr().out
    assert "Synthetic PSP Game" in summary
    assert "PSP_GAME/SYSDIR/EBOOT.BIN" in summary
    assert (output / "metadata" / "disc.json").exists()
    assert (output / "metadata" / "param_sfo.json").exists()
    assert (output / "modules" / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN").exists()

    payload = json.loads((output / "metadata" / "disc.json").read_text(encoding="utf-8"))
    assert payload["disc_id"] == "ULUS12345"
    assert payload["boot_path"] == "PSP_GAME/SYSDIR/EBOOT.BIN"
