from __future__ import annotations

from pspdisasm import generate_game_project
from tests.fixtures import build_allegrex_elf32
from tests.test_game_project import PNG, _build_sfo


def test_generate_game_project_accepts_extracted_psp_directory(tmp_path):
    source = tmp_path / "extracted"
    output = tmp_path / "game_decomp"
    (source / "PSP_GAME/SYSDIR").mkdir(parents=True)
    (source / "PSP_GAME/USRDIR").mkdir(parents=True)
    (source / "PSP_GAME/PARAM.SFO").write_bytes(
        _build_sfo(
            {
                "TITLE": "Synthetic PSP Game",
                "DISC_ID": "ULUS12345",
                "DISC_VERSION": "1.00",
                "PSP_SYSTEM_VER": "6.60",
            }
        )
    )
    eboot = build_allegrex_elf32()
    (source / "PSP_GAME/SYSDIR/EBOOT.BIN").write_bytes(eboot)
    (source / "PSP_GAME/USRDIR/TEXTURE.PNG").write_bytes(PNG)
    (source / "PSP_GAME/USRDIR/DATA.BIN").write_bytes(b"opaque proprietary payload")

    result = generate_game_project(source, output)

    assert result.module_count == 1
    assert result.analyzed_count == 1
    assert result.resource_count == 2
    assert result.known_resource_count == 1
    assert result.unknown_resource_count == 1
    assert (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").exists()
    assert (source / "PSP_GAME/SYSDIR/EBOOT.BIN").read_bytes() == eboot
