from __future__ import annotations

import pytest

from pspdisasm.errors import ParseError
from pspdisasm.game_project import generate_game_project
from tests.fixtures import build_allegrex_elf32
from tests.test_game_project import PNG, _build_sfo


def _build_directory_game(source):
    (source / "PSP_GAME/SYSDIR").mkdir(parents=True)
    (source / "PSP_GAME/USRDIR/MixedCase").mkdir(parents=True)
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
    (source / "PSP_GAME/USRDIR/MixedCase/Data.Bin").write_bytes(b"opaque proprietary payload")
    return eboot


def test_generate_game_project_accepts_extracted_psp_directory_directly(tmp_path):
    source = tmp_path / "extracted"
    output = tmp_path / "game_decomp"
    eboot = _build_directory_game(source)

    result = generate_game_project(source, output)

    assert result.module_count == 1
    assert result.analyzed_count == 1
    assert result.resource_count == 2
    assert result.known_resource_count == 1
    assert result.unknown_resource_count == 1
    assert (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").exists()
    assert (output / "resources/files/PSP_GAME/USRDIR/MixedCase/Data.Bin").exists()
    assert (source / "PSP_GAME/SYSDIR/EBOOT.BIN").read_bytes() == eboot


def test_generate_game_project_rejects_symlinks_in_extracted_source(tmp_path):
    source = tmp_path / "extracted"
    output = tmp_path / "game_decomp"
    _build_directory_game(source)
    outside = tmp_path / "outside.dat"
    outside.write_bytes(b"outside")
    (source / "PSP_GAME/USRDIR/escape.dat").symlink_to(outside)

    with pytest.raises(ParseError, match="Symlink"):
        generate_game_project(source, output)
