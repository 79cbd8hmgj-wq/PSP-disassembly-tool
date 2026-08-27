from __future__ import annotations

import struct

import pspdisasm.game_project as game_project_module
from pspdisasm import generate_game_project
from pspdisasm.model import ModuleLinkAnalysis
from tests.fixtures import build_prx_elf32
from tests.test_game_project import _build_game_iso


def _relocation_free_prx() -> bytes:
    payload = bytearray(build_prx_elf32(include_prxreloc2=False))
    shoff = struct.unpack_from("<I", payload, 0x20)[0]
    struct.pack_into("<I", payload, shoff + 5 * 0x28 + 4, 1)
    return bytes(payload)


def test_game_linker_receives_relocated_model_for_relocatable_boot(tmp_path, monkeypatch):
    image = tmp_path / "linker.iso"
    output = tmp_path / "linker_decomp"
    _build_game_iso(image, eboot=_relocation_free_prx())

    captured = {}

    def capture_link(units, database):
        captured["units"] = list(units)
        return ModuleLinkAnalysis()

    monkeypatch.setattr(game_project_module, "link_modules", capture_link)

    generate_game_project(image, output)

    units = captured["units"]
    assert len(units) == 1
    model = units[0].model
    assert model.module_info is not None
    assert model.module_info.address == 0x08804020
    assert model.exports[0].address == 0x08804060
    assert model.imports[0].address == 0x088040A0
    assert units[0].disassembly is not None
    assert min(function.address for function in units[0].disassembly.functions) >= 0x08804000
