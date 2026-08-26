from __future__ import annotations

import pytest

from pspdisasm.disassembler import disassemble_bytes
from pspdisasm.errors import DisassemblyError

from .fixtures import build_allegrex_elf32, build_psp_container_header


def test_disassemble_bytes_runs_phase1_and_engine_analysis() -> None:
    result = disassemble_bytes(build_allegrex_elf32(), "synthetic.elf")

    assert result.source_name == "synthetic.elf"
    assert [function.address for function in result.functions] == [0x08800000, 0x08800028]
    assert {engine.name for engine in result.engines} == {"spimdisasm", "rabbitizer"}


def test_disassemble_bytes_can_use_explicit_relocated_load_address() -> None:
    result = disassemble_bytes(
        build_allegrex_elf32(),
        "synthetic.elf",
        load_address=0x08900000,
    )

    assert [function.address for function in result.functions] == [0x08900000, 0x08900028]
    assert any(reference.target_address == 0x08900100 for reference in result.references)
    assert any(string.address == 0x08900100 for string in result.strings)


def test_disassemble_bytes_rejects_encrypted_psp_container() -> None:
    with pytest.raises(DisassemblyError, match="decryption"):
        disassemble_bytes(build_psp_container_header(), "EBOOT.BIN")
