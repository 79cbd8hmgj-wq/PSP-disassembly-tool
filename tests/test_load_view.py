from __future__ import annotations

import struct

from pspdisasm.load_view import build_relocated_load_view
from pspdisasm.model import (
    ElfHeader,
    ElfImage,
    ExecutableModel,
    ProgramHeader,
    Relocation,
    Section,
)


def _single_segment_fixture() -> tuple[bytes, ElfImage, ExecutableModel]:
    data = bytearray(0x120)
    struct.pack_into("<I", data, 0x100, 0x10)

    header = ElfHeader(
        file_type=0xFFA0,
        machine=8,
        version=1,
        entry=0,
        phoff=0x34,
        shoff=0,
        flags=0,
        ehsize=0x34,
        phentsize=0x20,
        phnum=1,
        shentsize=0x28,
        shnum=1,
        shstrndx=0,
    )
    program_header = ProgramHeader(
        index=0,
        type=1,
        offset=0x100,
        vaddr=0,
        paddr=0,
        filesz=4,
        memsz=8,
        flags=7,
        align=0x10,
    )
    section = Section(
        index=0,
        name=".text",
        type=1,
        flags=0x6,
        addr=0,
        offset=0x100,
        size=4,
        link=0,
        info=0,
        addralign=4,
        entsize=0,
        kind="executable",
    )
    elf = ElfImage(
        header=header,
        endianness="little",
        program_headers=[program_header],
        sections=[section],
        raw_data=bytes(data),
    )
    relocation = Relocation(
        section=".rel.text",
        offset=0,
        info=2,
        type=2,
        type_name="R_MIPS_32",
        symbol_index=0,
        target_section_index=None,
        source="section",
    )
    model = ExecutableModel(
        source_name="fixture.prx",
        input_kind="elf",
        executable_kind="prx",
        needs_decryption=False,
        endianness="little",
        elf_header=header,
        program_headers=[program_header],
        sections=[section],
        relocations=[relocation],
    )
    return bytes(data), elf, model


def test_relocated_load_view_rebases_addresses_and_applies_type_a_without_mutating_input():
    data, elf, model = _single_segment_fixture()

    view = build_relocated_load_view(data, elf, model, load_address=0x08804000)

    assert struct.unpack_from("<I", data, 0x100)[0] == 0x10
    assert struct.unpack_from("<I", view.elf.raw_data, 0x100)[0] == 0x08804010
    assert view.load_address == 0x08804000
    assert view.original_image_base == 0
    assert view.address_delta == 0x08804000
    assert view.segment_bases == {0: 0x08804000}
    assert view.applied_relocations == 1
    assert view.elf.program_headers[0].vaddr == 0x08804000
    assert view.elf.sections[0].addr == 0x08804000
    assert view.elf.header.entry == 0x08804000
    assert view.model.load_address == 0x08804000
    assert view.model.relocation_delta == 0x08804000
