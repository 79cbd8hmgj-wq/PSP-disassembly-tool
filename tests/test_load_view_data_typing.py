from __future__ import annotations

import struct

from pspdisasm.data_typing import analyze_data_types
from pspdisasm.model import (
    DisassemblyResult,
    ElfHeader,
    ElfImage,
    ExecutableModel,
    ProgramHeader,
    Relocation,
    Section,
)


def test_data_typing_resolves_psp_relocation_offset_from_source_segment() -> None:
    base = 0x08902000
    data = bytearray(0xC0)
    struct.pack_into("<I", data, 0x48, base + 0x40)

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
    load = ProgramHeader(
        index=0,
        type=1,
        offset=0x40,
        vaddr=base,
        paddr=base,
        filesz=0x80,
        memsz=0x80,
        flags=6,
        align=4,
    )
    section = Section(
        index=1,
        name=".data",
        type=1,
        flags=0x3,
        addr=base,
        offset=0x40,
        size=0x80,
        link=0,
        info=0,
        addralign=4,
        entsize=0,
        kind="writable",
    )
    relocation = Relocation(
        section="PT_PRXRELOC[0]",
        offset=8,
        info=2,
        type=2,
        type_name="R_MIPS_32",
        symbol_index=0,
        target_section_index=None,
        source="program_header",
    )
    elf = ElfImage(header, "little", [load], [section], bytes(data))
    model = ExecutableModel(
        source_name="fixture.prx",
        input_kind="elf",
        executable_kind="prx",
        needs_decryption=False,
        endianness="little",
        elf_header=header,
        program_headers=[load],
        sections=[section],
        relocations=[relocation],
    )
    disassembly = DisassemblyResult(source_name="fixture.prx")

    result = analyze_data_types(model, disassembly, elf)

    pointer = next(record for record in result.data_types if record.address == base + 8)
    assert pointer.type_name == "pointer"
    assert pointer.target_address == base + 0x40
    assert pointer.confidence == 0.90
    assert result.warnings == []
