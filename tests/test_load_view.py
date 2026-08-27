from __future__ import annotations

import struct

import pytest

from pspdisasm.errors import ParseError
from pspdisasm.load_view import build_relocated_load_view
from pspdisasm.model import (
    ElfHeader,
    ElfImage,
    ExecutableModel,
    LibraryExport,
    LibraryImport,
    ModuleInfo,
    NidEntry,
    ProgramHeader,
    Relocation,
    Section,
)


def _type_a(offset: int, relocation_type: int) -> Relocation:
    names = {
        2: "R_MIPS_32",
        5: "R_MIPS_HI16",
        6: "R_MIPS_LO16",
    }
    return Relocation(
        section=".rel.text",
        offset=offset,
        info=relocation_type,
        type=relocation_type,
        type_name=names[relocation_type],
        symbol_index=0,
        target_section_index=None,
        source="section",
    )


def _single_segment_fixture(
    words: tuple[int, ...] = (0x10,),
    relocations: list[Relocation] | None = None,
) -> tuple[bytes, ElfImage, ExecutableModel]:
    data = bytearray(0x180)
    for index, word in enumerate(words):
        struct.pack_into("<I", data, 0x100 + index * 4, word)

    size = len(words) * 4
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
        filesz=size,
        memsz=max(size + 4, 0x80),
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
        size=size,
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
    model = ExecutableModel(
        source_name="fixture.prx",
        input_kind="elf",
        executable_kind="prx",
        needs_decryption=False,
        endianness="little",
        elf_header=header,
        program_headers=[program_header],
        sections=[section],
        relocations=relocations if relocations is not None else [_type_a(0, 2)],
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
    assert view.model.elf_header is not None
    assert view.model.elf_header.entry == 0x08804000
    assert view.model.sections[0].addr == 0x08804000


def test_type_a_hi16_uses_following_lo16_word_before_relocation():
    data, elf, model = _single_segment_fixture(
        words=(0x3C080000, 0x25080020),
        relocations=[_type_a(0, 5), _type_a(4, 6)],
    )

    view = build_relocated_load_view(data, elf, model, load_address=0x08804000)

    assert struct.unpack_from("<I", view.elf.raw_data, 0x100)[0] == 0x3C080880
    assert struct.unpack_from("<I", view.elf.raw_data, 0x104)[0] == 0x25084020
    assert view.applied_relocations == 2


def test_relocated_load_view_rebases_loaded_prx_metadata_without_touching_external_values():
    data, elf, model = _single_segment_fixture(words=(0,) * 16, relocations=[])
    model.module_info = ModuleInfo(
        attributes=0,
        version=(1, 0),
        name="fixture",
        gp_value=0x10,
        exports_start=0x20,
        exports_end=0x28,
        imports_start=0x30,
        imports_end=0x38,
        address=0x08,
        location=".rodata.sceModuleInfo",
    )
    model.exports = [
        LibraryExport(
            name="FixtureEx",
            flags=0,
            entry_length=4,
            function_count=1,
            variable_count=1,
            address=0x20,
            functions=[NidEntry(0x11111111, 0x04, "function", 0x24)],
            variables=[NidEntry(0x22222222, 0x1000, "variable", 0x28)],
        )
    ]
    model.imports = [
        LibraryImport(
            name="FixtureIm",
            flags=0,
            entry_length=5,
            function_count=1,
            variable_count=0,
            address=0x30,
            functions=[NidEntry(0xAAAA0001, 0x14, "function", 0x34)],
        )
    ]

    view = build_relocated_load_view(data, elf, model, load_address=0x08800000)

    assert view.model.module_info is not None
    assert view.model.module_info.address == 0x08800008
    assert view.model.module_info.gp_value == 0x08800010
    assert view.model.module_info.exports_start == 0x08800020
    assert view.model.module_info.imports_end == 0x08800038
    assert view.model.exports[0].address == 0x08800020
    assert view.model.exports[0].functions[0].address == 0x08800004
    assert view.model.exports[0].functions[0].nid_address == 0x08800024
    assert view.model.exports[0].variables[0].address == 0x1000
    assert view.model.imports[0].address == 0x08800030
    assert view.model.imports[0].functions[0].address == 0x08800014
    assert view.model.imports[0].functions[0].nid_address == 0x08800034


def test_relocated_load_view_rebases_module_range_end_at_segment_boundary():
    data, elf, model = _single_segment_fixture(words=(0,) * 16, relocations=[])
    model.module_info = ModuleInfo(
        attributes=0,
        version=(1, 0),
        name="fixture",
        gp_value=0,
        exports_start=0x70,
        exports_end=0x80,
        imports_start=0x78,
        imports_end=0x80,
        address=0x08,
        location=".rodata.sceModuleInfo",
    )

    view = build_relocated_load_view(data, elf, model, load_address=0x08800000)

    assert view.model.module_info is not None
    assert view.model.module_info.exports_end == 0x08800080
    assert view.model.module_info.imports_end == 0x08800080


def test_relocated_load_view_rejects_segment_address_space_wraparound():
    data, elf, model = _single_segment_fixture(relocations=[])

    with pytest.raises(ParseError, match="32-bit address space"):
        build_relocated_load_view(data, elf, model, load_address=0xFFFFFFC0)
