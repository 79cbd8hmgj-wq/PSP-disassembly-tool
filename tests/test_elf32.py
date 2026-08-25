import pytest

from pspdisasm.elf32 import parse_elf32
from pspdisasm.errors import ParseError
from tests.fixtures import build_simple_elf32


def test_parses_mips_elf32_programs_sections_and_names():
    elf = parse_elf32(build_simple_elf32())
    assert elf.header.file_type == 2
    assert elf.header.machine == 8
    assert elf.header.entry == 0x08800000
    assert elf.endianness == "little"
    assert len(elf.program_headers) == 1
    assert elf.program_headers[0].vaddr == 0x08800000
    assert elf.program_headers[0].filesz == 12
    assert [s.name for s in elf.sections] == ["", ".text", ".data", ".bss", ".shstrtab"]
    assert elf.sections[1].kind == "executable"
    assert elf.sections[2].kind == "writable"
    assert elf.sections[3].kind == "bss"
    assert elf.vaddr_to_offset(0x08800004) == 0x104
    assert elf.vaddr_to_offset(0x0880000C) is None


def test_rejects_non_32_bit_elf():
    blob = bytearray(build_simple_elf32())
    blob[4] = 2
    with pytest.raises(ParseError, match="ELF32"):
        parse_elf32(bytes(blob))


def test_rejects_program_header_table_past_end_of_file():
    blob = bytearray(build_simple_elf32())
    blob[0x1C:0x20] = (len(blob) - 4).to_bytes(4, "little")
    with pytest.raises(ParseError, match="program header table"):
        parse_elf32(bytes(blob))


def test_rejects_section_data_past_end_of_file():
    blob = bytearray(build_simple_elf32())
    shoff = int.from_bytes(blob[0x20:0x24], "little")
    data_section = shoff + 2 * 0x28
    blob[data_section + 0x10:data_section + 0x14] = (len(blob) - 2).to_bytes(4, "little")
    blob[data_section + 0x14:data_section + 0x18] = (8).to_bytes(4, "little")
    with pytest.raises(ParseError, match="section 2"):
        parse_elf32(bytes(blob))
