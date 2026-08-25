from pspdisasm.elf32 import parse_elf32
from pspdisasm.prx import analyze_prx
from tests.fixtures import build_prx_elf32


def test_parses_prx_module_info_imports_exports_and_relocations():
    data = build_prx_elf32()
    elf = parse_elf32(data)
    result = analyze_prx(data, elf)

    assert result.module_info is not None
    assert result.module_info.name == "TESTPRX"
    assert result.module_info.attributes == 0x1000
    assert result.module_info.version == (1, 2)
    assert result.module_info.gp_value == 0x1234
    assert result.module_info.exports_start == 0x60
    assert result.module_info.imports_start == 0xA0

    assert len(result.exports) == 1
    export = result.exports[0]
    assert export.name == "TestEx"
    assert export.entry_length == 4
    assert [entry.nid for entry in export.functions] == [0x11111111]
    assert [entry.address for entry in export.functions] == [0x10]
    assert [entry.nid for entry in export.variables] == [0x22222222]
    assert [entry.address for entry in export.variables] == [0x14]

    assert len(result.imports) == 1
    imp = result.imports[0]
    assert imp.name == "TestIm"
    assert imp.entry_length == 6
    assert [entry.nid for entry in imp.functions] == [0xAAAA0001, 0xAAAA0002]
    assert [entry.address for entry in imp.functions] == [0xD8, 0xE0]
    assert [entry.nid for entry in imp.variables] == [0xBBBB0001]
    assert [entry.address for entry in imp.variables] == [0x50]

    assert len(result.relocations) == 1
    reloc = result.relocations[0]
    assert reloc.offset == 0x04
    assert reloc.type == 2
    assert reloc.type_name == "R_MIPS_32"
    assert reloc.symbol_index == 1
    assert reloc.target_section_index == 1
    assert any("PT_PRXRELOC2" in warning for warning in result.warnings)


def test_finds_module_info_from_first_load_header_when_section_name_is_absent():
    data = build_prx_elf32(module_section=False, include_prxreloc2=False)
    elf = parse_elf32(data)
    result = analyze_prx(data, elf)
    assert result.module_info is not None
    assert result.module_info.name == "TESTPRX"
    assert result.module_info.address == 0x20
    assert result.module_info.location == "program_header_fallback"
