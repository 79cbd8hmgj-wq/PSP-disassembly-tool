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

    assert len(result.relocations) == 2
    type_a = result.relocations[0]
    assert type_a.offset == 0x04
    assert type_a.type == 2
    assert type_a.type_name == "R_MIPS_32"
    assert type_a.symbol_index == 1
    assert type_a.target_section_index == 1

    type_b = result.relocations[1]
    assert type_b.source == "program_header_rel2"
    assert type_b.section == "PT_PRXRELOC2[1]"
    assert type_b.offset == 0
    assert type_b.type == 0
    assert type_b.type_name == "R_MIPS_NONE"
    assert type_b.source_segment_index == 0
    assert type_b.target_segment_index == 0
    assert not any("decoding is not implemented" in warning for warning in result.warnings)


def test_malformed_prxreloc2_isolated_as_warning_and_type_a_survives():
    blob = bytearray(build_prx_elf32())
    blob[0x308:0x310] = bytes.fromhex("00 00 0F 02 01 01 00 00")
    data = bytes(blob)
    elf = parse_elf32(data)

    result = analyze_prx(data, elf)

    assert len(result.relocations) == 1
    assert result.relocations[0].source == "section"
    assert result.relocations[0].type == 2
    assert any(
        "PT_PRXRELOC2 program header 1" in warning and "bit widths exceed 16 bits" in warning
        for warning in result.warnings
    )


def test_finds_module_info_from_first_load_header_when_section_name_is_absent():
    data = build_prx_elf32(module_section=False, include_prxreloc2=False)
    elf = parse_elf32(data)
    result = analyze_prx(data, elf)
    assert result.module_info is not None
    assert result.module_info.name == "TESTPRX"
    assert result.module_info.address == 0x20
    assert result.module_info.location == "program_header_fallback"
