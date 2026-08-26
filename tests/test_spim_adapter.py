from __future__ import annotations

from pspdisasm.analyzer import analyze_bytes
from pspdisasm.elf32 import parse_elf32
from pspdisasm.engines.spim import SpimdisasmAdapter

from .fixtures import build_allegrex_elf32


def test_adapter_decodes_allegrex_and_vfpu_and_discovers_functions() -> None:
    data = build_allegrex_elf32()
    elf = parse_elf32(data)
    model = analyze_bytes(data, "synthetic.elf")

    result = SpimdisasmAdapter().analyze(elf, model)

    assert [function.address for function in result.functions] == [0x08800000, 0x08800028]
    assert result.functions[0].instruction_count >= 8
    assert "clz" in result.functions[0].assembly
    assert "vzero.s" in result.functions[0].assembly
    assert len(result.assembly_sections) == 1
    assert result.assembly_sections[0].name == ".text"
    assert "clz" in result.assembly_sections[0].assembly


def test_adapter_normalizes_calls_branches_symbols_and_data_references() -> None:
    data = build_allegrex_elf32()
    elf = parse_elf32(data)
    model = analyze_bytes(data, "synthetic.elf")

    result = SpimdisasmAdapter().analyze(elf, model)

    call = next(ref for ref in result.references if ref.kind == "call")
    assert call.source_address == 0x08800004
    assert call.target_address == 0x08800028
    assert call.source_function == "func_08800000"
    assert call.target_section == ".text"

    branch = next(ref for ref in result.references if ref.kind == "branch")
    assert branch.source_address == 0x08800014
    assert branch.target_address == 0x0880001C
    assert branch.source_function == "func_08800000"
    assert branch.target_section == ".text"

    data_refs = [ref for ref in result.references if ref.kind == "data"]
    assert {(ref.source_address, ref.target_address) for ref in data_refs} == {
        (0x0880000C, 0x08800100),
        (0x08800010, 0x08800100),
    }
    assert {ref.target_section for ref in data_refs} == {".rodata"}

    function_symbols = [symbol for symbol in result.symbols if symbol.kind == "function"]
    assert {symbol.address for symbol in function_symbols} >= {0x08800000, 0x08800028}
    assert any(symbol.address == 0x08800100 and symbol.section == ".rodata" for symbol in result.symbols)


def test_adapter_recognizes_referenced_nul_terminated_strings() -> None:
    data = build_allegrex_elf32()
    elf = parse_elf32(data)
    model = analyze_bytes(data, "synthetic.elf")

    result = SpimdisasmAdapter().analyze(elf, model)

    assert len(result.strings) == 1
    string = result.strings[0]
    assert string.address == 0x08800100
    assert string.value == "Hello PSP!"
    assert string.section == ".rodata"
    assert string.referenced_by == [0x0880000C, 0x08800010]


def test_seeded_nid_functions_must_point_into_executable_sections() -> None:
    import spimdisasm

    from tests.fixtures import build_prx_elf32

    data = build_prx_elf32()
    elf = parse_elf32(data)
    model = analyze_bytes(data, "sample.prx")
    context = spimdisasm.common.Context()
    context.changeGlobalSegmentRanges(0, len(data), 0, 0x200)

    seeded = SpimdisasmAdapter()._seed_known_functions(context, elf, model)

    assert 0x10 in seeded  # exported function in .text
    assert 0xD8 not in seeded  # imported stub lives in read-only .lib.stub


def test_jump_table_decoder_accepts_only_consecutive_executable_targets() -> None:
    import struct

    data = bytearray(build_allegrex_elf32())
    struct.pack_into("<III", data, 0x200, 0x08800000, 0x08800028, 0xDEADBEEF)
    elf = parse_elf32(bytes(data))

    targets = SpimdisasmAdapter._decode_jump_table_targets(elf, 0x08800100)

    assert targets == [0x08800000, 0x08800028]


def test_indirect_call_normalizer_uses_resolved_jalr_targets() -> None:
    from types import SimpleNamespace

    analyzer = SimpleNamespace(indirectFunctionCallIntrOffset={0x04: 0x08800028})
    function = SimpleNamespace(
        vram=0x08800000,
        getNameUnquoted=lambda: "func_08800000",
        instrAnalyzer=analyzer,
    )
    text = SimpleNamespace(symbolList=[function])
    elf = parse_elf32(build_allegrex_elf32())

    references = SpimdisasmAdapter._normalize_indirect_references(text, elf)

    assert len(references) == 1
    reference = references[0]
    assert reference.source_address == 0x08800004
    assert reference.target_address == 0x08800028
    assert reference.kind == "indirect_call"
    assert reference.source_function == "func_08800000"
    assert reference.target_section == ".text"
