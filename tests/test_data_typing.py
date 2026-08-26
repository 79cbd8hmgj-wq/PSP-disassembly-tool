from __future__ import annotations

import struct

from pspdisasm.data_typing import analyze_data_types
from pspdisasm.model import (
    DataTypeRecord,
    DataTypingResult,
    DisassemblyResult,
    ElfHeader,
    ElfImage,
    ExecutableModel,
    FunctionRecord,
    JumpTableRecord,
    ReferenceRecord,
    Relocation,
    Section,
    StringRecord,
    SymbolRecord,
    TypedCallEdge,
    TypedFieldRecord,
    TypedReferenceRecord,
)

BASE_TEXT = 0x1000
BASE_DATA = 0x2000


def _header() -> ElfHeader:
    return ElfHeader(
        file_type=2,
        machine=8,
        version=1,
        entry=BASE_TEXT,
        phoff=0,
        shoff=0,
        flags=0,
        ehsize=0x34,
        phentsize=0,
        phnum=0,
        shentsize=0,
        shnum=0,
        shstrndx=0,
    )


def _fixture(
    words: dict[int, int] | None = None,
    *,
    data_size: int = 0x100,
    relocations: list[Relocation] | None = None,
    strings: list[StringRecord] | None = None,
    jump_tables: list[JumpTableRecord] | None = None,
    symbols: list[SymbolRecord] | None = None,
    references: list[ReferenceRecord] | None = None,
    functions: list[FunctionRecord] | None = None,
) -> tuple[ExecutableModel, DisassemblyResult, ElfImage]:
    text = Section(1, ".text", 1, 0x6, BASE_TEXT, 0, 0x40, 0, 0, 4, 0, "executable")
    data = Section(2, ".data", 1, 0x3, BASE_DATA, 0x40, data_size, 0, 0, 4, 0, "writable")
    bss = Section(3, ".bss", 8, 0x3, BASE_DATA + data_size, 0x40 + data_size, 0x20, 0, 0, 4, 0, "bss")
    raw = bytearray(0x40 + data_size)
    for address, value in (words or {}).items():
        assert BASE_DATA <= address <= BASE_DATA + data_size - 4
        struct.pack_into("<I", raw, 0x40 + address - BASE_DATA, value)

    model = ExecutableModel(
        source_name="fixture.elf",
        input_kind="elf",
        executable_kind="elf",
        needs_decryption=False,
        endianness="little",
        elf_header=_header(),
        sections=[text, data, bss],
        relocations=list(relocations or []),
    )
    disassembly = DisassemblyResult(
        source_name="fixture.elf",
        functions=list(
            functions
            or [
                FunctionRecord("func_00001000", BASE_TEXT, 8, ".text", "", 0),
                FunctionRecord("func_00001010", BASE_TEXT + 0x10, 8, ".text", "", 0),
            ]
        ),
        symbols=list(symbols or []),
        references=list(references or []),
        strings=list(strings or []),
        jump_tables=list(jump_tables or []),
    )
    elf = ElfImage(_header(), "little", [], [text, data, bss], bytes(raw))
    return model, disassembly, elf


def _reloc(address: int) -> Relocation:
    return Relocation(
        section=".rel.data",
        offset=address,
        info=0,
        type=2,
        type_name="R_MIPS_32",
        symbol_index=0,
        target_section_index=2,
    )


def _type(result: DataTypingResult, address: int) -> DataTypeRecord | None:
    return next((record for record in result.data_types if record.address == address), None)


def test_phase6c_record_types_are_normalized_dataclasses():
    field = TypedFieldRecord(4, "pointer", BASE_DATA + 0x80, 0.9, ["evidence"])
    dtype = DataTypeRecord(
        address=BASE_DATA,
        section=".data",
        type_name="struct_candidate",
        size=8,
        confidence=0.65,
        evidence=["anchored fields"],
        fields=[field],
    )
    reference = TypedReferenceRecord(
        source_address=BASE_TEXT,
        target_address=BASE_DATA,
        kind="data",
        source_function="func_00001000",
        target_section=".data",
        target_type="struct_candidate",
        confidence=0.65,
        evidence=["typed target"],
    )
    edge = TypedCallEdge(
        source_function="func_00001000",
        target_function="func_00001010",
        source_address=BASE_TEXT + 4,
        target_address=BASE_TEXT + 0x10,
        kind="typed_indirect",
        evidence=["indirect call", "function pointer"],
    )
    result = DataTypingResult("fixture.elf", [dtype], [reference], [edge], [])

    assert result.data_types[0].fields[0].offset == 4
    assert result.typed_references[0].target_type == "struct_candidate"
    assert result.call_edges[0].kind == "typed_indirect"


def test_existing_string_and_jump_table_are_seeded_at_full_confidence():
    string = StringRecord(BASE_DATA + 0x80, "hello", ".data", [BASE_TEXT])
    jump = JumpTableRecord(BASE_DATA + 0x20, "func_00001000", BASE_TEXT + 4, [BASE_TEXT, BASE_TEXT + 0x10])
    model, disassembly, elf = _fixture(strings=[string], jump_tables=[jump])

    result = analyze_data_types(model, disassembly, elf)

    string_type = _type(result, string.address)
    jump_type = _type(result, jump.address)
    assert string_type is not None and string_type.type_name == "string" and string_type.confidence == 1.0
    assert jump_type is not None and jump_type.type_name == "jump_table" and jump_type.confidence == 1.0
    assert jump_type.count == 2 and jump_type.element_size == 4 and jump_type.size == 8


def test_relocation_backed_function_pointer_and_data_pointer_are_accepted():
    words = {
        BASE_DATA: BASE_TEXT + 0x10,
        BASE_DATA + 4: 1,
        BASE_DATA + 8: BASE_DATA + 0x80,
        BASE_DATA + 12: 2,
        BASE_DATA + 16: BASE_DATA + 0x90,
    }
    relocs = [_reloc(BASE_DATA), _reloc(BASE_DATA + 8)]
    model, disassembly, elf = _fixture(words, relocations=relocs)

    result = analyze_data_types(model, disassembly, elf)

    function_pointer = _type(result, BASE_DATA)
    data_pointer = _type(result, BASE_DATA + 8)
    arbitrary = _type(result, BASE_DATA + 16)
    assert function_pointer is not None and function_pointer.type_name == "function_pointer"
    assert function_pointer.target_address == BASE_TEXT + 0x10 and function_pointer.confidence == 1.0
    assert data_pointer is not None and data_pointer.type_name == "pointer"
    assert data_pointer.target_address == BASE_DATA + 0x80
    assert arbitrary is None


def test_unaligned_pointer_looking_bytes_are_never_scanned_as_pointer_slots():
    model, disassembly, elf = _fixture()
    raw = bytearray(elf.raw_data)
    struct.pack_into("<I", raw, 0x41, BASE_TEXT + 0x10)
    elf.raw_data = bytes(raw)
    model.relocations = [_reloc(BASE_DATA + 1)]

    result = analyze_data_types(model, disassembly, elf)

    assert _type(result, BASE_DATA + 1) is None


def test_three_entry_pointer_table_requires_corroboration_and_suppresses_children():
    words = {
        BASE_DATA: BASE_TEXT,
        BASE_DATA + 4: BASE_TEXT + 0x10,
        BASE_DATA + 8: BASE_DATA + 0x80,
    }
    symbols = [SymbolRecord("D_00002080", BASE_DATA + 0x80, ".data", "data", "fixture")]
    model, disassembly, elf = _fixture(words, relocations=[_reloc(BASE_DATA)], symbols=symbols)

    result = analyze_data_types(model, disassembly, elf)

    table = _type(result, BASE_DATA)
    assert table is not None and table.type_name == "pointer_table"
    assert table.count == 3 and table.element_type == "pointer" and table.element_size == 4
    assert _type(result, BASE_DATA + 4) is None
    assert _type(result, BASE_DATA + 8) is None


def test_three_mapped_values_without_required_table_evidence_are_rejected():
    words = {
        BASE_DATA: BASE_DATA + 0x60,
        BASE_DATA + 4: BASE_DATA + 0x64,
        BASE_DATA + 8: BASE_DATA + 0x68,
    }
    model, disassembly, elf = _fixture(words)

    result = analyze_data_types(model, disassembly, elf)

    assert not any(record.type_name in {"pointer_table", "function_pointer_table"} for record in result.data_types)
    assert not any(record.address in words for record in result.data_types)


def test_two_entry_table_requires_relocation_on_every_slot():
    words = {BASE_DATA: BASE_TEXT, BASE_DATA + 4: BASE_TEXT + 0x10}
    model, disassembly, elf = _fixture(words, relocations=[_reloc(BASE_DATA)])
    rejected = analyze_data_types(model, disassembly, elf)
    assert _type(rejected, BASE_DATA) is not None
    assert _type(rejected, BASE_DATA).type_name == "function_pointer"
    assert not any(record.type_name.endswith("_table") for record in rejected.data_types)

    model.relocations.append(_reloc(BASE_DATA + 4))
    accepted = analyze_data_types(model, disassembly, elf)
    table = _type(accepted, BASE_DATA)
    assert table is not None and table.type_name == "function_pointer_table"
    assert table.count == 2 and table.confidence == 1.0


def test_table_scan_stops_at_section_boundary():
    words = {BASE_DATA: BASE_TEXT, BASE_DATA + 4: BASE_TEXT + 0x10}
    model, disassembly, elf = _fixture(words, data_size=8, relocations=[_reloc(BASE_DATA), _reloc(BASE_DATA + 4)])

    result = analyze_data_types(model, disassembly, elf)

    table = _type(result, BASE_DATA)
    assert table is not None and table.size == 8 and table.count == 2


def test_struct_candidate_requires_two_typed_fields_and_array_candidate_outranks_struct():
    words = {
        BASE_DATA: BASE_DATA + 0x80,
        BASE_DATA + 4: 1,
        BASE_DATA + 8: BASE_TEXT,
        BASE_DATA + 12: 2,
        BASE_DATA + 16: BASE_DATA + 0x84,
        BASE_DATA + 20: 3,
        BASE_DATA + 24: BASE_TEXT + 0x10,
        BASE_DATA + 28: 4,
    }
    relocs = [
        _reloc(BASE_DATA),
        _reloc(BASE_DATA + 8),
        _reloc(BASE_DATA + 16),
        _reloc(BASE_DATA + 24),
    ]
    references = [ReferenceRecord(BASE_TEXT, BASE_DATA, "data", "func_00001000", ".data")]
    model, disassembly, elf = _fixture(words, relocations=relocs, references=references)

    result = analyze_data_types(model, disassembly, elf)

    composite = _type(result, BASE_DATA)
    assert composite is not None and composite.type_name == "array_candidate"
    assert composite.element_type == "struct_candidate" and composite.element_size == 16 and composite.count == 2
    assert [(field.offset, field.type_name) for field in composite.fields] == [(0, "pointer"), (8, "function_pointer")]


def test_single_typed_field_does_not_create_struct_candidate():
    words = {BASE_DATA + 0x20: BASE_DATA + 0x80}
    references = [ReferenceRecord(BASE_TEXT, BASE_DATA + 0x20, "data", "func_00001000", ".data")]
    model, disassembly, elf = _fixture(words, relocations=[_reloc(BASE_DATA + 0x20)], references=references)

    result = analyze_data_types(model, disassembly, elf)

    record = _type(result, BASE_DATA + 0x20)
    assert record is not None and record.type_name == "pointer"
    assert not any(item.type_name == "struct_candidate" for item in result.data_types)


def test_stronger_string_typing_suppresses_overlapping_pointer_candidate():
    string = StringRecord(BASE_DATA, "abcd", ".data", [])
    words = {BASE_DATA: BASE_TEXT}
    model, disassembly, elf = _fixture(words, relocations=[_reloc(BASE_DATA)], strings=[string])

    result = analyze_data_types(model, disassembly, elf)

    record = _type(result, BASE_DATA)
    assert record is not None and record.type_name == "string"
    assert [item for item in result.data_types if item.address == BASE_DATA] == [record]


def test_typed_references_preserve_identity_one_for_one_and_annotate_known_target():
    string = StringRecord(BASE_DATA + 0x80, "hello", ".data", [])
    references = [
        ReferenceRecord(BASE_TEXT, BASE_DATA + 0x80, "data", "func_00001000", ".data"),
        ReferenceRecord(BASE_TEXT + 4, BASE_DATA + 0x90, "data", "func_00001000", ".data"),
    ]
    model, disassembly, elf = _fixture(strings=[string], references=references)

    result = analyze_data_types(model, disassembly, elf)

    assert len(result.typed_references) == 2
    known, unknown = result.typed_references
    assert (known.source_address, known.target_address, known.kind, known.source_function, known.target_section) == (
        BASE_TEXT,
        BASE_DATA + 0x80,
        "data",
        "func_00001000",
        ".data",
    )
    assert known.target_type == "string" and known.confidence == 1.0
    assert unknown.target_type == "unknown" and unknown.confidence == 0.0 and unknown.evidence == []


def test_typed_indirect_call_requires_existing_indirect_reference_and_function_pointer_slot():
    words = {BASE_DATA: BASE_TEXT + 0x10}
    references = [ReferenceRecord(BASE_TEXT + 4, BASE_DATA, "indirect_call", "func_00001000", ".data")]
    symbols = [SymbolRecord("D_00002000", BASE_DATA, ".data", "data", "fixture")]
    model, disassembly, elf = _fixture(words, symbols=symbols, references=references)

    result = analyze_data_types(model, disassembly, elf)

    pointer = _type(result, BASE_DATA)
    assert pointer is not None and pointer.type_name == "function_pointer" and pointer.confidence == 0.95
    assert result.call_edges == [
        TypedCallEdge(
            source_function="func_00001000",
            target_function="func_00001010",
            source_address=BASE_TEXT + 4,
            target_address=BASE_TEXT + 0x10,
            kind="typed_indirect",
            evidence=result.call_edges[0].evidence,
        )
    ]
    assert any("indirect_call" in item for item in result.call_edges[0].evidence)
    assert any("function_pointer" in item for item in result.call_edges[0].evidence)


def test_direct_call_reference_does_not_create_phase6c_call_edge():
    words = {BASE_DATA: BASE_TEXT + 0x10}
    references = [ReferenceRecord(BASE_TEXT + 4, BASE_DATA, "call", "func_00001000", ".data")]
    model, disassembly, elf = _fixture(words, relocations=[_reloc(BASE_DATA)], references=references)

    result = analyze_data_types(model, disassembly, elf)

    assert result.call_edges == []


def test_unmappable_relocation_is_warned_and_does_not_supply_pointer_evidence():
    words = {BASE_DATA: BASE_DATA + 0x80}
    model, disassembly, elf = _fixture(words, relocations=[_reloc(0xDEADBEEF)])

    result = analyze_data_types(model, disassembly, elf)

    assert _type(result, BASE_DATA) is None
    assert len(result.warnings) == 1
    assert "DEADBEEF" in result.warnings[0]
