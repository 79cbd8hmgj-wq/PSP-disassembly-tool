from __future__ import annotations

import importlib

import pytest

from pspdisasm.model import (
    DisassemblyResult,
    ElfHeader,
    ExecutableModel,
    FunctionRecord,
    InstructionRecord,
    JumpTableRecord,
    LibraryExport,
    NidEntry,
    ReferenceRecord,
)


def _function(name: str, address: int) -> FunctionRecord:
    return FunctionRecord(
        name=name,
        address=address,
        size=8,
        section=".text",
        assembly="",
        instruction_count=2,
        instructions=[
            InstructionRecord(address=address, word=0, text="nop", valid=True, implemented=True),
            InstructionRecord(address=address + 4, word=0, text="nop", valid=True, implemented=True),
        ],
    )


def _model(*, exports: list[LibraryExport] | None = None) -> ExecutableModel:
    return ExecutableModel(
        source_name="synthetic.elf",
        input_kind="elf",
        executable_kind="elf",
        needs_decryption=False,
        endianness="little",
        elf_header=ElfHeader(
            file_type=2,
            machine=8,
            version=1,
            entry=0x08800000,
            phoff=0,
            shoff=0,
            flags=0,
            ehsize=52,
            phentsize=32,
            phnum=0,
            shentsize=40,
            shnum=0,
            shstrndx=0,
        ),
        exports=exports or [],
    )


def test_advanced_builds_direct_call_graph_and_scores_function_evidence() -> None:
    advanced_module = importlib.import_module("pspdisasm.advanced")
    caller = _function("func_08800000", 0x08800000)
    callee = _function("func_08800020", 0x08800020)
    disassembly = DisassemblyResult(
        source_name="synthetic.elf",
        functions=[caller, callee],
        references=[
            ReferenceRecord(
                source_address=0x08800004,
                target_address=0x08800020,
                kind="call",
                source_function=caller.name,
                target_section=".text",
            )
        ],
    )

    result = advanced_module.analyze_advanced(_model(), disassembly)

    assert len(result.call_edges) == 1
    edge = result.call_edges[0]
    assert edge.source_function == caller.name
    assert edge.target_function == callee.name
    assert edge.source_address == 0x08800004
    assert edge.target_address == 0x08800020
    assert edge.kind == "direct"

    scores = {item.name: item for item in result.function_confidence}
    assert scores[caller.name].score == pytest.approx(0.85)
    assert scores[callee.name].score == pytest.approx(0.70)
    assert "ELF entry point" in scores[caller.name].evidence
    assert "incoming call" in scores[callee.name].evidence


def test_confidence_rewards_psp_export_seed_and_penalizes_invalid_code() -> None:
    advanced_module = importlib.import_module("pspdisasm.advanced")
    function = _function("func_08800020", 0x08800020)
    function.instructions[1].valid = False
    function.instructions[1].implemented = False
    export = LibraryExport(
        name="SyntheticLib",
        flags=0,
        entry_length=4,
        function_count=1,
        variable_count=0,
        address=0x08800100,
        functions=[
            NidEntry(
                nid=0x12345678,
                address=function.address,
                kind="function",
                nid_address=0x08800120,
            )
        ],
    )
    disassembly = DisassemblyResult(source_name="synthetic.elf", functions=[function])

    result = advanced_module.analyze_advanced(_model(exports=[export]), disassembly)

    confidence = result.function_confidence[0]
    assert confidence.name == function.name
    assert confidence.score == pytest.approx(0.40)
    assert "PSP import/export seed" in confidence.evidence
    assert "invalid instruction" in confidence.evidence
    assert "unimplemented instruction" in confidence.evidence


def test_advanced_preserves_normalized_jump_tables() -> None:
    advanced_module = importlib.import_module("pspdisasm.advanced")
    jump_table = JumpTableRecord(
        address=0x08800100,
        source_function="func_08800000",
        source_address=0x08800018,
        targets=[0x08800020, 0x08800040],
    )
    disassembly = DisassemblyResult(source_name="synthetic.elf", jump_tables=[jump_table])

    result = advanced_module.analyze_advanced(_model(), disassembly)

    assert result.jump_tables == [jump_table]


def test_package_exports_phase6a_api_and_version() -> None:
    import pspdisasm

    advanced_module = importlib.import_module("pspdisasm.advanced")

    assert pspdisasm.analyze_advanced is advanced_module.analyze_advanced
    assert pspdisasm.__version__ == "0.6.0"
