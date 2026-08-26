from __future__ import annotations

from .model import (
    AdvancedAnalysisResult,
    CallGraphEdge,
    DisassemblyResult,
    ExecutableModel,
    FunctionConfidence,
)


def _seeded_function_addresses(model: ExecutableModel) -> set[int]:
    addresses: set[int] = set()
    for library in [*model.imports, *model.exports]:
        addresses.update(entry.address for entry in library.functions)
    return addresses


def _build_call_edges(disassembly: DisassemblyResult) -> list[CallGraphEdge]:
    functions_by_address = {function.address: function for function in disassembly.functions}
    edges: dict[tuple[str, str, int, int, str], CallGraphEdge] = {}
    for reference in disassembly.references:
        if reference.kind not in {"call", "indirect_call"}:
            continue
        if reference.source_function is None:
            continue
        target = functions_by_address.get(reference.target_address)
        if target is None:
            continue
        kind = "indirect" if reference.kind == "indirect_call" else "direct"
        edge = CallGraphEdge(
            source_function=reference.source_function,
            target_function=target.name,
            source_address=reference.source_address,
            target_address=reference.target_address,
            kind=kind,
        )
        key = (
            edge.source_function,
            edge.target_function,
            edge.source_address,
            edge.target_address,
            edge.kind,
        )
        edges[key] = edge
    return sorted(
        edges.values(),
        key=lambda item: (
            item.source_address,
            item.target_address,
            item.source_function,
            item.target_function,
            item.kind,
        ),
    )


def _score_functions(
    model: ExecutableModel,
    disassembly: DisassemblyResult,
    call_edges: list[CallGraphEdge],
) -> list[FunctionConfidence]:
    entry_point = model.elf_header.entry if model.elf_header is not None else None
    seeded = _seeded_function_addresses(model)
    incoming_addresses = {edge.target_address for edge in call_edges}
    records: list[FunctionConfidence] = []

    for function in disassembly.functions:
        score = 0.50
        evidence: list[str] = []
        instructions = function.instructions

        if entry_point is not None and function.address == entry_point:
            score += 0.25
            evidence.append("ELF entry point")
        if function.address in seeded:
            score += 0.20
            evidence.append("PSP import/export seed")
        if function.address in incoming_addresses:
            score += 0.10
            evidence.append("incoming call")
        if len(instructions) >= 2 and all(instruction.valid for instruction in instructions):
            score += 0.05
            evidence.append("valid multi-instruction body")
        if instructions and all(instruction.implemented for instruction in instructions):
            score += 0.05
            evidence.append("all instructions implemented")
        if any(not instruction.valid for instruction in instructions):
            score -= 0.20
            evidence.append("invalid instruction")
        if any(not instruction.implemented for instruction in instructions):
            score -= 0.10
            evidence.append("unimplemented instruction")

        records.append(
            FunctionConfidence(
                name=function.name,
                address=function.address,
                score=max(0.0, min(1.0, score)),
                evidence=evidence,
            )
        )

    return sorted(records, key=lambda item: (item.address, item.name))


def analyze_advanced(
    model: ExecutableModel,
    disassembly: DisassemblyResult,
) -> AdvancedAnalysisResult:
    """Build deterministic higher-level analysis from normalized Phase 1/2 metadata."""

    call_edges = _build_call_edges(disassembly)
    return AdvancedAnalysisResult(
        source_name=disassembly.source_name,
        call_edges=call_edges,
        function_confidence=_score_functions(model, disassembly, call_edges),
    )
