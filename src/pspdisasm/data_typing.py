from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable

from .model import (
    DataTypeRecord,
    DataTypingResult,
    DisassemblyResult,
    ElfImage,
    ExecutableModel,
    Section,
    TypedCallEdge,
    TypedFieldRecord,
    TypedReferenceRecord,
)

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_NOBITS = 8
PT_LOAD = 1
STRUCT_LIMIT = 64
ARRAY_SIZES = (8, 12, 16, 20, 24, 32, 48, 64)

_TYPE_PRECEDENCE = {
    "string": 1,
    "jump_table": 2,
    "function_pointer_table": 3,
    "pointer_table": 4,
    "array_candidate": 5,
    "struct_candidate": 6,
    "function_pointer": 7,
    "pointer": 8,
}
_TABLE_TYPES = {"function_pointer_table", "pointer_table"}
_STRONG_RANGE_TYPES = {"string", "jump_table", "function_pointer_table", "pointer_table"}
_LEAF_TYPES = {"pointer", "function_pointer"}


@dataclass(slots=True)
class _Leaf:
    record: DataTypeRecord
    relocation_backed: bool


def _allocated_section(elf: ElfImage, address: int, *, file_backed: bool = False) -> Section | None:
    for section in elf.sections:
        if section.size <= 0 or not section.flags & SHF_ALLOC:
            continue
        if file_backed and section.type == SHT_NOBITS:
            continue
        if section.addr <= address < section.addr + section.size:
            return section
    return None


def _storage_section(elf: ElfImage, address: int) -> Section | None:
    section = _allocated_section(elf, address, file_backed=True)
    if section is None or section.flags & SHF_EXECINSTR:
        return None
    return section


def _storage_sections(elf: ElfImage) -> list[Section]:
    return sorted(
        [
            section
            for section in elf.sections
            if section.size > 0
            and section.flags & SHF_ALLOC
            and not section.flags & SHF_EXECINSTR
            and section.type != SHT_NOBITS
        ],
        key=lambda item: (item.addr, item.index, item.name),
    )


def _safe_word(elf: ElfImage, section: Section, address: int) -> int | None:
    if address & 3:
        return None
    if address < section.addr or address + 4 > section.addr + section.size:
        return None
    offset = section.offset + address - section.addr
    if offset < 0 or offset + 4 > len(elf.raw_data):
        return None
    return struct.unpack_from("<I", elf.raw_data, offset)[0]


def _range(record: DataTypeRecord) -> tuple[int, int]:
    size = max(1, record.size)
    return record.address, record.address + size


def _inside_ranges(address: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def _overlaps_ranges(start: int, end: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(start < reserved_end and reserved_start < end for reserved_start, reserved_end in ranges)


def _resolved_relocation_slot(model: ExecutableModel, elf: ElfImage, relocation) -> int | None:
    is_psp_segment_relative = (
        model.executable_kind == "prx"
        or relocation.source_segment_index is not None
        or relocation.source in {"program_header", "program_header_rel2"}
    )
    if is_psp_segment_relative:
        source_index = relocation.source_segment_index
        if source_index is None:
            source_index = (relocation.info >> 8) & 0xFF
        if 0 <= source_index < len(elf.program_headers):
            source = elf.program_headers[source_index]
            if source.type == PT_LOAD:
                if relocation.offset < 0 or relocation.offset + 4 > source.filesz:
                    return None
                address = source.vaddr + relocation.offset
                if 0 <= address <= 0xFFFFFFFF:
                    return address
                return None
    return relocation.offset


def _safe_relocation_slots(model: ExecutableModel, elf: ElfImage) -> tuple[set[int], list[str]]:
    slots: set[int] = set()
    warning_keys: set[tuple[str, str, int]] = set()
    warnings: list[str] = []
    for relocation in sorted(
        model.relocations,
        key=lambda item: (item.offset, item.source, item.type_name, item.type, item.section),
    ):
        slot_address = _resolved_relocation_slot(model, elf, relocation)
        section = None if slot_address is None else _allocated_section(elf, slot_address, file_backed=True)
        mapped = None if slot_address is None else elf.vaddr_to_offset(slot_address)
        if (
            slot_address is None
            or section is None
            or mapped is None
            or mapped < 0
            or mapped + 4 > len(elf.raw_data)
        ):
            warning_address = relocation.offset if slot_address is None else slot_address
            key = (relocation.source, relocation.type_name, warning_address)
            if key not in warning_keys:
                warning_keys.add(key)
                warnings.append(
                    "Skipped unmappable relocation "
                    f"source={relocation.source} type={relocation.type_name} offset=0x{warning_address:08X}"
                )
            continue
        slots.add(slot_address)
    return slots, warnings


def _seed_existing_types(disassembly: DisassemblyResult, elf: ElfImage) -> list[DataTypeRecord]:
    records: list[DataTypeRecord] = []
    for string in sorted(disassembly.strings, key=lambda item: (item.address, item.section, item.value)):
        size = len(string.value.encode("utf-8", errors="replace")) + 1
        records.append(
            DataTypeRecord(
                address=string.address,
                section=string.section,
                type_name="string",
                size=max(1, size),
                confidence=1.0,
                evidence=["existing referenced string"],
            )
        )
    for jump in sorted(disassembly.jump_tables, key=lambda item: (item.address, item.source_address, item.source_function)):
        section = _allocated_section(elf, jump.address)
        records.append(
            DataTypeRecord(
                address=jump.address,
                section=section.name if section is not None else "",
                type_name="jump_table",
                size=len(jump.targets) * 4,
                count=len(jump.targets),
                element_type="pointer",
                element_size=4,
                confidence=1.0,
                evidence=["accepted Phase 6A jump table"],
            )
        )
    return records


def _function_targets(model: ExecutableModel, disassembly: DisassemblyResult) -> set[int]:
    targets = {function.address for function in disassembly.functions}
    for library in model.exports:
        targets.update(entry.address for entry in library.functions)
    return targets


def _variable_addresses(model: ExecutableModel) -> set[int]:
    addresses: set[int] = set()
    for library in [*model.imports, *model.exports]:
        addresses.update(entry.address for entry in library.variables)
    return addresses


def _data_symbol_addresses(disassembly: DisassemblyResult, elf: ElfImage) -> set[int]:
    addresses: set[int] = set()
    for symbol in disassembly.symbols:
        if _storage_section(elf, symbol.address) is not None:
            addresses.add(symbol.address)
    return addresses


def _reference_slot_anchors(disassembly: DisassemblyResult, elf: ElfImage) -> set[int]:
    return {
        reference.target_address
        for reference in disassembly.references
        if _storage_section(elf, reference.target_address) is not None
    }


def _struct_anchors(
    model: ExecutableModel,
    disassembly: DisassemblyResult,
    data_symbols: set[int],
    table_starts: set[int],
) -> set[int]:
    anchors = set(data_symbols)
    anchors.update(_variable_addresses(model))
    anchors.update(table_starts)
    anchors.update(
        reference.target_address
        for reference in disassembly.references
        if reference.kind in {"data", "pointer"}
    )
    return anchors


def _function_pointer_leaf(
    address: int,
    target: int,
    section: Section,
    *,
    relocation_backed: bool,
    anchor_backed: bool,
    table_backed: bool,
) -> _Leaf:
    evidence = [f"exact function target 0x{target:08X}"]
    if relocation_backed:
        evidence.append(f"safe relocation at 0x{address:08X}")
        confidence = 1.0
    elif anchor_backed:
        evidence.append(f"normalized symbol/reference anchor at 0x{address:08X}")
        confidence = 0.95
    else:
        evidence.append("accepted repeated pointer-table pattern")
        confidence = 0.90
    if table_backed and "accepted repeated pointer-table pattern" not in evidence:
        evidence.append("accepted repeated pointer-table pattern")
    return _Leaf(
        DataTypeRecord(
            address=address,
            section=section.name,
            type_name="function_pointer",
            size=4,
            target_address=target,
            confidence=confidence,
            evidence=evidence,
        ),
        relocation_backed,
    )


def _data_pointer_leaf(
    address: int,
    target: int,
    section: Section,
    *,
    relocation_backed: bool,
    anchor_backed: bool,
    identity_backed: bool,
    table_backed: bool,
) -> _Leaf:
    evidence = [f"mapped target 0x{target:08X}"]
    if relocation_backed:
        evidence.append(f"safe relocation at 0x{address:08X}")
    if anchor_backed:
        evidence.append(f"normalized symbol/reference anchor at 0x{address:08X}")
    if identity_backed:
        evidence.append(f"exact known data identity 0x{target:08X}")
    if table_backed:
        evidence.append("accepted repeated pointer-table pattern")

    if relocation_backed and identity_backed:
        confidence = 1.0
    elif anchor_backed and identity_backed:
        confidence = 0.95
    else:
        confidence = 0.90
    return _Leaf(
        DataTypeRecord(
            address=address,
            section=section.name,
            type_name="pointer",
            size=4,
            target_address=target,
            confidence=confidence,
            evidence=evidence,
        ),
        relocation_backed,
    )


def _scan_pointer_tables(
    elf: ElfImage,
    *,
    relocation_slots: set[int],
    function_targets: set[int],
    known_data_targets: set[int],
    reserved_ranges: list[tuple[int, int]],
) -> tuple[list[DataTypeRecord], dict[int, _Leaf]]:
    tables: list[DataTypeRecord] = []
    leaves: dict[int, _Leaf] = {}

    for section in _storage_sections(elf):
        address = (section.addr + 3) & ~3
        section_end = section.addr + section.size
        while address + 4 <= section_end:
            if _inside_ranges(address, reserved_ranges):
                address += 4
                continue
            first = _safe_word(elf, section, address)
            if first is None or _allocated_section(elf, first) is None:
                address += 4
                continue

            run: list[tuple[int, int]] = []
            cursor = address
            while cursor + 4 <= section_end and not _inside_ranges(cursor, reserved_ranges):
                value = _safe_word(elf, section, cursor)
                if value is None or _allocated_section(elf, value) is None:
                    break
                run.append((cursor, value))
                cursor += 4

            relocation_count = sum(slot in relocation_slots for slot, _ in run)
            identity_count = sum(
                value in function_targets or value in known_data_targets
                for _, value in run
            )
            qualifies = (
                len(run) >= 3 and (relocation_count >= 1 or identity_count >= 2)
            ) or (
                len(run) >= 2 and relocation_count == len(run)
            )
            if not qualifies:
                address = max(address + 4, cursor)
                continue

            all_functions = all(value in function_targets for _, value in run)
            table_type = "function_pointer_table" if all_functions else "pointer_table"
            entry_leaves: list[_Leaf] = []
            for slot, value in run:
                relocation_backed = slot in relocation_slots
                if value in function_targets:
                    leaf = _function_pointer_leaf(
                        slot,
                        value,
                        section,
                        relocation_backed=relocation_backed,
                        anchor_backed=False,
                        table_backed=True,
                    )
                else:
                    leaf = _data_pointer_leaf(
                        slot,
                        value,
                        section,
                        relocation_backed=relocation_backed,
                        anchor_backed=False,
                        identity_backed=value in known_data_targets,
                        table_backed=True,
                    )
                leaves[slot] = leaf
                entry_leaves.append(leaf)

            confidence = min(leaf.record.confidence for leaf in entry_leaves)
            if relocation_count != len(run):
                confidence = min(confidence, 0.95)
            evidence = [
                f"{len(run)} consecutive mapped aligned pointer-like entries",
                f"{relocation_count} relocation-backed entries",
                f"{identity_count} exact known target identities",
            ]
            table = DataTypeRecord(
                address=run[0][0],
                section=section.name,
                type_name=table_type,
                size=len(run) * 4,
                count=len(run),
                element_type="function_pointer" if all_functions else "pointer",
                element_size=4,
                confidence=round(confidence, 2),
                evidence=evidence,
            )
            tables.append(table)
            reserved_ranges.append(_range(table))
            address = cursor

    return tables, leaves


def _scan_standalone_leaves(
    elf: ElfImage,
    *,
    relocation_slots: set[int],
    function_targets: set[int],
    known_data_targets: set[int],
    slot_anchors: set[int],
    reserved_ranges: list[tuple[int, int]],
    leaves: dict[int, _Leaf],
) -> list[DataTypeRecord]:
    records: list[DataTypeRecord] = []
    for section in _storage_sections(elf):
        start = (section.addr + 3) & ~3
        end = section.addr + section.size
        for address in range(start, end - 3, 4):
            if address in leaves or _inside_ranges(address, reserved_ranges):
                continue
            value = _safe_word(elf, section, address)
            if value is None:
                continue
            relocation_backed = address in relocation_slots
            anchor_backed = address in slot_anchors
            if value in function_targets and (relocation_backed or anchor_backed):
                leaf = _function_pointer_leaf(
                    address,
                    value,
                    section,
                    relocation_backed=relocation_backed,
                    anchor_backed=anchor_backed,
                    table_backed=False,
                )
            else:
                target_section = _allocated_section(elf, value)
                identity_backed = value in known_data_targets
                if target_section is None or not (
                    relocation_backed or (identity_backed and anchor_backed)
                ):
                    continue
                leaf = _data_pointer_leaf(
                    address,
                    value,
                    section,
                    relocation_backed=relocation_backed,
                    anchor_backed=anchor_backed,
                    identity_backed=identity_backed,
                    table_backed=False,
                )
            leaves[address] = leaf
            records.append(leaf.record)
    return records


def _strong_object_ranges(records: Iterable[DataTypeRecord]) -> list[tuple[int, int]]:
    return sorted(
        [_range(record) for record in records if record.type_name in _STRONG_RANGE_TYPES],
        key=lambda item: (item[0], item[1]),
    )


def _infer_struct_candidates(
    elf: ElfImage,
    *,
    anchors: set[int],
    leaves: dict[int, _Leaf],
    strong_records: list[DataTypeRecord],
) -> list[DataTypeRecord]:
    strong_ranges = _strong_object_ranges(strong_records)
    strong_starts = sorted(record.address for record in strong_records if record.type_name in _STRONG_RANGE_TYPES)
    records: list[DataTypeRecord] = []

    for anchor in sorted(anchors):
        section = _storage_section(elf, anchor)
        if section is None or _inside_ranges(anchor, strong_ranges):
            continue
        upper = min(anchor + STRUCT_LIMIT, section.addr + section.size)
        for start in strong_starts:
            if anchor < start < upper:
                upper = start
                break
        fields: list[TypedFieldRecord] = []
        for address in sorted(leaves):
            if address < anchor or address + 4 > upper:
                continue
            leaf = leaves[address]
            if leaf.record.type_name not in _LEAF_TYPES:
                continue
            fields.append(
                TypedFieldRecord(
                    offset=address - anchor,
                    type_name=leaf.record.type_name,
                    target_address=leaf.record.target_address,
                    confidence=leaf.record.confidence,
                    evidence=list(leaf.record.evidence),
                )
            )
        if len(fields) < 2:
            continue
        relocation_fields = sum(
            leaves[anchor + field.offset].relocation_backed
            for field in fields
        )
        confidence = 0.80 if relocation_fields >= 2 else (0.75 if relocation_fields == 1 else 0.65)
        size = min(STRUCT_LIMIT, max(field.offset + 4 for field in fields))
        records.append(
            DataTypeRecord(
                address=anchor,
                section=section.name,
                type_name="struct_candidate",
                size=size,
                confidence=confidence,
                evidence=[
                    f"anchored data object with {len(fields)} accepted typed fields",
                    f"{relocation_fields} relocation-backed fields",
                ],
                fields=fields,
            )
        )
    return records


def _record_signature(
    start: int,
    size: int,
    leaves: dict[int, _Leaf],
) -> tuple[tuple[int, str], ...]:
    return tuple(
        (address - start, leaves[address].record.type_name)
        for address in sorted(leaves)
        if start <= address < start + size and leaves[address].record.type_name in _LEAF_TYPES
    )


def _infer_array_candidates(
    elf: ElfImage,
    *,
    structs: list[DataTypeRecord],
    leaves: dict[int, _Leaf],
    strong_records: list[DataTypeRecord],
) -> list[DataTypeRecord]:
    strong_ranges = _strong_object_ranges(strong_records)
    arrays: list[DataTypeRecord] = []

    for struct_record in structs:
        anchor = struct_record.address
        section = _storage_section(elf, anchor)
        if section is None:
            continue
        for element_size in ARRAY_SIZES:
            if anchor + element_size * 2 > section.addr + section.size:
                continue
            first_signature = _record_signature(anchor, element_size, leaves)
            if len(first_signature) < 2:
                continue
            count = 1
            confidences: list[float] = []
            first_relocs = sum(
                leaves[anchor + offset].relocation_backed
                for offset, _ in first_signature
            )
            confidences.append(0.80 if first_relocs >= 2 else (0.75 if first_relocs == 1 else 0.65))

            while True:
                record_start = anchor + count * element_size
                record_end = record_start + element_size
                if record_end > section.addr + section.size:
                    break
                if _overlaps_ranges(record_start, record_end, strong_ranges):
                    break
                signature = _record_signature(record_start, element_size, leaves)
                if signature != first_signature:
                    break
                reloc_count = sum(
                    leaves[record_start + offset].relocation_backed
                    for offset, _ in signature
                )
                confidences.append(0.80 if reloc_count >= 2 else (0.75 if reloc_count == 1 else 0.65))
                count += 1
            if count < 2:
                continue

            confidence = min(confidences) - 0.05
            confidence = round(max(0.60, min(0.75, confidence)), 2)
            fields = []
            for offset, type_name in first_signature:
                leaf = leaves[anchor + offset].record
                fields.append(
                    TypedFieldRecord(
                        offset=offset,
                        type_name=type_name,
                        target_address=leaf.target_address,
                        confidence=leaf.confidence,
                        evidence=list(leaf.evidence),
                    )
                )
            arrays.append(
                DataTypeRecord(
                    address=anchor,
                    section=section.name,
                    type_name="array_candidate",
                    size=element_size * count,
                    count=count,
                    element_type="struct_candidate",
                    element_size=element_size,
                    confidence=confidence,
                    evidence=[
                        f"{count} consecutive records share typed-field signature",
                        f"fixed element size {element_size}",
                    ],
                    fields=fields,
                )
            )
    return arrays


def _candidate_key(record: DataTypeRecord) -> tuple[int, float, str, int, tuple[str, ...]]:
    return (
        _TYPE_PRECEDENCE[record.type_name],
        -record.confidence,
        record.type_name,
        record.size,
        tuple(record.evidence),
    )


def _resolve_conflicts(candidates: list[DataTypeRecord], warnings: list[str]) -> list[DataTypeRecord]:
    by_address: dict[int, list[DataTypeRecord]] = {}
    for record in candidates:
        by_address.setdefault(record.address, []).append(record)

    chosen: list[DataTypeRecord] = []
    for address in sorted(by_address):
        unique: dict[tuple[object, ...], DataTypeRecord] = {}
        for record in by_address[address]:
            fingerprint = (
                record.type_name,
                record.size,
                record.target_address,
                record.count,
                record.element_type,
                record.element_size,
                record.confidence,
                tuple(record.evidence),
                tuple((field.offset, field.type_name, field.target_address, field.confidence) for field in record.fields),
            )
            unique[fingerprint] = record
        records = list(unique.values())
        records.sort(key=_candidate_key)
        best = records[0]
        same_precedence = [
            record
            for record in records
            if _TYPE_PRECEDENCE[record.type_name] == _TYPE_PRECEDENCE[best.type_name]
        ]
        highest = max(record.confidence for record in same_precedence)
        tied = [record for record in same_precedence if record.confidence == highest]
        tied.sort(key=lambda item: (item.type_name, item.size, tuple(item.evidence)))
        best = tied[0]
        if len(tied) > 1:
            warnings.append(
                f"Resolved same-precedence type conflict at 0x{address:08X}: "
                + ", ".join(f"{item.type_name}/0x{item.size:X}" for item in tied)
            )
        chosen.append(best)

    reserved = _strong_object_ranges(chosen)
    final: list[DataTypeRecord] = []
    for record in chosen:
        if record.type_name in _STRONG_RANGE_TYPES:
            final.append(record)
            continue
        containing = [
            (start, end)
            for start, end in reserved
            if start <= record.address < end
        ]
        if containing:
            continue
        final.append(record)
    return sorted(final, key=lambda item: (item.address, _TYPE_PRECEDENCE[item.type_name], item.type_name, item.size))


def _typed_references(
    disassembly: DisassemblyResult,
    data_types: list[DataTypeRecord],
) -> list[TypedReferenceRecord]:
    types = {record.address: record for record in data_types}
    records: list[TypedReferenceRecord] = []
    for reference in disassembly.references:
        target = types.get(reference.target_address)
        records.append(
            TypedReferenceRecord(
                source_address=reference.source_address,
                target_address=reference.target_address,
                kind=reference.kind,
                source_function=reference.source_function,
                target_section=reference.target_section,
                target_type=target.type_name if target is not None else "unknown",
                confidence=target.confidence if target is not None else 0.0,
                evidence=list(target.evidence) if target is not None else [],
            )
        )
    return records


def _typed_call_edges(
    disassembly: DisassemblyResult,
    leaves: dict[int, _Leaf],
) -> list[TypedCallEdge]:
    functions = {function.address: function for function in disassembly.functions}
    edges: dict[tuple[str, str, int, int, str], TypedCallEdge] = {}
    for reference in disassembly.references:
        if reference.kind != "indirect_call" or reference.source_function is None:
            continue
        leaf = leaves.get(reference.target_address)
        if leaf is None or leaf.record.type_name != "function_pointer":
            continue
        target_address = leaf.record.target_address
        if target_address is None:
            continue
        function = functions.get(target_address)
        if function is None:
            continue
        edge = TypedCallEdge(
            source_function=reference.source_function,
            target_function=function.name,
            source_address=reference.source_address,
            target_address=target_address,
            kind="typed_indirect",
            evidence=[
                f"existing indirect_call reference targets slot 0x{reference.target_address:08X}",
                f"slot classified as function_pointer to 0x{target_address:08X}",
            ],
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
        key=lambda item: (item.source_address, item.target_address, item.source_function, item.target_function, item.kind),
    )


def analyze_data_types(
    model: ExecutableModel,
    disassembly: DisassemblyResult,
    elf: ElfImage,
) -> DataTypingResult:
    """Infer conservative, explainable Phase 6C data types without mutating lower-level analysis."""

    warnings: list[str] = []
    seeded = _seed_existing_types(disassembly, elf)
    relocation_slots, relocation_warnings = _safe_relocation_slots(model, elf)
    warnings.extend(relocation_warnings)

    function_targets = _function_targets(model, disassembly)
    strings = {record.address for record in disassembly.strings}
    jump_tables = {record.address for record in disassembly.jump_tables}
    data_symbols = _data_symbol_addresses(disassembly, elf)
    slot_anchors = _reference_slot_anchors(disassembly, elf) | data_symbols | _variable_addresses(model)
    known_data_targets = strings | jump_tables | data_symbols | _variable_addresses(model)

    reserved_ranges = [_range(record) for record in seeded if record.type_name in {"string", "jump_table"}]
    tables, leaves = _scan_pointer_tables(
        elf,
        relocation_slots=relocation_slots,
        function_targets=function_targets,
        known_data_targets=known_data_targets,
        reserved_ranges=reserved_ranges,
    )
    known_data_targets |= {record.address for record in tables}

    standalone = _scan_standalone_leaves(
        elf,
        relocation_slots=relocation_slots,
        function_targets=function_targets,
        known_data_targets=known_data_targets,
        slot_anchors=slot_anchors,
        reserved_ranges=reserved_ranges,
        leaves=leaves,
    )

    anchors = _struct_anchors(model, disassembly, data_symbols, {record.address for record in tables})
    strong_records = [*seeded, *tables]
    structs = _infer_struct_candidates(
        elf,
        anchors=anchors,
        leaves=leaves,
        strong_records=strong_records,
    )
    arrays = _infer_array_candidates(
        elf,
        structs=structs,
        leaves=leaves,
        strong_records=strong_records,
    )

    data_types = _resolve_conflicts(
        [*seeded, *tables, *standalone, *structs, *arrays],
        warnings,
    )
    typed_references = _typed_references(disassembly, data_types)
    call_edges = _typed_call_edges(disassembly, leaves)

    return DataTypingResult(
        source_name=disassembly.source_name,
        data_types=data_types,
        typed_references=typed_references,
        call_edges=call_edges,
        warnings=sorted(set(warnings)),
    )
