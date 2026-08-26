from __future__ import annotations

from .model import (
    AssetDiscoveryResult,
    AssetRecord,
    AssetReferenceRecord,
    DataTypingResult,
    DisassemblyResult,
    ElfImage,
    ExecutableModel,
    Section,
)
from .resource_formats import scan_resource_bytes

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_NOBITS = 8


def _eligible_sections(elf: ElfImage) -> list[Section]:
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


def _scan_section(elf: ElfImage, section: Section) -> tuple[list[AssetRecord], list[str]]:
    end = section.offset + section.size
    if section.offset < 0 or end > len(elf.raw_data):
        return [], [f"Skipped out-of-bounds asset section {section.name or section.index}"]
    data = elf.raw_data[section.offset:end]
    assets = [
        AssetRecord(
            address=section.addr + match.offset,
            file_offset=section.offset + match.offset,
            section=section.name,
            format=match.format,
            kind=match.kind,
            size=match.size,
            confidence=match.confidence,
            evidence=list(match.evidence),
            extractable=match.extractable,
            suggested_extension=match.suggested_extension,
            metadata=dict(match.metadata),
        )
        for match in scan_resource_bytes(data)
    ]
    return assets, []


def _merge_reference(
    selected: dict[tuple[int, int, str], AssetReferenceRecord],
    candidate: AssetReferenceRecord,
) -> None:
    key = (candidate.source_address, candidate.asset_address, candidate.reference_kind)
    current = selected.get(key)
    if current is None:
        selected[key] = candidate
        return
    selected[key] = AssetReferenceRecord(
        source_address=current.source_address,
        asset_address=current.asset_address,
        source_function=current.source_function or candidate.source_function,
        reference_kind=current.reference_kind,
        asset_format=current.asset_format,
        confidence=max(current.confidence, candidate.confidence),
        evidence=sorted(set(current.evidence) | set(candidate.evidence)),
    )


def _link_references(
    assets: list[AssetRecord],
    disassembly: DisassemblyResult,
    data_typing: DataTypingResult,
) -> list[AssetReferenceRecord]:
    assets_by_address = {asset.address: asset for asset in assets}
    selected: dict[tuple[int, int, str], AssetReferenceRecord] = {}

    for reference in sorted(
        disassembly.references,
        key=lambda item: (item.source_address, item.target_address, item.kind, item.source_function or ""),
    ):
        asset = assets_by_address.get(reference.target_address)
        if asset is None:
            continue
        _merge_reference(
            selected,
            AssetReferenceRecord(
                source_address=reference.source_address,
                asset_address=asset.address,
                source_function=reference.source_function,
                reference_kind="direct",
                asset_format=asset.format,
                confidence=asset.confidence,
                evidence=["asset_exact_start", "reference_record"],
            ),
        )

    for reference in sorted(
        data_typing.typed_references,
        key=lambda item: (item.source_address, item.target_address, item.kind, item.source_function or ""),
    ):
        asset = assets_by_address.get(reference.target_address)
        if asset is None:
            continue
        _merge_reference(
            selected,
            AssetReferenceRecord(
                source_address=reference.source_address,
                asset_address=asset.address,
                source_function=reference.source_function,
                reference_kind="typed",
                asset_format=asset.format,
                confidence=min(asset.confidence, reference.confidence),
                evidence=sorted(set(reference.evidence) | {"asset_exact_start", "typed_reference"}),
            ),
        )

    for record in sorted(data_typing.data_types, key=lambda item: (item.address, item.type_name)):
        if record.target_address is None:
            continue
        asset = assets_by_address.get(record.target_address)
        if asset is None:
            continue
        _merge_reference(
            selected,
            AssetReferenceRecord(
                source_address=record.address,
                asset_address=asset.address,
                source_function=None,
                reference_kind="typed_data",
                asset_format=asset.format,
                confidence=min(asset.confidence, record.confidence),
                evidence=sorted(set(record.evidence) | {"asset_exact_start", "typed_data"}),
            ),
        )

    return sorted(
        selected.values(),
        key=lambda item: (item.asset_address, item.source_address, item.reference_kind, item.asset_format),
    )


def analyze_assets(
    model: ExecutableModel,
    disassembly: DisassemblyResult,
    data_typing: DataTypingResult,
    elf: ElfImage,
) -> AssetDiscoveryResult:
    assets: list[AssetRecord] = []
    warnings: list[str] = []
    for section in _eligible_sections(elf):
        section_assets, section_warnings = _scan_section(elf, section)
        assets.extend(section_assets)
        warnings.extend(section_warnings)
    assets.sort(key=lambda item: (item.address, item.format))
    references = _link_references(assets, disassembly, data_typing)
    return AssetDiscoveryResult(
        source_name=model.source_name,
        assets=assets,
        references=references,
        warnings=sorted(set(warnings)),
    )
