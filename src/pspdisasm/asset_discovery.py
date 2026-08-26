from __future__ import annotations

from collections.abc import Callable
import struct

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

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_NOBITS = 8

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_GIM_SIGNATURE = b"MIG.00.1PSP"
_ATRAC_CODEC_TAGS = {0x0270, 0x0271}


def _record(
    section: Section,
    start: int,
    *,
    format: str,
    kind: str,
    size: int | None,
    confidence: float,
    evidence: list[str],
    extractable: bool,
    extension: str | None,
    metadata: dict[str, object] | None = None,
) -> AssetRecord:
    return AssetRecord(
        address=section.addr + start,
        file_offset=section.offset + start,
        section=section.name,
        format=format,
        kind=kind,
        size=size,
        confidence=confidence,
        evidence=evidence,
        extractable=extractable,
        suggested_extension=extension,
        metadata=metadata or {},
    )


def _detect_png(data: bytes, section: Section, start: int) -> AssetRecord | None:
    if not data.startswith(_PNG_SIGNATURE, start):
        return None
    cursor = start + len(_PNG_SIGNATURE)
    chunk_count = 0
    while cursor + 12 <= len(data):
        length = int.from_bytes(data[cursor : cursor + 4], "big")
        chunk_type = data[cursor + 4 : cursor + 8]
        chunk_end = cursor + 12 + length
        if chunk_end > len(data):
            return None
        chunk_count += 1
        if chunk_type == b"IEND":
            if length != 0:
                return None
            size = chunk_end - start
            return _record(
                section,
                start,
                format="png",
                kind="image",
                size=size,
                confidence=1.0,
                evidence=["png_signature", "png_iend", "bounded_extent"],
                extractable=True,
                extension="png",
                metadata={"chunk_count": chunk_count},
            )
        cursor = chunk_end
    return None


def _jpeg_next_marker(data: bytes, cursor: int) -> tuple[int, int] | None:
    while cursor < len(data):
        if data[cursor] != 0xFF:
            cursor += 1
            continue
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            return None
        marker = data[cursor]
        cursor += 1
        if marker == 0x00:
            continue
        return marker, cursor
    return None


def _detect_jpeg(data: bytes, section: Section, start: int) -> AssetRecord | None:
    if start + 2 > len(data) or data[start : start + 2] != b"\xff\xd8":
        return None
    cursor = start + 2
    in_scan = False
    while cursor < len(data):
        if in_scan:
            marker_info = _jpeg_next_marker(data, cursor)
        else:
            if cursor >= len(data) or data[cursor] != 0xFF:
                return None
            marker_info = _jpeg_next_marker(data, cursor)
        if marker_info is None:
            return None
        marker, after_marker = marker_info
        if marker == 0xD9:
            size = after_marker - start
            return _record(
                section,
                start,
                format="jpeg",
                kind="image",
                size=size,
                confidence=1.0,
                evidence=["jpeg_soi", "jpeg_eoi", "bounded_extent"],
                extractable=True,
                extension="jpg",
                metadata={},
            )
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            cursor = after_marker
            continue
        if marker == 0xD8:
            return None
        if after_marker + 2 > len(data):
            return None
        segment_length = int.from_bytes(data[after_marker : after_marker + 2], "big")
        if segment_length < 2:
            return None
        segment_end = after_marker + segment_length
        if segment_end > len(data):
            return None
        cursor = segment_end
        in_scan = marker == 0xDA
    return None


def _detect_riff(data: bytes, section: Section, start: int) -> AssetRecord | None:
    if start + 12 > len(data) or data[start : start + 4] != b"RIFF":
        return None
    declared_size = int.from_bytes(data[start + 4 : start + 8], "little")
    total_size = declared_size + 8
    end = start + total_size
    if total_size < 12 or end > len(data):
        return None
    form = data[start + 8 : start + 12]
    if form != b"WAVE":
        return None

    cursor = start + 12
    codec_tag: int | None = None
    chunk_count = 0
    while cursor < end:
        if cursor + 8 > end:
            return None
        chunk_id = data[cursor : cursor + 4]
        chunk_size = int.from_bytes(data[cursor + 4 : cursor + 8], "little")
        chunk_start = cursor + 8
        chunk_end = chunk_start + chunk_size
        if chunk_end > end:
            return None
        chunk_count += 1
        if chunk_id == b"fmt " and chunk_size >= 2:
            codec_tag = int.from_bytes(data[chunk_start : chunk_start + 2], "little")
        cursor = chunk_end + (chunk_size & 1)
        if cursor > end:
            return None

    is_atrac = codec_tag in _ATRAC_CODEC_TAGS
    evidence = ["riff_signature", "wave_form", "bounded_declared_extent"]
    if is_atrac:
        evidence.append("atrac_codec")
    metadata: dict[str, object] = {"chunk_count": chunk_count}
    if codec_tag is not None:
        metadata["codec_tag"] = codec_tag
    return _record(
        section,
        start,
        format="at3" if is_atrac else "wav",
        kind="audio",
        size=total_size,
        confidence=1.0,
        evidence=evidence,
        extractable=True,
        extension="at3" if is_atrac else "wav",
        metadata=metadata,
    )


def _detect_vag(data: bytes, section: Section, start: int) -> AssetRecord | None:
    header_size = 0x30
    if start + header_size > len(data) or data[start : start + 4] != b"VAGp":
        return None
    version = int.from_bytes(data[start + 4 : start + 8], "big")
    payload_size = int.from_bytes(data[start + 12 : start + 16], "big")
    sample_rate = int.from_bytes(data[start + 16 : start + 20], "big")
    if version == 0 or payload_size <= 0 or not 4000 <= sample_rate <= 192000:
        return None
    total_size = header_size + payload_size
    if start + total_size > len(data):
        return None
    return _record(
        section,
        start,
        format="vag",
        kind="audio",
        size=total_size,
        confidence=1.0,
        evidence=["vag_signature", "vag_header_fields", "bounded_declared_extent"],
        extractable=True,
        extension="vag",
        metadata={"version": version, "sample_rate": sample_rate, "payload_size": payload_size},
    )


def _detect_gim(data: bytes, section: Section, start: int) -> AssetRecord | None:
    if not data.startswith(_GIM_SIGNATURE, start):
        return None
    if start + 16 > len(data):
        return None
    return _record(
        section,
        start,
        format="gim",
        kind="image",
        size=None,
        confidence=0.90,
        evidence=["gim_psp_signature", "minimum_header_available"],
        extractable=False,
        extension="gim",
        metadata={},
    )


def _detect_psmf(data: bytes, section: Section, start: int) -> AssetRecord | None:
    if start + 16 > len(data) or data[start : start + 4] != b"PSMF":
        return None
    return _record(
        section,
        start,
        format="pmf",
        kind="video",
        size=None,
        confidence=0.90,
        evidence=["psmf_signature", "minimum_header_available"],
        extractable=False,
        extension="pmf",
        metadata={},
    )


_DETECTORS: tuple[Callable[[bytes, Section, int], AssetRecord | None], ...] = (
    _detect_png,
    _detect_jpeg,
    _detect_riff,
    _detect_vag,
    _detect_gim,
    _detect_psmf,
)


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
    assets: list[AssetRecord] = []
    cursor = 0
    while cursor < len(data):
        candidates: list[AssetRecord] = []
        for detector in _DETECTORS:
            try:
                candidate = detector(data, section, cursor)
            except (IndexError, OverflowError, struct.error, ValueError):
                candidate = None
            if candidate is not None and candidate.confidence >= 0.90:
                candidates.append(candidate)
        if not candidates:
            cursor += 1
            continue
        candidates.sort(
            key=lambda item: (
                -item.confidence,
                0 if item.extractable and item.size else 1,
                item.format,
            )
        )
        accepted = candidates[0]
        assets.append(accepted)
        if accepted.extractable and accepted.size is not None and accepted.size > 0:
            cursor += accepted.size
        else:
            cursor += 1
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
