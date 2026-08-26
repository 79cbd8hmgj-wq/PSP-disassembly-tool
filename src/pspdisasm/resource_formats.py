from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import struct


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_GIM_SIGNATURE = b"MIG.00.1PSP"
_ATRAC_CODEC_TAGS = {0x0270, 0x0271}
_PSMF_VERSIONS = {b"0012", b"0013", b"0014", b"0015"}


@dataclass(slots=True)
class ResourceFormatMatch:
    offset: int
    format: str
    kind: str
    size: int | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    extractable: bool = False
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


def _match(
    offset: int,
    *,
    format: str,
    kind: str,
    size: int | None,
    confidence: float,
    evidence: list[str],
    extractable: bool,
    extension: str | None,
    metadata: dict[str, object] | None = None,
) -> ResourceFormatMatch:
    return ResourceFormatMatch(
        offset=offset,
        format=format,
        kind=kind,
        size=size,
        confidence=confidence,
        evidence=evidence,
        extractable=extractable,
        suggested_extension=extension,
        metadata=metadata or {},
    )


def _detect_png(data: bytes, start: int) -> ResourceFormatMatch | None:
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
            return _match(
                start,
                format="png",
                kind="image",
                size=chunk_end - start,
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


def _detect_jpeg(data: bytes, start: int) -> ResourceFormatMatch | None:
    if start + 2 > len(data) or data[start : start + 2] != b"\xff\xd8":
        return None
    cursor = start + 2
    while cursor < len(data):
        marker_info = _jpeg_next_marker(data, cursor)
        if marker_info is None:
            return None
        marker, after_marker = marker_info
        if marker == 0xD9:
            return _match(
                start,
                format="jpeg",
                kind="image",
                size=after_marker - start,
                confidence=1.0,
                evidence=["jpeg_soi", "jpeg_eoi", "bounded_extent"],
                extractable=True,
                extension="jpg",
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
    return None


def _detect_riff(data: bytes, start: int) -> ResourceFormatMatch | None:
    if start + 12 > len(data) or data[start : start + 4] != b"RIFF":
        return None
    declared_size = int.from_bytes(data[start + 4 : start + 8], "little")
    total_size = declared_size + 8
    end = start + total_size
    if total_size < 12 or end > len(data):
        return None
    if data[start + 8 : start + 12] != b"WAVE":
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
    return _match(
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


def _detect_vag(data: bytes, start: int) -> ResourceFormatMatch | None:
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
    return _match(
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


def _detect_gim(data: bytes, start: int) -> ResourceFormatMatch | None:
    if not data.startswith(_GIM_SIGNATURE, start) or start + 16 > len(data):
        return None
    return _match(
        start,
        format="gim",
        kind="image",
        size=None,
        confidence=0.90,
        evidence=["gim_psp_signature", "minimum_header_available"],
        extractable=False,
        extension="gim",
    )


def _detect_psmf(data: bytes, start: int) -> ResourceFormatMatch | None:
    if start + 16 > len(data) or data[start : start + 4] != b"PSMF":
        return None
    version_bytes = data[start + 4 : start + 8]
    if version_bytes not in _PSMF_VERSIONS:
        return None
    stream_offset = int.from_bytes(data[start + 8 : start + 12], "big")
    stream_size = int.from_bytes(data[start + 12 : start + 16], "big")
    if stream_offset == 0 or stream_offset & 0x7FF or stream_size <= 0:
        return None

    total_size = stream_offset + stream_size
    bounded = start + total_size <= len(data)
    evidence = ["psmf_signature", "psmf_version", "psmf_stream_offset", "psmf_stream_size"]
    if bounded:
        evidence.append("bounded_declared_extent")
    return _match(
        start,
        format="pmf",
        kind="video",
        size=total_size if bounded else None,
        confidence=1.0 if bounded else 0.95,
        evidence=evidence,
        extractable=bounded,
        extension="pmf",
        metadata={
            "version": version_bytes.decode("ascii"),
            "stream_offset": stream_offset,
            "stream_size": stream_size,
        },
    )


Detector = Callable[[bytes, int], ResourceFormatMatch | None]
_DETECTORS: tuple[Detector, ...] = (
    _detect_png,
    _detect_jpeg,
    _detect_riff,
    _detect_vag,
    _detect_gim,
    _detect_psmf,
)


def detect_resource_at(data: bytes, offset: int = 0) -> ResourceFormatMatch | None:
    if offset < 0 or offset >= len(data):
        return None
    candidates: list[ResourceFormatMatch] = []
    for detector in _DETECTORS:
        try:
            candidate = detector(data, offset)
        except (IndexError, OverflowError, struct.error, ValueError):
            candidate = None
        if candidate is not None:
            candidates.append(candidate)
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            -item.confidence,
            0 if item.extractable and item.size else 1,
            item.format,
        )
    )
    return candidates[0]


def scan_resource_bytes(data: bytes, *, minimum_confidence: float = 0.90) -> list[ResourceFormatMatch]:
    matches: list[ResourceFormatMatch] = []
    cursor = 0
    while cursor < len(data):
        candidate = detect_resource_at(data, cursor)
        if candidate is None or candidate.confidence < minimum_confidence:
            cursor += 1
            continue
        matches.append(candidate)
        if candidate.extractable and candidate.size is not None and candidate.size > 0:
            cursor += candidate.size
        else:
            cursor += 1
    return matches
