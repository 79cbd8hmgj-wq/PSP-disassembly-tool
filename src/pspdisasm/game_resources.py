from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path, PurePosixPath
from typing import Iterable

from .disc import DiscResourceRecord
from .resource_containers import (
    MAX_CONTAINER_ENTRIES,
    ContainerCandidateProfile,
    ContainerFamily,
    ContainerInspection,
    ResourceContainerParser,
    group_container_families,
    profile_container_candidate,
    select_container_parser,
)
from .resource_formats import ResourceFormatMatch, detect_resource_at, scan_resource_bytes


MAX_EMBEDDED_SCAN_BYTES = 64 * 1024 * 1024
MAX_LOOSE_PROBE_BYTES = 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024


@dataclass(slots=True)
class GameResourceRecord:
    path: str
    extracted_path: str
    size: int
    detected_format: str = "unknown"
    kind: str = "unknown"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    embedded_count: int = 0
    container_family: str | None = None
    container_parser: str | None = None
    container_entry_count: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EmbeddedGameResourceRecord:
    parent_path: str
    file_offset: int
    format: str
    kind: str
    size: int | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    extracted_path: str | None = None
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ContainerInspectionRecord:
    parent_path: str
    parser_name: str
    format_name: str
    confidence: float
    entry_count: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ContainerEntryRecord:
    parent_path: str
    parser_name: str
    inner_path: str
    offset: int
    size: int
    extracted_path: str
    detected_format: str = "unknown"
    kind: str = "unknown"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GameResourceAnalysis:
    source_name: str
    resources: list[GameResourceRecord] = field(default_factory=list)
    embedded_resources: list[EmbeddedGameResourceRecord] = field(default_factory=list)
    container_candidates: list[ContainerCandidateProfile] = field(default_factory=list)
    container_families: list[ContainerFamily] = field(default_factory=list)
    container_inspections: list[ContainerInspectionRecord] = field(default_factory=list)
    container_entries: list[ContainerEntryRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# Phase 7D intentionally ships no speculative proprietary parser. The public
# parser protocol is imported above so callers can provide evidence-backed
# parsers programmatically without changing orchestration.
_CONTAINER_PARSERS: tuple[ResourceContainerParser, ...] = ()


def _safe_relative_target(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"Unsafe game resource path: {relative_path}")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*pure.parts)).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"Unsafe game resource path: {relative_path}")
    return target


def _safe_container_entry_target(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if not relative_path or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"Unsafe container entry path: {relative_path}")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*pure.parts)).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"Unsafe container entry path: {relative_path}")
    return target


def _relative_display(path: Path, output: Path) -> str:
    return str(path.relative_to(output.resolve()))


def _read_probe(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(min(size, MAX_LOOSE_PROBE_BYTES))


def _known_file_fields(match: ResourceFormatMatch | None) -> tuple[str, str, float, list[str], str | None, dict[str, object]]:
    if match is None or match.offset != 0 or match.confidence < 0.90:
        return "unknown", "unknown", 0.0, [], None, {}
    return (
        match.format,
        match.kind,
        match.confidence,
        list(match.evidence),
        match.suggested_extension,
        dict(match.metadata),
    )


def _embedded_destination(output: Path, match: ResourceFormatMatch, parent_path: str) -> Path:
    extension = match.suggested_extension or match.format
    filename = f"{match.offset:08X}_{match.format}.{extension}"
    return _safe_relative_target(output / "resources" / "embedded", f"{parent_path}/{filename}")


def _write_embedded(
    output: Path,
    parent_path: str,
    data: bytes,
    match: ResourceFormatMatch,
) -> str | None:
    if not match.extractable or match.size is None or match.size <= 0:
        return None
    end = match.offset + match.size
    if match.offset < 0 or end > len(data):
        return None
    destination = _embedded_destination(output, match, parent_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data[match.offset:end])
    return _relative_display(destination, output)


def _container_destination(output: Path, parent_path: str, inner_path: str) -> Path:
    parent_root = _safe_relative_target(output / "resources" / "containers", parent_path)
    return _safe_container_entry_target(parent_root, inner_path)


def _copy_entry_range(source: Path, destination: Path, offset: int, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    with source.open("rb") as src, destination.open("wb") as dst:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(remaining, _COPY_CHUNK_BYTES))
            if not chunk:
                raise OSError(
                    f"Unexpected end of container while extracting range 0x{offset:X}+0x{size:X}"
                )
            dst.write(chunk)
            remaining -= len(chunk)


def _classify_extracted_entry(path: Path, size: int) -> tuple[str, str, float, list[str], str | None, dict[str, object]]:
    if size <= MAX_EMBEDDED_SCAN_BYTES:
        data = path.read_bytes()
    else:
        data = _read_probe(path, size)
    match = detect_resource_at(data, 0) if data else None
    return _known_file_fields(match)


def _write_reports(output: Path, analysis: GameResourceAnalysis) -> None:
    metadata_dir = output / "metadata"
    reports_dir = output / "reports"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    (metadata_dir / "game_resources.json").write_text(
        json.dumps(asdict(analysis), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (metadata_dir / "embedded_resources.json").write_text(
        json.dumps([asdict(record) for record in analysis.embedded_resources], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (metadata_dir / "container_candidates.json").write_text(
        json.dumps([asdict(record) for record in analysis.container_candidates], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (metadata_dir / "container_inspections.json").write_text(
        json.dumps([asdict(record) for record in analysis.container_inspections], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with (reports_dir / "game_resources.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "path",
            "size",
            "detected_format",
            "kind",
            "confidence",
            "embedded_count",
            "container_family",
            "container_parser",
            "container_entry_count",
            "extracted_path",
            "evidence",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in analysis.resources:
            writer.writerow(
                {
                    "path": record.path,
                    "size": record.size,
                    "detected_format": record.detected_format,
                    "kind": record.kind,
                    "confidence": f"{record.confidence:.2f}",
                    "embedded_count": record.embedded_count,
                    "container_family": record.container_family or "",
                    "container_parser": record.container_parser or "",
                    "container_entry_count": record.container_entry_count,
                    "extracted_path": record.extracted_path,
                    "evidence": ";".join(record.evidence),
                }
            )

    with (reports_dir / "container_candidates.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "path",
            "size",
            "suffix",
            "family_key",
            "prefix_hex",
            "prefix_ascii",
            "sample_entropy",
            "embedded_count",
            "bounded_embedded_bytes",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in analysis.container_candidates:
            writer.writerow(
                {
                    "path": record.path,
                    "size": record.size,
                    "suffix": record.suffix,
                    "family_key": record.family_key,
                    "prefix_hex": record.prefix_hex,
                    "prefix_ascii": record.prefix_ascii,
                    "sample_entropy": f"{record.sample_entropy:.6f}",
                    "embedded_count": record.embedded_count,
                    "bounded_embedded_bytes": record.bounded_embedded_bytes,
                }
            )

    with (reports_dir / "container_entries.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "parent_path",
            "parser_name",
            "inner_path",
            "offset",
            "size",
            "detected_format",
            "kind",
            "confidence",
            "extracted_path",
            "evidence",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in analysis.container_entries:
            writer.writerow(
                {
                    "parent_path": record.parent_path,
                    "parser_name": record.parser_name,
                    "inner_path": record.inner_path,
                    "offset": record.offset,
                    "size": record.size,
                    "detected_format": record.detected_format,
                    "kind": record.kind,
                    "confidence": f"{record.confidence:.2f}",
                    "extracted_path": record.extracted_path,
                    "evidence": ";".join(record.evidence),
                }
            )


def analyze_game_resources(
    source_name: str,
    output_dir: Path | str,
    resources: Iterable[DiscResourceRecord],
    *,
    container_parsers: Iterable[ResourceContainerParser] = _CONTAINER_PARSERS,
) -> GameResourceAnalysis:
    output = Path(output_dir)
    ordered = sorted(resources, key=lambda item: item.path.casefold())
    parsers = tuple(container_parsers)

    # Containment is a game-level integrity property. Validate every supplied
    # extraction path before resource-local error isolation begins.
    resolved: list[tuple[DiscResourceRecord, Path]] = [
        (record, _safe_relative_target(output, record.output_path))
        for record in ordered
    ]

    resource_records: list[GameResourceRecord] = []
    embedded_records: list[EmbeddedGameResourceRecord] = []
    candidate_profiles: list[ContainerCandidateProfile] = []
    inspection_records: list[ContainerInspectionRecord] = []
    container_entry_records: list[ContainerEntryRecord] = []
    global_warnings: list[str] = []

    for record, path in resolved:
        warnings: list[str] = []
        probe_prefix = b""
        try:
            if record.size <= MAX_EMBEDDED_SCAN_BYTES:
                data = path.read_bytes()
                probe_prefix = data[:MAX_LOOSE_PROBE_BYTES]
                loose_match = detect_resource_at(data, 0) if data else None
                matches = scan_resource_bytes(data) if data else []
            else:
                data = None
                probe_prefix = _read_probe(path, record.size)
                loose_match = detect_resource_at(probe_prefix, 0) if probe_prefix else None
                matches = []
                warning = (
                    f"Embedded scanning skipped for {record.path}: file size {record.size} "
                    f"exceeds {MAX_EMBEDDED_SCAN_BYTES} byte safety ceiling"
                )
                warnings.append(warning)
                global_warnings.append(warning)
        except OSError as exc:
            loose_match = None
            matches = []
            data = None
            warning = f"Unable to read resource {record.path}: {exc}"
            warnings.append(warning)
            global_warnings.append(warning)

        detected_format, kind, confidence, evidence, extension, metadata = _known_file_fields(loose_match)
        embedded_for_file: list[EmbeddedGameResourceRecord] = []

        if data is not None:
            for match in matches:
                # A recognized loose file is not also an embedded copy of itself.
                if match.offset == 0 and loose_match is not None and match.format == loose_match.format:
                    continue
                extracted_path: str | None = None
                try:
                    extracted_path = _write_embedded(output, record.path, data, match)
                except OSError as exc:
                    warning = (
                        f"Unable to extract embedded {match.format} at 0x{match.offset:X} "
                        f"from {record.path}: {exc}"
                    )
                    warnings.append(warning)
                    global_warnings.append(warning)
                embedded_for_file.append(
                    EmbeddedGameResourceRecord(
                        parent_path=record.path,
                        file_offset=match.offset,
                        format=match.format,
                        kind=match.kind,
                        size=match.size,
                        confidence=match.confidence,
                        evidence=list(match.evidence),
                        extracted_path=extracted_path,
                        suggested_extension=match.suggested_extension,
                        metadata=dict(match.metadata),
                    )
                )

        embedded_for_file.sort(key=lambda item: (item.file_offset, item.format))
        embedded_records.extend(embedded_for_file)

        container_family: str | None = None
        container_parser_name: str | None = None
        container_entry_count = 0

        if detected_format == "unknown":
            bounded_embedded_bytes = sum(
                embedded.size or 0
                for embedded in embedded_for_file
                if embedded.size is not None and embedded.size > 0
            )
            try:
                profile = profile_container_candidate(
                    path,
                    record.path,
                    embedded_count=len(embedded_for_file),
                    bounded_embedded_bytes=bounded_embedded_bytes,
                )
            except OSError as exc:
                warning = f"Unable to profile container candidate {record.path}: {exc}"
                warnings.append(warning)
                global_warnings.append(warning)
                profile = None
            if profile is not None:
                candidate_profiles.append(profile)
                container_family = profile.family_key

            if parsers and probe_prefix:
                parser, selected_confidence, probe_warnings = select_container_parser(
                    probe_prefix,
                    record.path,
                    parsers,
                )
                warnings.extend(probe_warnings)
                global_warnings.extend(probe_warnings)
                if parser is not None:
                    parser_name = str(getattr(parser, "name", parser.__class__.__name__))
                    try:
                        inspection = parser.inspect(path)
                    except Exception as exc:
                        warning = f"Container parser {parser_name} inspect failed for {record.path}: {exc}"
                        warnings.append(warning)
                        global_warnings.append(warning)
                    else:
                        container_parser_name = parser_name
                        inspection_warnings = list(inspection.warnings)
                        entries = list(inspection.entries)
                        if len(entries) > MAX_CONTAINER_ENTRIES:
                            warning = (
                                f"Container parser {parser_name} returned {len(entries)} entries for "
                                f"{record.path}; only the first {MAX_CONTAINER_ENTRIES} are accepted"
                            )
                            inspection_warnings.append(warning)
                            warnings.append(warning)
                            global_warnings.append(warning)
                            entries = entries[:MAX_CONTAINER_ENTRIES]

                        accepted_for_container = 0
                        for entry in entries:
                            # Inner paths are an integrity boundary and are therefore
                            # validated before any parser-local range/error isolation.
                            destination = _container_destination(output, record.path, entry.path)
                            if entry.offset < 0 or entry.size <= 0 or entry.offset + entry.size > record.size:
                                warning = (
                                    f"Container entry {entry.path} from {record.path} is out of bounds: "
                                    f"offset={entry.offset}, size={entry.size}, parent_size={record.size}"
                                )
                                inspection_warnings.append(warning)
                                warnings.append(warning)
                                global_warnings.append(warning)
                                continue

                            try:
                                _copy_entry_range(path, destination, entry.offset, entry.size)
                                (
                                    entry_format,
                                    entry_kind,
                                    entry_confidence,
                                    entry_evidence,
                                    entry_extension,
                                    entry_metadata,
                                ) = _classify_extracted_entry(destination, entry.size)
                            except OSError as exc:
                                warning = (
                                    f"Unable to extract container entry {entry.path} from {record.path}: {exc}"
                                )
                                inspection_warnings.append(warning)
                                warnings.append(warning)
                                global_warnings.append(warning)
                                continue

                            combined_metadata = dict(entry.metadata)
                            combined_metadata.update(entry_metadata)
                            container_entry_records.append(
                                ContainerEntryRecord(
                                    parent_path=record.path,
                                    parser_name=parser_name,
                                    inner_path=entry.path,
                                    offset=entry.offset,
                                    size=entry.size,
                                    extracted_path=_relative_display(destination, output),
                                    detected_format=entry_format,
                                    kind=entry_kind,
                                    confidence=entry_confidence,
                                    evidence=entry_evidence,
                                    suggested_extension=entry_extension,
                                    metadata=combined_metadata,
                                )
                            )
                            accepted_for_container += 1

                        inspection_records.append(
                            ContainerInspectionRecord(
                                parent_path=record.path,
                                parser_name=parser_name,
                                format_name=inspection.format_name,
                                confidence=selected_confidence,
                                entry_count=accepted_for_container,
                                warnings=sorted(set(inspection_warnings)),
                            )
                        )
                        container_entry_count = accepted_for_container

        resource_records.append(
            GameResourceRecord(
                path=record.path,
                extracted_path=record.output_path,
                size=record.size,
                detected_format=detected_format,
                kind=kind,
                confidence=confidence,
                evidence=evidence,
                suggested_extension=extension,
                metadata=metadata,
                embedded_count=len(embedded_for_file),
                container_family=container_family,
                container_parser=container_parser_name,
                container_entry_count=container_entry_count,
                warnings=sorted(set(warnings)),
            )
        )

    resource_records.sort(key=lambda item: item.path.casefold())
    embedded_records.sort(key=lambda item: (item.parent_path.casefold(), item.file_offset, item.format))
    candidate_profiles.sort(key=lambda item: item.path.casefold())
    families = group_container_families(candidate_profiles)
    inspection_records.sort(key=lambda item: (item.parent_path.casefold(), item.parser_name.casefold()))
    container_entry_records.sort(
        key=lambda item: (
            item.parent_path.casefold(),
            item.parser_name.casefold(),
            item.offset,
            item.inner_path.casefold(),
        )
    )
    analysis = GameResourceAnalysis(
        source_name=source_name,
        resources=resource_records,
        embedded_resources=embedded_records,
        container_candidates=candidate_profiles,
        container_families=families,
        container_inspections=inspection_records,
        container_entries=container_entry_records,
        warnings=sorted(set(global_warnings)),
    )
    _write_reports(output, analysis)
    return analysis
