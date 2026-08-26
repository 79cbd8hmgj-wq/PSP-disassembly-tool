from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path, PurePosixPath
from typing import Iterable, Protocol

from .disc import DiscResourceRecord
from .resource_formats import ResourceFormatMatch, detect_resource_at, scan_resource_bytes


MAX_EMBEDDED_SCAN_BYTES = 64 * 1024 * 1024
MAX_LOOSE_PROBE_BYTES = 1024 * 1024


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
class GameResourceAnalysis:
    source_name: str
    resources: list[GameResourceRecord] = field(default_factory=list)
    embedded_resources: list[EmbeddedGameResourceRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ContainerInspection:
    parser_name: str
    entries: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ResourceContainerParser(Protocol):
    name: str

    def probe(self, prefix: bytes, path: str) -> float: ...

    def inspect(self, path: Path) -> ContainerInspection: ...


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

    with (reports_dir / "game_resources.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "path",
            "size",
            "detected_format",
            "kind",
            "confidence",
            "embedded_count",
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
                    "extracted_path": record.extracted_path,
                    "evidence": ";".join(record.evidence),
                }
            )


def analyze_game_resources(
    source_name: str,
    output_dir: Path | str,
    resources: Iterable[DiscResourceRecord],
) -> GameResourceAnalysis:
    output = Path(output_dir)
    ordered = sorted(resources, key=lambda item: item.path.casefold())

    # Containment is a game-level integrity property. Validate every supplied
    # extraction path before resource-local error isolation begins.
    resolved: list[tuple[DiscResourceRecord, Path]] = [
        (record, _safe_relative_target(output, record.output_path))
        for record in ordered
    ]

    resource_records: list[GameResourceRecord] = []
    embedded_records: list[EmbeddedGameResourceRecord] = []
    global_warnings: list[str] = []

    for record, path in resolved:
        warnings: list[str] = []
        try:
            if record.size <= MAX_EMBEDDED_SCAN_BYTES:
                data = path.read_bytes()
                loose_match = detect_resource_at(data, 0) if data else None
                matches = scan_resource_bytes(data) if data else []
            else:
                data = None
                prefix = _read_probe(path, record.size)
                loose_match = detect_resource_at(prefix, 0) if prefix else None
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
                warnings=sorted(set(warnings)),
            )
        )

    resource_records.sort(key=lambda item: item.path.casefold())
    embedded_records.sort(key=lambda item: (item.parent_path.casefold(), item.file_offset, item.format))
    analysis = GameResourceAnalysis(
        source_name=source_name,
        resources=resource_records,
        embedded_resources=embedded_records,
        warnings=sorted(set(global_warnings)),
    )
    _write_reports(output, analysis)
    return analysis
