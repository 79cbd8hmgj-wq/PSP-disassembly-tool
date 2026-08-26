from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import math
from pathlib import Path, PurePosixPath
from typing import Iterable, Protocol, runtime_checkable


PREFIX_FINGERPRINT_BYTES = 16
FAMILY_PREFIX_BYTES = 4
ENTROPY_SAMPLE_BYTES = 64 * 1024
DEFAULT_PARSER_THRESHOLD = 0.90
MAX_CONTAINER_ENTRIES = 4096


@dataclass(slots=True)
class ContainerCandidateProfile:
    path: str
    size: int
    suffix: str
    prefix_hex: str
    prefix_ascii: str
    sample_entropy: float
    embedded_count: int = 0
    bounded_embedded_bytes: int = 0
    family_key: str = ""


@dataclass(slots=True)
class ContainerFamily:
    family_key: str
    suffix: str
    prefix_hex: str
    member_paths: list[str] = field(default_factory=list)
    member_count: int = 0
    total_size: int = 0


@dataclass(slots=True)
class ContainerEntry:
    path: str
    offset: int
    size: int
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ContainerInspection:
    parser_name: str
    format_name: str
    confidence: float
    entries: list[ContainerEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@runtime_checkable
class ResourceContainerParser(Protocol):
    name: str

    def probe(self, prefix: bytes, path: str) -> float: ...

    def inspect(self, path: Path) -> ContainerInspection: ...


def _read_prefix_and_sample(path: Path) -> tuple[bytes, bytes]:
    with path.open("rb") as handle:
        sample = handle.read(ENTROPY_SAMPLE_BYTES)
    return sample[:PREFIX_FINGERPRINT_BYTES], sample


def _ascii_view(data: bytes) -> str:
    return "".join(chr(value) if 0x20 <= value <= 0x7E else "." for value in data)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _family_key(logical_path: str, prefix: bytes) -> tuple[str, str, str]:
    suffix = PurePosixPath(logical_path).suffix.lower()
    family_prefix = prefix[:FAMILY_PREFIX_BYTES].hex()
    return f"{suffix or '<none>'}:{family_prefix}", suffix, family_prefix


def profile_container_candidate(
    path: Path | str,
    logical_path: str,
    *,
    embedded_count: int = 0,
    bounded_embedded_bytes: int = 0,
) -> ContainerCandidateProfile:
    source = Path(path)
    prefix, sample = _read_prefix_and_sample(source)
    family_key, suffix, _ = _family_key(logical_path, prefix)
    return ContainerCandidateProfile(
        path=logical_path,
        size=source.stat().st_size,
        suffix=suffix,
        prefix_hex=prefix.hex(),
        prefix_ascii=_ascii_view(prefix),
        sample_entropy=_shannon_entropy(sample),
        embedded_count=max(0, int(embedded_count)),
        bounded_embedded_bytes=max(0, int(bounded_embedded_bytes)),
        family_key=family_key,
    )


def group_container_families(
    profiles: Iterable[ContainerCandidateProfile],
) -> list[ContainerFamily]:
    grouped: dict[str, list[ContainerCandidateProfile]] = {}
    for profile in profiles:
        grouped.setdefault(profile.family_key, []).append(profile)

    families: list[ContainerFamily] = []
    for family_key in sorted(grouped, key=str.casefold):
        members = sorted(grouped[family_key], key=lambda item: item.path.casefold())
        first = members[0]
        families.append(
            ContainerFamily(
                family_key=family_key,
                suffix=first.suffix,
                prefix_hex=first.prefix_hex[: FAMILY_PREFIX_BYTES * 2],
                member_paths=[member.path for member in members],
                member_count=len(members),
                total_size=sum(member.size for member in members),
            )
        )
    return families


def select_container_parser(
    prefix: bytes,
    logical_path: str,
    parsers: Iterable[ResourceContainerParser],
    *,
    threshold: float = DEFAULT_PARSER_THRESHOLD,
) -> tuple[ResourceContainerParser | None, float, list[str]]:
    warnings: list[str] = []
    accepted: list[tuple[float, str, int, ResourceContainerParser]] = []

    for index, parser in enumerate(parsers):
        parser_name = str(getattr(parser, "name", parser.__class__.__name__))
        try:
            score = float(parser.probe(prefix, logical_path))
        except Exception as exc:
            warnings.append(f"Container parser {parser_name} probe failed for {logical_path}: {exc}")
            continue
        if not math.isfinite(score) or score < 0.0 or score > 1.0:
            warnings.append(
                f"Container parser {parser_name} returned invalid probe confidence {score!r} "
                f"for {logical_path}"
            )
            continue
        if score >= threshold:
            accepted.append((score, parser_name, index, parser))

    if not accepted:
        return None, 0.0, warnings

    accepted.sort(key=lambda item: (-item[0], item[1].casefold(), item[1], item[2]))
    score, _, _, parser = accepted[0]
    return parser, score, warnings
