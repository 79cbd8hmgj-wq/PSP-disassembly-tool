from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .errors import ParseError


ISO_SECTOR_SIZE = 2048
ISO_PRIMARY_VOLUME_DESCRIPTOR_SECTOR = 16


@dataclass(slots=True)
class GameImageFile:
    path: str
    size: int
    extent: int
    is_directory: bool


@dataclass(slots=True)
class GameExecutable:
    path: str
    size: int
    kind: str


@dataclass(slots=True)
class GameImageAnalysis:
    source_name: str
    image_format: str
    logical_size: int
    sector_size: int
    files: list[GameImageFile] = field(default_factory=list)
    executables: list[GameExecutable] = field(default_factory=list)
    boot_path: str | None = None
    param_sfo: dict[str, object] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        return len(self.files)


class _RawImageReader:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.size = path.stat().st_size
        self._stream: BinaryIO = path.open("rb")

    def close(self) -> None:
        self._stream.close()

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ParseError("Negative image read is invalid")
        if offset >= self.size or size == 0:
            return b""
        self._stream.seek(offset)
        return self._stream.read(min(size, self.size - offset))


@dataclass(slots=True)
class _IsoDirectoryRecord:
    extent: int
    size: int
    is_directory: bool
    identifier: bytes


def _read_u32_le(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ParseError("Truncated ISO9660 numeric field")
    return int.from_bytes(data[offset : offset + 4], "little")


def _parse_directory_record(data: bytes, offset: int) -> tuple[_IsoDirectoryRecord | None, int]:
    if offset >= len(data):
        return None, len(data)
    length = data[offset]
    if length == 0:
        next_sector = ((offset // ISO_SECTOR_SIZE) + 1) * ISO_SECTOR_SIZE
        return None, min(next_sector, len(data))
    if length < 34 or offset + length > len(data):
        raise ParseError("Malformed ISO9660 directory record")

    record = data[offset : offset + length]
    identifier_length = record[32]
    if 33 + identifier_length > len(record):
        raise ParseError("Truncated ISO9660 file identifier")

    parsed = _IsoDirectoryRecord(
        extent=_read_u32_le(record, 2),
        size=_read_u32_le(record, 10),
        is_directory=bool(record[25] & 0x02),
        identifier=record[33 : 33 + identifier_length],
    )
    return parsed, offset + length


def _clean_identifier(identifier: bytes) -> str | None:
    if identifier in (b"\x00", b"\x01"):
        return None
    try:
        name = identifier.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ParseError("ISO9660 file identifier is not ASCII") from exc
    if ";" in name:
        base, version = name.rsplit(";", 1)
        if version.isdigit():
            name = base
    return name


def _parse_primary_volume(reader: _RawImageReader) -> _IsoDirectoryRecord:
    offset = ISO_PRIMARY_VOLUME_DESCRIPTOR_SECTOR * ISO_SECTOR_SIZE
    descriptor = reader.read(offset, ISO_SECTOR_SIZE)
    if len(descriptor) != ISO_SECTOR_SIZE:
        raise ParseError("Image is too small to contain an ISO9660 primary volume descriptor")
    if descriptor[0] != 1 or descriptor[1:6] != b"CD001" or descriptor[6] != 1:
        raise ParseError("Unsupported game image: expected ISO9660 primary volume descriptor")
    logical_block_size = int.from_bytes(descriptor[128:130], "little")
    if logical_block_size != ISO_SECTOR_SIZE:
        raise ParseError(f"Unsupported ISO9660 logical block size: {logical_block_size}")
    root, _ = _parse_directory_record(descriptor, 156)
    if root is None or not root.is_directory:
        raise ParseError("ISO9660 primary volume descriptor has no valid root directory")
    return root


def _read_directory(reader: _RawImageReader, record: _IsoDirectoryRecord) -> bytes:
    if record.size < 0:
        raise ParseError("Negative ISO9660 directory size")
    data = reader.read(record.extent * ISO_SECTOR_SIZE, record.size)
    if len(data) != record.size:
        raise ParseError("ISO9660 directory extends beyond the image")
    return data


def _walk_iso(
    reader: _RawImageReader,
    directory: _IsoDirectoryRecord,
    parent_path: str,
    entries: list[GameImageFile],
    records: dict[str, _IsoDirectoryRecord],
    visited: set[tuple[int, int]],
) -> None:
    identity = (directory.extent, directory.size)
    if identity in visited:
        return
    visited.add(identity)

    data = _read_directory(reader, directory)
    offset = 0
    while offset < len(data):
        parsed, next_offset = _parse_directory_record(data, offset)
        if next_offset <= offset:
            raise ParseError("ISO9660 directory parser made no forward progress")
        offset = next_offset
        if parsed is None:
            continue
        name = _clean_identifier(parsed.identifier)
        if name is None:
            continue
        path = f"{parent_path}/{name}" if parent_path else f"/{name}"
        entries.append(
            GameImageFile(
                path=path,
                size=parsed.size,
                extent=parsed.extent,
                is_directory=parsed.is_directory,
            )
        )
        records[path.upper()] = parsed
        if parsed.is_directory:
            _walk_iso(reader, parsed, path, entries, records, visited)


def _read_record_prefix(reader: _RawImageReader, record: _IsoDirectoryRecord, size: int = 4) -> bytes:
    return reader.read(record.extent * ISO_SECTOR_SIZE, min(size, record.size))


def _executable_kind(prefix: bytes) -> str | None:
    if prefix.startswith(b"~PSP"):
        return "encrypted_psp_container"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    return None


def _discover_executables(
    reader: _RawImageReader, entries: list[GameImageFile], records: dict[str, _IsoDirectoryRecord]
) -> tuple[list[GameExecutable], str | None]:
    executables: list[GameExecutable] = []
    by_path = {entry.path.upper(): entry for entry in entries if not entry.is_directory}

    for path, entry in sorted(by_path.items()):
        record = records[path]
        kind = _executable_kind(_read_record_prefix(reader, record))
        if kind is None:
            continue
        executables.append(GameExecutable(path=entry.path, size=entry.size, kind=kind))

    eboot = "/PSP_GAME/SYSDIR/EBOOT.BIN"
    boot = "/PSP_GAME/SYSDIR/BOOT.BIN"
    boot_path: str | None = None
    if eboot in by_path:
        record = records[eboot]
        if _executable_kind(_read_record_prefix(reader, record)) is not None:
            boot_path = by_path[eboot].path
    if boot_path is None and boot in by_path:
        record = records[boot]
        if _executable_kind(_read_record_prefix(reader, record)) is not None:
            boot_path = by_path[boot].path
    return executables, boot_path


def analyze_game_image(path: Path | str) -> GameImageAnalysis:
    source = Path(path)
    reader = _RawImageReader(source)
    try:
        root = _parse_primary_volume(reader)
        entries: list[GameImageFile] = []
        records: dict[str, _IsoDirectoryRecord] = {}
        _walk_iso(reader, root, "", entries, records, set())
        executables, boot_path = _discover_executables(reader, entries, records)
        warnings: list[str] = []
        if boot_path is None:
            warnings.append("No PSP boot executable was discovered under /PSP_GAME/SYSDIR")
        return GameImageAnalysis(
            source_name=str(source),
            image_format="iso",
            logical_size=reader.size,
            sector_size=ISO_SECTOR_SIZE,
            files=entries,
            executables=executables,
            boot_path=boot_path,
            warnings=warnings,
        )
    finally:
        reader.close()
