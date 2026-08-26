from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Protocol
import struct
import zlib

from .errors import ParseError


ISO_SECTOR_SIZE = 2048
ISO_PRIMARY_VOLUME_DESCRIPTOR_SECTOR = 16
CSO_HEADER_SIZE = 24
CSO_INDEX_MASK = 0x7FFFFFFF
CSO_INDEX_UNCOMPRESSED = 0x80000000
SFO_HEADER_SIZE = 20
SFO_INDEX_SIZE = 16
SFO_FORMAT_BINARY = 0x0004
SFO_FORMAT_UTF8 = 0x0204
SFO_FORMAT_UINT32 = 0x0404


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


class _ImageReader(Protocol):
    size: int
    image_format: str

    def close(self) -> None: ...

    def read(self, offset: int, size: int) -> bytes: ...


class _RawImageReader:
    image_format = "iso"

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


class _CsoImageReader:
    image_format = "cso"

    def __init__(self, path: Path) -> None:
        self.path = path
        self._physical_size = path.stat().st_size
        self._stream: BinaryIO = path.open("rb")
        header = self._stream.read(CSO_HEADER_SIZE)
        if len(header) != CSO_HEADER_SIZE:
            self.close()
            raise ParseError("Truncated CSO header")

        magic, _declared_header_size, total_size, block_size, version, index_shift, _unused = struct.unpack(
            "<4sIQIBB2s", header
        )
        if magic != b"CISO":
            self.close()
            raise ParseError("Invalid CSO magic")
        if version not in (0, 1):
            self.close()
            raise ParseError(f"Unsupported CSO version: {version}; expected version 0 or 1")
        if block_size < ISO_SECTOR_SIZE or block_size & (block_size - 1):
            self.close()
            raise ParseError("CSO block size must be a power of two and at least 2048 bytes")
        if index_shift > 20:
            self.close()
            raise ParseError("CSO index shift is unreasonably large")
        if total_size <= 0:
            self.close()
            raise ParseError("CSO declares an empty logical image")

        self.size = total_size
        self.block_size = block_size
        self.index_shift = index_shift
        self.block_count = (total_size + block_size - 1) // block_size
        index_bytes = self._stream.read((self.block_count + 1) * 4)
        if len(index_bytes) != (self.block_count + 1) * 4:
            self.close()
            raise ParseError("Truncated CSO block index")
        self._indices = list(struct.unpack(f"<{self.block_count + 1}I", index_bytes))
        self._validate_indices()
        self._cached_block_number: int | None = None
        self._cached_block = b""

    def close(self) -> None:
        self._stream.close()

    def _index_offset(self, value: int) -> int:
        return (value & CSO_INDEX_MASK) << self.index_shift

    def _validate_indices(self) -> None:
        previous = 0
        for index, value in enumerate(self._indices):
            offset = self._index_offset(value)
            if index and offset < previous:
                self.close()
                raise ParseError("CSO block index offsets are not monotonic")
            if offset > self._physical_size:
                self.close()
                raise ParseError("CSO block index points beyond the compressed file")
            previous = offset

    def _read_block(self, block_number: int) -> bytes:
        if block_number == self._cached_block_number:
            return self._cached_block
        if not 0 <= block_number < self.block_count:
            raise ParseError("CSO block number is out of range")

        current = self._indices[block_number]
        next_value = self._indices[block_number + 1]
        start = self._index_offset(current)
        end = self._index_offset(next_value)
        if end < start:
            raise ParseError("CSO block has a negative compressed span")

        remaining = self.size - block_number * self.block_size
        expected_size = min(self.block_size, remaining)
        self._stream.seek(start)
        if current & CSO_INDEX_UNCOMPRESSED:
            block = self._stream.read(expected_size)
            if len(block) != expected_size:
                raise ParseError("Truncated uncompressed CSO block")
        else:
            compressed = self._stream.read(end - start)
            if len(compressed) != end - start:
                raise ParseError("Truncated compressed CSO block")
            try:
                block = zlib.decompress(compressed, -15)
            except zlib.error as exc:
                raise ParseError(f"Invalid CSO deflate block {block_number}") from exc
            if len(block) != expected_size:
                raise ParseError(
                    f"CSO block {block_number} decompressed to {len(block)} bytes; expected {expected_size}"
                )

        self._cached_block_number = block_number
        self._cached_block = block
        return block

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ParseError("Negative image read is invalid")
        if offset >= self.size or size == 0:
            return b""
        end = min(offset + size, self.size)
        output = bytearray()
        cursor = offset
        while cursor < end:
            block_number = cursor // self.block_size
            block_offset = cursor % self.block_size
            block = self._read_block(block_number)
            take = min(end - cursor, len(block) - block_offset)
            if take <= 0:
                raise ParseError("CSO block mapping made no forward progress")
            output.extend(block[block_offset : block_offset + take])
            cursor += take
        return bytes(output)


@dataclass(slots=True)
class _IsoDirectoryRecord:
    extent: int
    size: int
    is_directory: bool
    identifier: bytes


def parse_param_sfo(data: bytes) -> dict[str, object]:
    if len(data) < SFO_HEADER_SIZE:
        raise ParseError("Truncated PARAM.SFO header")
    magic, _version, key_table_start, data_table_start, entry_count = struct.unpack_from("<4sIIII", data, 0)
    if magic != b"\x00PSF":
        raise ParseError("Invalid PARAM.SFO magic")

    index_end = SFO_HEADER_SIZE + entry_count * SFO_INDEX_SIZE
    if index_end > len(data):
        raise ParseError("Truncated PARAM.SFO entry table")
    if key_table_start < index_end or data_table_start < key_table_start or data_table_start > len(data):
        raise ParseError("Invalid PARAM.SFO table offsets")

    result: dict[str, object] = {}
    for entry_index in range(entry_count):
        entry_offset = SFO_HEADER_SIZE + entry_index * SFO_INDEX_SIZE
        key_offset, data_format, data_length, data_max_length, data_offset = struct.unpack_from(
            "<HHIII", data, entry_offset
        )
        if data_length > data_max_length:
            raise ParseError("PARAM.SFO entry length exceeds its declared maximum")

        key_position = key_table_start + key_offset
        if not key_table_start <= key_position < data_table_start:
            raise ParseError("PARAM.SFO key offset lies outside the key table")
        key_end = data.find(b"\x00", key_position, data_table_start)
        if key_end < 0:
            raise ParseError("PARAM.SFO key is not NUL-terminated")
        try:
            key = data[key_position:key_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ParseError("PARAM.SFO key is not valid UTF-8") from exc
        if not key:
            raise ParseError("PARAM.SFO contains an empty key")

        value_start = data_table_start + data_offset
        value_end = value_start + data_length
        if value_start < data_table_start or value_end > len(data):
            raise ParseError(f"PARAM.SFO value for {key!r} extends beyond the file")
        value = data[value_start:value_end]

        if data_format == SFO_FORMAT_UTF8:
            string_bytes = value.split(b"\x00", 1)[0]
            try:
                decoded: object = string_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ParseError(f"PARAM.SFO value for {key!r} is not valid UTF-8") from exc
        elif data_format == SFO_FORMAT_UINT32:
            if data_length != 4:
                raise ParseError(f"PARAM.SFO integer value for {key!r} is not four bytes")
            decoded = int.from_bytes(value, "little")
        else:
            decoded = value.hex()
        result[key] = decoded

    return dict(sorted(result.items()))


def _open_image_reader(path: Path) -> _ImageReader:
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic == b"CISO":
        return _CsoImageReader(path)
    return _RawImageReader(path)


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


def _parse_primary_volume(reader: _ImageReader) -> _IsoDirectoryRecord:
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


def _read_directory(reader: _ImageReader, record: _IsoDirectoryRecord) -> bytes:
    data = reader.read(record.extent * ISO_SECTOR_SIZE, record.size)
    if len(data) != record.size:
        raise ParseError("ISO9660 directory extends beyond the image")
    return data


def _walk_iso(
    reader: _ImageReader,
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


def _read_record_prefix(reader: _ImageReader, record: _IsoDirectoryRecord, size: int = 4) -> bytes:
    return reader.read(record.extent * ISO_SECTOR_SIZE, min(size, record.size))


def _executable_kind(prefix: bytes) -> str | None:
    if prefix.startswith(b"~PSP"):
        return "encrypted_psp_container"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    return None


def _discover_executables(
    reader: _ImageReader, entries: list[GameImageFile], records: dict[str, _IsoDirectoryRecord]
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
    reader = _open_image_reader(source)
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
            image_format=reader.image_format,
            logical_size=reader.size,
            sector_size=ISO_SECTOR_SIZE,
            files=entries,
            executables=executables,
            boot_path=boot_path,
            warnings=warnings,
        )
    finally:
        reader.close()
