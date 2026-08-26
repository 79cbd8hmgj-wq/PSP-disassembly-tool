from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import io
from pathlib import Path
import struct
from typing import BinaryIO, Iterator
import zlib

from .errors import EngineUnavailableError, ParseError


_CSO_HEADER = struct.Struct("<4sIQIBB2s")
_CSO_MAGIC = b"CISO"
_ISO_PVD_OFFSET = 16 * 2048
_ISO_PVD_MAGIC = b"\x01CD001\x01"
_INDEX_MASK = 0x7FFFFFFF
_INDEX_FLAG = 0x80000000
_CACHE_BLOCKS = 8


class DiscImageFormat(str, Enum):
    ISO = "iso"
    CSO = "cso"


@dataclass(frozen=True, slots=True)
class CsoHeader:
    header_size: int
    uncompressed_size: int
    block_size: int
    version: int
    index_shift: int


def detect_disc_format(data: bytes) -> DiscImageFormat:
    if data.startswith(_CSO_MAGIC):
        return DiscImageFormat.CSO
    if len(data) >= _ISO_PVD_OFFSET + len(_ISO_PVD_MAGIC):
        if data[_ISO_PVD_OFFSET : _ISO_PVD_OFFSET + len(_ISO_PVD_MAGIC)] == _ISO_PVD_MAGIC:
            return DiscImageFormat.ISO
    raise ParseError("Unsupported disc image format: expected ISO9660 or CISO")


class CsoReader(io.RawIOBase):
    def __init__(self, path: Path | str):
        super().__init__()
        self.path = Path(path)
        self._fp = self.path.open("rb")
        self._position = 0
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        try:
            self.header, self._indexes, self._file_size = self._read_header_and_indexes()
        except Exception:
            self._fp.close()
            raise

    def _read_header_and_indexes(self) -> tuple[CsoHeader, list[int], int]:
        self._fp.seek(0, io.SEEK_END)
        file_size = self._fp.tell()
        self._fp.seek(0)
        raw_header = self._fp.read(_CSO_HEADER.size)
        if len(raw_header) != _CSO_HEADER.size:
            raise ParseError("Truncated CISO header")

        magic, header_size, uncompressed_size, block_size, version, index_shift, unused = _CSO_HEADER.unpack(raw_header)
        if magic != _CSO_MAGIC:
            raise ParseError("Invalid CISO magic")
        if version not in (0, 1, 2):
            raise ParseError(f"Unsupported CISO version: {version}")
        if block_size <= 0:
            raise ParseError("CISO block size must be positive")
        if uncompressed_size <= 0:
            raise ParseError("CISO uncompressed size must be positive")
        if index_shift > 31:
            raise ParseError("CISO index shift is out of range")
        if version == 2 and header_size != _CSO_HEADER.size:
            raise ParseError("CISO v2 header size must be 0x18")
        if version == 2 and unused != b"\0\0":
            raise ParseError("CISO v2 reserved header bytes must be zero")

        # Legacy CISO v0/v1 writers did not reliably populate header_size.
        # Their index table is defined directly after the 0x18-byte header.
        index_offset = _CSO_HEADER.size if version <= 1 else header_size
        if index_offset > file_size:
            raise ParseError("CISO header size exceeds file size")
        block_count = (uncompressed_size + block_size - 1) // block_size
        index_count = block_count + 1
        index_bytes = index_count * 4
        if index_offset + index_bytes > file_size:
            raise ParseError("Truncated CISO index table")

        self._fp.seek(index_offset)
        raw_indexes = self._fp.read(index_bytes)
        indexes = list(struct.unpack(f"<{index_count}I", raw_indexes))
        offsets = [(value & _INDEX_MASK) << index_shift for value in indexes]
        index_end = index_offset + index_bytes
        if offsets[0] < index_end:
            raise ParseError("CISO first block overlaps the header or index table")
        if any(current > following for current, following in zip(offsets, offsets[1:])):
            raise ParseError("CISO block indexes must be monotonic")
        if any(offset > file_size for offset in offsets):
            raise ParseError("CISO block index points beyond end of file")
        if version == 2 and indexes[-1] & _INDEX_FLAG:
            raise ParseError("CISO v2 final index entry must not set the compression flag")

        return CsoHeader(header_size, uncompressed_size, block_size, version, index_shift), indexes, file_size

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._checkClosed()
        if whence == io.SEEK_SET:
            new_position = offset
        elif whence == io.SEEK_CUR:
            new_position = self._position + offset
        elif whence == io.SEEK_END:
            new_position = self.header.uncompressed_size + offset
        else:
            raise ValueError(f"invalid whence ({whence})")
        if new_position < 0:
            raise ValueError("negative seek position")
        self._position = new_position
        return self._position

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        total_size = self.header.uncompressed_size
        if self._position >= total_size:
            return b""
        if size is None or size < 0:
            size = total_size - self._position
        else:
            size = min(size, total_size - self._position)
        if size == 0:
            return b""

        output = bytearray()
        while size > 0 and self._position < total_size:
            block_index = self._position // self.header.block_size
            block_offset = self._position % self.header.block_size
            block = self._read_block(block_index)
            available = len(block) - block_offset
            if available <= 0:
                raise ParseError(f"CISO block {block_index} is shorter than expected")
            take = min(size, available)
            output.extend(block[block_offset : block_offset + take])
            self._position += take
            size -= take
        return bytes(output)

    def readinto(self, buffer: bytearray | memoryview) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def _read_block(self, block_index: int) -> bytes:
        cached = self._cache.get(block_index)
        if cached is not None:
            self._cache.move_to_end(block_index)
            return cached

        block_count = len(self._indexes) - 1
        if block_index < 0 or block_index >= block_count:
            return b""

        current = self._indexes[block_index]
        following = self._indexes[block_index + 1]
        offset = (current & _INDEX_MASK) << self.header.index_shift
        next_offset = (following & _INDEX_MASK) << self.header.index_shift
        stored_size = next_offset - offset
        expected_size = min(
            self.header.block_size,
            self.header.uncompressed_size - block_index * self.header.block_size,
        )
        if stored_size < 0:
            raise ParseError(f"CISO block {block_index} has a negative stored size")

        self._fp.seek(offset)
        if self.header.version <= 1:
            is_plain = bool(current & _INDEX_FLAG)
            if is_plain:
                if stored_size < expected_size:
                    raise ParseError(
                        f"CISO uncompressed block {block_index} spans {stored_size} bytes; expected at least {expected_size}"
                    )
                block = self._fp.read(expected_size)
            else:
                stored = self._fp.read(stored_size)
                block = self._inflate(stored, block_index)
        else:
            if stored_size >= self.header.block_size:
                block = self._fp.read(expected_size)
            else:
                stored = self._fp.read(stored_size)
                if current & _INDEX_FLAG:
                    block = self._decompress_lz4(
                        stored,
                        expected_size,
                        block_index,
                        self.header.index_shift,
                    )
                else:
                    block = self._inflate(stored, block_index)

        if len(block) != expected_size:
            raise ParseError(
                f"CISO block {block_index} decompressed to {len(block)} bytes; expected {expected_size}"
            )
        self._cache[block_index] = block
        self._cache.move_to_end(block_index)
        while len(self._cache) > _CACHE_BLOCKS:
            self._cache.popitem(last=False)
        return block

    @staticmethod
    def _inflate(data: bytes, block_index: int) -> bytes:
        try:
            inflater = zlib.decompressobj(wbits=-15)
            return inflater.decompress(data) + inflater.flush()
        except zlib.error as exc:
            raise ParseError(f"CISO DEFLATE block {block_index} is invalid: {exc}") from exc

    @staticmethod
    def _decompress_lz4(
        data: bytes,
        expected_size: int,
        block_index: int,
        index_shift: int,
    ) -> bytes:
        try:
            import lz4.block
        except ImportError as exc:
            raise EngineUnavailableError(
                "CISO v2 uses LZ4 compression; install pspdisasm with the 'disc' extra"
            ) from exc

        # The index span can include up to (2**index_shift - 1) bytes of
        # alignment padding. Python's LZ4 block API requires an exact input
        # length, unlike maxcso's partial decoder, so try only the legal
        # padding window and accept the first exact-size decode.
        max_padding = min((1 << index_shift) - 1 if index_shift else 0, max(0, len(data) - 1))
        first_error: Exception | None = None
        for padding in range(max_padding + 1):
            candidate = data if padding == 0 else data[:-padding]
            try:
                block = lz4.block.decompress(candidate, uncompressed_size=expected_size)
            except Exception as exc:
                if first_error is None:
                    first_error = exc
                continue
            if len(block) == expected_size:
                return block

        detail = f": {first_error}" if first_error is not None else ""
        raise ParseError(f"CISO LZ4 block {block_index} is invalid{detail}")

    def close(self) -> None:
        if not self.closed:
            self._fp.close()
        super().close()


@contextmanager
def open_disc_stream(path: Path | str) -> Iterator[tuple[DiscImageFormat, BinaryIO]]:
    source = Path(path)
    with source.open("rb") as probe:
        prefix = probe.read(_ISO_PVD_OFFSET + len(_ISO_PVD_MAGIC))
    image_format = detect_disc_format(prefix)
    if image_format is DiscImageFormat.ISO:
        with source.open("rb") as fp:
            yield image_format, fp
        return

    with CsoReader(source) as reader:
        yield image_format, reader
