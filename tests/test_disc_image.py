import struct
import zlib

import pytest

from pspdisasm.disc_image import CsoReader, DiscImageFormat, detect_disc_format
from pspdisasm.errors import ParseError


HEADER = struct.Struct("<4sIQIBB2s")


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def build_cso(
    blocks: list[bytes],
    *,
    compressed: set[int] | None = None,
    version: int = 1,
    lz4_blocks: set[int] | None = None,
    block_size: int = 2048,
) -> bytes:
    compressed = compressed or set()
    lz4_blocks = lz4_blocks or set()
    total_size = sum(len(block) for block in blocks)
    header_size = HEADER.size
    index_count = len(blocks) + 1
    data_offset = header_size + index_count * 4
    payload = bytearray()
    indexes: list[int] = []

    for index, block in enumerate(blocks):
        flag = 0
        if version <= 1:
            if index in compressed:
                stored = _raw_deflate(block)
            else:
                stored = block
                flag = 0x80000000
        else:
            if index in lz4_blocks:
                lz4 = pytest.importorskip("lz4.block")
                stored = lz4.compress(block, store_size=False)
                flag = 0x80000000
            elif index in compressed:
                stored = _raw_deflate(block)
            else:
                stored = block
        indexes.append(data_offset | flag)
        payload.extend(stored)
        data_offset += len(stored)

    indexes.append(data_offset)
    header = HEADER.pack(b"CISO", header_size, total_size, block_size, version, 0, b"\0\0")
    index_data = b"".join(struct.pack("<I", value) for value in indexes)
    return header + index_data + payload


def test_detect_disc_format_recognizes_iso_and_cso():
    iso = bytearray(0x8007)
    iso[0x8000:0x8007] = b"\x01CD001\x01"
    assert detect_disc_format(bytes(iso)) is DiscImageFormat.ISO
    assert detect_disc_format(b"CISO" + b"\0" * 32) is DiscImageFormat.CSO


def test_detect_disc_format_rejects_unknown_data():
    with pytest.raises(ParseError, match="disc image"):
        detect_disc_format(b"not a PSP disc")


def test_cso_reader_reads_across_plain_and_deflate_blocks(tmp_path):
    path = tmp_path / "game.cso"
    path.write_bytes(build_cso([b"A" * 2048, b"B" * 2048], compressed={1}))

    with CsoReader(path) as reader:
        reader.seek(2040)
        assert reader.read(16) == b"A" * 8 + b"B" * 8
        assert reader.tell() == 2056


def test_cso_reader_handles_partial_last_block(tmp_path):
    path = tmp_path / "game.cso"
    path.write_bytes(build_cso([b"A" * 2048, b"tail"], compressed={1}))

    with CsoReader(path) as reader:
        reader.seek(2048)
        assert reader.read(100) == b"tail"
        assert reader.read(1) == b""


def test_cso_reader_supports_version2_lz4_blocks(tmp_path):
    pytest.importorskip("lz4.block")
    path = tmp_path / "game-v2.cso"
    path.write_bytes(build_cso([b"Z" * 2048], version=2, lz4_blocks={0}))

    with CsoReader(path) as reader:
        assert reader.read() == b"Z" * 2048


def test_cso_reader_rejects_non_monotonic_indexes(tmp_path):
    image = bytearray(build_cso([b"A" * 2048, b"B" * 2048]))
    first_index = HEADER.size
    first_offset = struct.unpack_from("<I", image, first_index)[0] & 0x7FFFFFFF
    struct.pack_into("<I", image, first_index + 4, first_offset - 1)
    path = tmp_path / "broken.cso"
    path.write_bytes(image)

    with pytest.raises(ParseError, match="monotonic"):
        CsoReader(path)


def test_cso_v1_ignores_unreliable_header_size_field(tmp_path):
    image = bytearray(build_cso([b"A" * 2048]))
    struct.pack_into("<I", image, 4, 0x12345678)
    path = tmp_path / "legacy-header.cso"
    path.write_bytes(image)

    with CsoReader(path) as reader:
        assert reader.read() == b"A" * 2048


def test_cso_reader_rejects_plain_block_shorter_than_declared_span(tmp_path):
    image = bytearray(build_cso([b"A" * 2048]))
    first_index_offset = HEADER.size
    first = struct.unpack_from("<I", image, first_index_offset)[0]
    data_offset = first & 0x7FFFFFFF
    struct.pack_into("<I", image, first_index_offset + 4, data_offset + 2047)
    path = tmp_path / "short-plain.cso"
    path.write_bytes(image)

    with CsoReader(path) as reader:
        with pytest.raises(ParseError, match="uncompressed block"):
            reader.read()
