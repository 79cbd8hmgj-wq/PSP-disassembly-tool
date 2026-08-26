import struct

import lz4.block
import pytest

from pspdisasm.disc_image import CsoReader
from pspdisasm.errors import ParseError


HEADER = struct.Struct("<4sIQIBB2s")


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_padded_lz4_cso(block: bytes, *, index_shift: int = 5) -> bytes:
    alignment = 1 << index_shift
    header_size = HEADER.size
    index_end = header_size + 8
    block_offset = _align(index_end, alignment)
    compressed = lz4.block.compress(block, store_size=False)
    next_offset = _align(block_offset + len(compressed), alignment)

    image = bytearray()
    image.extend(HEADER.pack(b"CISO", header_size, len(block), len(block), 2, index_shift, b"\0\0"))
    image.extend(struct.pack("<I", (block_offset >> index_shift) | 0x80000000))
    image.extend(struct.pack("<I", next_offset >> index_shift))
    image.extend(b"\0" * (block_offset - len(image)))
    image.extend(compressed)
    image.extend(b"\xA5" * (next_offset - len(image)))
    return bytes(image)


def test_cso_v2_lz4_accepts_index_alignment_padding(tmp_path):
    block = b"P" * 2048
    path = tmp_path / "padded.cso"
    path.write_bytes(build_padded_lz4_cso(block))

    with CsoReader(path) as reader:
        assert reader.read() == block
