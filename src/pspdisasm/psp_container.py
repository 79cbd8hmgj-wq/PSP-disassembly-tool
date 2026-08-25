from __future__ import annotations

import struct

from .errors import ParseError
from .model import PspContainerHeader

PSP_HEADER_SIZE = 0x150


def _cstring(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def parse_psp_container_header(data: bytes) -> PspContainerHeader:
    if len(data) < PSP_HEADER_SIZE:
        raise ParseError(f"PSP header requires at least 0x150 bytes, got 0x{len(data):X}")
    if data[:4] != b"~PSP":
        raise ParseError("Invalid PSP container magic")

    module_attribute = struct.unpack_from("<H", data, 0x04)[0]
    compression_attribute = struct.unpack_from("<H", data, 0x06)[0]
    minor = data[0x08]
    major = data[0x09]
    module_name = _cstring(data[0x0A:0x26])
    module_version_byte = data[0x26]
    segment_count = data[0x27]
    elf_size, psp_size, boot_entry = struct.unpack_from("<III", data, 0x28)
    module_info_offset = struct.unpack_from("<i", data, 0x34)[0]
    bss_size = struct.unpack_from("<I", data, 0x38)[0]
    segment_alignments = list(struct.unpack_from("<4H", data, 0x3C))
    segment_addresses = list(struct.unpack_from("<4I", data, 0x44))
    segment_sizes = list(struct.unpack_from("<4I", data, 0x54))
    devkit_version = struct.unpack_from("<I", data, 0x78)[0]
    decrypt_mode = data[0x7C]
    overlap_size = struct.unpack_from("<H", data, 0x7E)[0]
    compressed_size = struct.unpack_from("<I", data, 0xB0)[0]
    subtype = struct.unpack_from("<I", data, 0xD0)[0]

    return PspContainerHeader(
        module_attribute=module_attribute,
        compression_attribute=compression_attribute,
        module_version=(major, minor),
        module_name=module_name,
        module_version_byte=module_version_byte,
        segment_count=segment_count,
        elf_size=elf_size,
        psp_size=psp_size,
        boot_entry=boot_entry,
        module_info_offset=module_info_offset,
        bss_size=bss_size,
        segment_alignments=segment_alignments,
        segment_addresses=segment_addresses,
        segment_sizes=segment_sizes,
        devkit_version=devkit_version,
        decrypt_mode=decrypt_mode,
        overlap_size=overlap_size,
        compressed_size=compressed_size,
        subtype=subtype,
    )
