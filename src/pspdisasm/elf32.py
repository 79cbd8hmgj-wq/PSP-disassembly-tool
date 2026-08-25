from __future__ import annotations

import struct

from .errors import ParseError
from .model import ElfHeader, ElfImage, ProgramHeader, Section

ELF_HEADER_SIZE = 0x34
PROGRAM_HEADER_SIZE = 0x20
SECTION_HEADER_SIZE = 0x28
SHT_NOBITS = 8
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def _require_range(data: bytes, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ParseError(
            f"{what} extends past end of file: offset=0x{offset:X} size=0x{size:X} file=0x{len(data):X}"
        )


def _section_kind(section_type: int, flags: int) -> str:
    if section_type == SHT_NOBITS:
        return "bss"
    if flags & SHF_EXECINSTR:
        return "executable"
    if flags & SHF_WRITE:
        return "writable"
    if flags & SHF_ALLOC:
        return "readonly"
    return "metadata"


def _read_cstring(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\0", offset)
    if end < 0:
        end = len(table)
    return table[offset:end].decode("utf-8", errors="replace")


def parse_elf32(data: bytes) -> ElfImage:
    _require_range(data, 0, ELF_HEADER_SIZE, "ELF header")
    if data[:4] != b"\x7fELF":
        raise ParseError("Invalid ELF magic")
    if data[4] != 1:
        raise ParseError("Unsupported ELF class: expected ELF32")
    if data[5] == 1:
        prefix = "<"
        endianness = "little"
    elif data[5] == 2:
        prefix = ">"
        endianness = "big"
    else:
        raise ParseError(f"Unsupported ELF data encoding: {data[5]}")

    fields = struct.unpack_from(prefix + "HHIIIIIHHHHHH", data, 0x10)
    header = ElfHeader(*fields)
    if header.ehsize and header.ehsize < ELF_HEADER_SIZE:
        raise ParseError(f"Invalid ELF header size: 0x{header.ehsize:X}")

    if header.phnum:
        if header.phentsize < PROGRAM_HEADER_SIZE:
            raise ParseError(f"Invalid program header entry size: 0x{header.phentsize:X}")
        _require_range(
            data,
            header.phoff,
            header.phentsize * header.phnum,
            "program header table",
        )
    if header.shnum:
        if header.shentsize < SECTION_HEADER_SIZE:
            raise ParseError(f"Invalid section header entry size: 0x{header.shentsize:X}")
        _require_range(
            data,
            header.shoff,
            header.shentsize * header.shnum,
            "section header table",
        )

    program_headers: list[ProgramHeader] = []
    for index in range(header.phnum):
        off = header.phoff + index * header.phentsize
        values = struct.unpack_from(prefix + "8I", data, off)
        ph = ProgramHeader(index, *values)
        if ph.filesz:
            _require_range(data, ph.offset, ph.filesz, f"program header {index} data")
        program_headers.append(ph)

    raw_sections: list[tuple[int, ...]] = []
    for index in range(header.shnum):
        off = header.shoff + index * header.shentsize
        values = struct.unpack_from(prefix + "10I", data, off)
        section_type = values[1]
        section_offset = values[4]
        section_size = values[5]
        if section_size and section_type != SHT_NOBITS:
            _require_range(data, section_offset, section_size, f"section {index} data")
        raw_sections.append(values)

    shstr = b""
    if raw_sections and header.shstrndx != 0:
        if header.shstrndx >= len(raw_sections):
            raise ParseError(f"Section-name string table index out of range: {header.shstrndx}")
        entry = raw_sections[header.shstrndx]
        if entry[1] == SHT_NOBITS:
            raise ParseError("Section-name string table cannot be NOBITS")
        shstr = data[entry[4]:entry[4] + entry[5]]

    sections: list[Section] = []
    for index, values in enumerate(raw_sections):
        (
            name_offset,
            section_type,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
        ) = values
        sections.append(
            Section(
                index=index,
                name=_read_cstring(shstr, name_offset) if shstr else "",
                type=section_type,
                flags=flags,
                addr=addr,
                offset=offset,
                size=size,
                link=link,
                info=info,
                addralign=addralign,
                entsize=entsize,
                kind=_section_kind(section_type, flags),
            )
        )

    return ElfImage(
        header=header,
        endianness=endianness,
        program_headers=program_headers,
        sections=sections,
        raw_data=data,
    )
