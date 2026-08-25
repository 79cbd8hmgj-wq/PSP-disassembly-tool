from __future__ import annotations

import struct


def build_simple_elf32(*, e_type: int = 2, machine: int = 8) -> bytes:
    names = b"\x00.text\x00.data\x00.bss\x00.shstrtab\x00"
    name_offsets = {
        ".text": names.index(b".text"),
        ".data": names.index(b".data"),
        ".bss": names.index(b".bss"),
        ".shstrtab": names.index(b".shstrtab"),
    }

    phoff = 0x34
    text_off = 0x100
    data_off = 0x108
    shstr_off = 0x120
    shoff = 0x160
    shnum = 5
    total = shoff + shnum * 0x28
    blob = bytearray(total)

    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 1
    ident[5] = 1
    ident[6] = 1
    blob[0:16] = ident
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        blob,
        0x10,
        e_type,
        machine,
        1,
        0x08800000,
        phoff,
        shoff,
        0x10A23001,
        0x34,
        0x20,
        1,
        0x28,
        shnum,
        4,
    )

    struct.pack_into(
        "<8I",
        blob,
        phoff,
        1,
        text_off,
        0x08800000,
        0x08800000,
        12,
        16,
        7,
        0x10,
    )

    blob[text_off:text_off + 8] = b"TEXTCODE"
    blob[data_off:data_off + 4] = b"DATA"
    blob[shstr_off:shstr_off + len(names)] = names

    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_offsets[".text"], 1, 0x6, 0x08800000, text_off, 8, 0, 0, 4, 0),
        (name_offsets[".data"], 1, 0x3, 0x08800008, data_off, 4, 0, 0, 4, 0),
        (name_offsets[".bss"], 8, 0x3, 0x0880000C, data_off + 4, 4, 0, 0, 4, 0),
        (name_offsets[".shstrtab"], 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0),
    ]
    for i, section in enumerate(sections):
        struct.pack_into("<10I", blob, shoff + i * 0x28, *section)

    return bytes(blob)


def build_prx_elf32(*, module_section: bool = True, include_prxreloc2: bool = True) -> bytes:
    names_list = [".text", ".rodata.sceModuleInfo" if module_section else ".rodata", ".lib.ent", ".lib.stub", ".rel.text", ".shstrtab"]
    names = b"\x00"
    name_offsets: dict[str, int] = {}
    for name in names_list:
        name_offsets[name] = len(names)
        names += name.encode() + b"\x00"

    phoff = 0x34
    phnum = 2 if include_prxreloc2 else 1
    load_off = 0x100
    load_filesz = 0x100
    reloc_off = 0x300
    reloc2_off = 0x308
    shstr_off = 0x320
    shoff = 0x380
    shnum = 7
    total = shoff + shnum * 0x28
    blob = bytearray(total)

    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 1
    ident[5] = 1
    ident[6] = 1
    blob[:16] = ident
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        blob,
        0x10,
        0xFFA0,
        8,
        1,
        0x0,
        phoff,
        shoff,
        0x10A23001,
        0x34,
        0x20,
        phnum,
        0x28,
        shnum,
        6,
    )

    # First LOAD. p_paddr encodes module-info file position for stripped PRX fallback.
    struct.pack_into("<8I", blob, phoff, 1, load_off, 0, 0x120, load_filesz, load_filesz + 0x20, 7, 0x10)
    if include_prxreloc2:
        struct.pack_into("<8I", blob, phoff + 0x20, 0x700000A1, reloc2_off, 0, 0, 8, 8, 4, 4)
        blob[reloc2_off:reloc2_off + 8] = b"\x00\x00\x03\x03\x01\x01\x00\x00"

    # Text.
    blob[load_off:load_off + 0x20] = bytes(range(0x20))

    # sceModuleInfo at vaddr 0x20 / file 0x120.
    module_off = load_off + 0x20
    struct.pack_into("<HBB", blob, module_off, 0x1000, 2, 1)
    blob[module_off + 4:module_off + 4 + 8] = b"TESTPRX\x00"
    struct.pack_into("<IIIII", blob, module_off + 0x20, 0x1234, 0x60, 0x70, 0xA0, 0xB8)

    # Export library at vaddr 0x60: one function + one variable, 4 words long.
    export_off = load_off + 0x60
    struct.pack_into("<4I", blob, export_off, 0x70, 0, 4 | (1 << 8) | (1 << 16), 0x80)
    blob[load_off + 0x70:load_off + 0x70 + 7] = b"TestEx\x00"
    struct.pack_into("<4I", blob, load_off + 0x80, 0x11111111, 0x22222222, 0x10, 0x14)

    # Import library at vaddr 0xA0: two functions + one variable, 6 words long.
    import_off = load_off + 0xA0
    struct.pack_into("<6I", blob, import_off, 0xC0, 0, 6 | (1 << 8) | (2 << 16), 0xD0, 0xD8, 0xE8)
    blob[load_off + 0xC0:load_off + 0xC0 + 7] = b"TestIm\x00"
    struct.pack_into("<2I", blob, load_off + 0xD0, 0xAAAA0001, 0xAAAA0002)
    blob[load_off + 0xD8:load_off + 0xE8] = b"\x08\x00\xE0\x03\x00\x00\x00\x00" * 2
    struct.pack_into("<2I", blob, load_off + 0xE8, 0x50, 0xBBBB0001)

    # Type-A PSP relocation.
    struct.pack_into("<2I", blob, reloc_off, 0x04, (1 << 8) | 2)
    blob[shstr_off:shstr_off + len(names)] = names

    module_section_name = names_list[1]
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_offsets[".text"], 1, 0x6, 0x00, load_off, 0x20, 0, 0, 4, 0),
        (name_offsets[module_section_name], 1, 0x2, 0x20, module_off, 0x34, 0, 0, 4, 0),
        (name_offsets[".lib.ent"], 1, 0x2, 0x60, export_off, 0x30, 0, 0, 4, 0),
        (name_offsets[".lib.stub"], 1, 0x2, 0xA0, import_off, 0x50, 0, 0, 4, 0),
        (name_offsets[".rel.text"], 0x700000A0, 0, 0, reloc_off, 8, 0, 1, 4, 8),
        (name_offsets[".shstrtab"], 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0),
    ]
    for i, section in enumerate(sections):
        struct.pack_into("<10I", blob, shoff + i * 0x28, *section)

    return bytes(blob)


def build_psp_container_header() -> bytes:
    blob = bytearray(0x150)
    blob[:4] = b"~PSP"
    struct.pack_into("<H", blob, 0x04, 0)
    struct.pack_into("<H", blob, 0x06, 0x0200)
    blob[0x08] = 1
    blob[0x09] = 1
    blob[0x0A:0x12] = b"GAMEBOOT"
    blob[0x27] = 1
    struct.pack_into("<I", blob, 0x28, 0x10000)
    struct.pack_into("<I", blob, 0x2C, 0x8000)
    struct.pack_into("<I", blob, 0x78, 0x06060110)
    blob[0x7C] = 9
    struct.pack_into("<I", blob, 0xD0, 0xD91611F0)
    return bytes(blob)
