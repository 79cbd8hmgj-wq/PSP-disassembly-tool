from __future__ import annotations

import struct

from .errors import ParseError
from .model import (
    ElfImage,
    LibraryExport,
    LibraryImport,
    ModuleInfo,
    NidEntry,
    PrxAnalysis,
    Relocation,
)

ET_SCE_PSPRELEXEC = 0xFFA0
SHT_REL = 9
SHT_PRXRELOC = 0x700000A0
PT_LOAD = 1
PT_PRXRELOC = 0x700000A0
PT_PRXRELOC2 = 0x700000A1
MODULE_INFO_SECTION = ".rodata.sceModuleInfo"
MODULE_INFO_SIZE = 0x34

RELOC_NAMES = {
    0: "R_MIPS_NONE",
    1: "R_MIPS_16",
    2: "R_MIPS_32",
    3: "R_MIPS_REL32",
    4: "R_MIPS_26",
    5: "R_MIPS_HI16",
    6: "R_MIPS_LO16",
    7: "R_MIPS_GPREL16",
    8: "R_MIPS_LITERAL",
    9: "R_MIPS_GOT16",
    10: "R_MIPS_PC16",
    11: "R_MIPS_CALL16",
    12: "R_MIPS_GPREL32",
    13: "R_MIPS_X_HI16",
    14: "R_MIPS_X_J26",
    15: "R_MIPS_X_JAL26",
}


def _prefix(elf: ElfImage) -> str:
    return "<" if elf.endianness == "little" else ">"


def _read_at_vaddr(data: bytes, elf: ElfImage, address: int, size: int, what: str) -> bytes:
    off = elf.vaddr_to_offset(address)
    if off is None or off < 0 or size < 0 or off > len(data) or size > len(data) - off:
        raise ParseError(f"Invalid virtual address for {what}: 0x{address:X}")
    return data[off:off + size]


def _u32_at_vaddr(data: bytes, elf: ElfImage, address: int, what: str) -> int:
    return struct.unpack(_prefix(elf) + "I", _read_at_vaddr(data, elf, address, 4, what))[0]


def _cstring_at_vaddr(data: bytes, elf: ElfImage, address: int, what: str, max_len: int = 128) -> str:
    off = elf.vaddr_to_offset(address)
    if off is None:
        raise ParseError(f"Invalid virtual address for {what}: 0x{address:X}")
    end_limit = min(len(data), off + max_len)
    end = data.find(b"\0", off, end_limit)
    if end < 0:
        end = end_limit
    return data[off:end].decode("ascii", errors="replace")


def _parse_module_info_at(data: bytes, elf: ElfImage, file_offset: int, address: int, location: str) -> ModuleInfo:
    if file_offset < 0 or file_offset + MODULE_INFO_SIZE > len(data):
        raise ParseError("PSP module info extends past end of file")
    p = _prefix(elf)
    attributes, minor, major = struct.unpack_from(p + "HBB", data, file_offset)
    raw_name = data[file_offset + 4:file_offset + 0x20]
    name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
    gp, exp_start, exp_end, imp_start, imp_end = struct.unpack_from(p + "IIIII", data, file_offset + 0x20)
    return ModuleInfo(
        attributes=attributes,
        version=(major, minor),
        name=name,
        gp_value=gp,
        exports_start=exp_start,
        exports_end=exp_end,
        imports_start=imp_start,
        imports_end=imp_end,
        address=address,
        location=location,
    )


def _find_module_info(data: bytes, elf: ElfImage, warnings: list[str]) -> ModuleInfo | None:
    for section in elf.sections:
        if section.name == MODULE_INFO_SECTION:
            try:
                return _parse_module_info_at(data, elf, section.offset, section.addr, "section")
            except ParseError as exc:
                warnings.append(str(exc))
                return None

    first_load = next((ph for ph in elf.program_headers if ph.type == PT_LOAD), None)
    if first_load is None:
        warnings.append("Could not locate PSP module info: no named section and no PT_LOAD segment")
        return None
    address = (first_load.paddr & 0x7FFFFFFF) - first_load.offset
    file_offset = elf.vaddr_to_offset(address)
    if file_offset is None:
        warnings.append(f"Could not map PSP module-info fallback address 0x{address:X}")
        return None
    try:
        return _parse_module_info_at(data, elf, file_offset, address, "program_header_fallback")
    except ParseError as exc:
        warnings.append(str(exc))
        return None


def _walk_exports(data: bytes, elf: ElfImage, module: ModuleInfo, warnings: list[str]) -> list[LibraryExport]:
    result: list[LibraryExport] = []
    cursor = module.exports_start
    while cursor and cursor < module.exports_end:
        try:
            raw = _read_at_vaddr(data, elf, cursor, 16, "export library")
            name_ptr, flags, counts, exports_ptr = struct.unpack(_prefix(elf) + "4I", raw)
            entry_length = counts & 0xFF
            var_count = (counts >> 8) & 0xFF
            func_count = (counts >> 16) & 0xFFFF
            if entry_length < 4:
                warnings.append(f"Invalid export entry length {entry_length} at 0x{cursor:X}")
                break
            entry_bytes = entry_length * 4
            if cursor + entry_bytes > module.exports_end:
                warnings.append(f"Export entry at 0x{cursor:X} extends past module export table")
                break
            name = "syslib" if name_ptr == 0 else _cstring_at_vaddr(data, elf, name_ptr, "export library name")
            total = func_count + var_count
            functions: list[NidEntry] = []
            variables: list[NidEntry] = []
            for i in range(func_count):
                nid_address = exports_ptr + i * 4
                nid = _u32_at_vaddr(data, elf, nid_address, "export function NID")
                address = _u32_at_vaddr(data, elf, exports_ptr + (total + i) * 4, "export function address")
                functions.append(NidEntry(nid, address, "function", nid_address))
            for i in range(var_count):
                index = func_count + i
                nid_address = exports_ptr + index * 4
                nid = _u32_at_vaddr(data, elf, nid_address, "export variable NID")
                address = _u32_at_vaddr(data, elf, exports_ptr + (total + index) * 4, "export variable address")
                variables.append(NidEntry(nid, address, "variable", nid_address))
            result.append(
                LibraryExport(
                    name=name,
                    flags=flags,
                    entry_length=entry_length,
                    function_count=func_count,
                    variable_count=var_count,
                    address=cursor,
                    functions=functions,
                    variables=variables,
                )
            )
            cursor += entry_bytes
        except ParseError as exc:
            warnings.append(f"Export parsing stopped at 0x{cursor:X}: {exc}")
            break
    return result


def _walk_imports(data: bytes, elf: ElfImage, module: ModuleInfo, warnings: list[str]) -> list[LibraryImport]:
    result: list[LibraryImport] = []
    cursor = module.imports_start
    while cursor and cursor < module.imports_end:
        try:
            base = _read_at_vaddr(data, elf, cursor, 20, "import library")
            name_ptr, flags, counts, nids_ptr, funcs_ptr = struct.unpack(_prefix(elf) + "5I", base)
            entry_length = counts & 0xFF
            var_count = (counts >> 8) & 0xFF
            func_count = (counts >> 16) & 0xFFFF
            if entry_length < 5:
                warnings.append(f"Invalid import entry length {entry_length} at 0x{cursor:X}")
                break
            entry_bytes = entry_length * 4
            if cursor + entry_bytes > module.imports_end:
                warnings.append(f"Import entry at 0x{cursor:X} extends past module import table")
                break
            vars_ptr = 0
            if entry_length >= 6:
                vars_ptr = _u32_at_vaddr(data, elf, cursor + 20, "import variable table pointer")
            if name_ptr == 0:
                warnings.append(f"Import library at 0x{cursor:X} has no name pointer")
                break
            name = _cstring_at_vaddr(data, elf, name_ptr, "import library name")
            functions: list[NidEntry] = []
            variables: list[NidEntry] = []
            for i in range(func_count):
                nid_address = nids_ptr + i * 4
                nid = _u32_at_vaddr(data, elf, nid_address, "import function NID")
                functions.append(NidEntry(nid, funcs_ptr + i * 8, "function", nid_address))
            if var_count and not vars_ptr:
                warnings.append(f"Import library {name} declares {var_count} variables without a variable table")
            elif vars_ptr:
                for i in range(var_count):
                    pair = vars_ptr + i * 8
                    address = _u32_at_vaddr(data, elf, pair, "import variable address")
                    nid_address = pair + 4
                    nid = _u32_at_vaddr(data, elf, nid_address, "import variable NID")
                    variables.append(NidEntry(nid, address, "variable", nid_address))
            result.append(
                LibraryImport(
                    name=name,
                    flags=flags,
                    entry_length=entry_length,
                    function_count=func_count,
                    variable_count=var_count,
                    address=cursor,
                    functions=functions,
                    variables=variables,
                )
            )
            cursor += entry_bytes
        except ParseError as exc:
            warnings.append(f"Import parsing stopped at 0x{cursor:X}: {exc}")
            break
    return result


def _parse_relocations(data: bytes, elf: ElfImage, warnings: list[str]) -> list[Relocation]:
    relocs: list[Relocation] = []
    p = _prefix(elf)
    section_ranges: set[tuple[int, int]] = set()
    for section in elf.sections:
        if section.type not in {SHT_REL, SHT_PRXRELOC}:
            continue
        section_ranges.add((section.offset, section.size))
        if section.size % 8:
            warnings.append(f"Relocation section {section.name or section.index} has non-multiple-of-8 size")
        count = section.size // 8
        for i in range(count):
            off = section.offset + i * 8
            r_offset, r_info = struct.unpack_from(p + "2I", data, off)
            r_type = r_info & 0xFF
            relocs.append(
                Relocation(
                    section=section.name,
                    offset=r_offset,
                    info=r_info,
                    type=r_type,
                    type_name=RELOC_NAMES.get(r_type, f"R_MIPS_{r_type}"),
                    symbol_index=r_info >> 8,
                    target_section_index=section.info if section.info < len(elf.sections) else None,
                    source="section",
                )
            )

    # Some stripped PRX files expose Type-A relocations only as PT_PRXRELOC.
    for ph in elf.program_headers:
        if ph.type == PT_PRXRELOC and (ph.offset, ph.filesz) not in section_ranges:
            if ph.filesz % 8:
                warnings.append("PT_PRXRELOC segment has non-multiple-of-8 size")
            for i in range(ph.filesz // 8):
                r_offset, r_info = struct.unpack_from(p + "2I", data, ph.offset + i * 8)
                r_type = r_info & 0xFF
                relocs.append(
                    Relocation(
                        section="",
                        offset=r_offset,
                        info=r_info,
                        type=r_type,
                        type_name=RELOC_NAMES.get(r_type, f"R_MIPS_{r_type}"),
                        symbol_index=r_info >> 8,
                        target_section_index=None,
                        source="program_header",
                    )
                )
        elif ph.type == PT_PRXRELOC2:
            warnings.append("PT_PRXRELOC2 compressed relocation segment detected; decoding is not implemented in Phase 1")
    return relocs


def analyze_prx(data: bytes, elf: ElfImage) -> PrxAnalysis:
    warnings: list[str] = []
    module = _find_module_info(data, elf, warnings)
    exports: list[LibraryExport] = []
    imports: list[LibraryImport] = []
    if module is not None:
        exports = _walk_exports(data, elf, module, warnings)
        imports = _walk_imports(data, elf, module, warnings)
    relocations = _parse_relocations(data, elf, warnings)
    return PrxAnalysis(
        module_info=module,
        imports=imports,
        exports=exports,
        relocations=relocations,
        warnings=warnings,
    )
