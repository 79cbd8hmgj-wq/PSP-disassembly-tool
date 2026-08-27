from __future__ import annotations

from dataclasses import dataclass, replace

from .errors import ParseError
from .model import ElfImage, ExecutableModel, ProgramHeader, Relocation
from .prxreloc2 import apply_psp_relocation_word


PT_LOAD = 1
SHF_ALLOC = 0x2
UINT32_MAX = 0xFFFFFFFF
UINT32_LIMIT = 1 << 32


@dataclass(slots=True)
class RelocatedLoadView:
    load_address: int
    original_image_base: int
    address_delta: int
    segment_bases: dict[int, int]
    applied_relocations: int
    elf: ElfImage
    model: ExecutableModel


def _loaded_segments(elf: ElfImage) -> list[ProgramHeader]:
    return [segment for segment in elf.program_headers if segment.type == PT_LOAD and segment.memsz > 0]


def _segment_index(relocation: Relocation, shift: int, explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    return (relocation.info >> shift) & 0xFF


def _relocation_segments(relocation: Relocation) -> tuple[int, int]:
    return (
        _segment_index(relocation, 8, relocation.source_segment_index),
        _segment_index(relocation, 16, relocation.target_segment_index),
    )


def _segment(elf: ElfImage, index: int, role: str) -> ProgramHeader:
    if index < 0 or index >= len(elf.program_headers):
        raise ParseError(f"Relocation {role} segment index {index} is out of range")
    segment = elf.program_headers[index]
    if segment.type != PT_LOAD:
        raise ParseError(f"Relocation {role} segment {index} is not PT_LOAD")
    return segment


def _source_file_offset(elf: ElfImage, relocation: Relocation) -> tuple[int, int]:
    source_index, _ = _relocation_segments(relocation)
    source = _segment(elf, source_index, "source")
    if relocation.offset < 0 or relocation.offset + 4 > source.filesz:
        raise ParseError(
            f"Relocation source offset 0x{relocation.offset:X} is not a complete file-backed word "
            f"inside PT_LOAD segment {source_index}"
        )
    return source_index, source.offset + relocation.offset


def _signed_low_half(word: int) -> int:
    value = word & 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _type_a_hi16_low_half(
    data: bytes,
    elf: ElfImage,
    relocations: list[Relocation],
    index: int,
) -> int | None:
    relocation = relocations[index]
    if relocation.type != 5 or relocation.source == "program_header_rel2":
        return None
    source_index, target_index = _relocation_segments(relocation)
    for candidate in relocations[index + 1 :]:
        if candidate.type == 5:
            continue
        if candidate.type not in {1, 6}:
            continue
        candidate_source, candidate_target = _relocation_segments(candidate)
        if (candidate_source, candidate_target) != (source_index, target_index):
            continue
        _, file_offset = _source_file_offset(elf, candidate)
        if file_offset < 0 or file_offset + 4 > len(data):
            raise ParseError("Type-A HI16 companion word extends beyond the input")
        return _signed_low_half(int.from_bytes(data[file_offset : file_offset + 4], "little"))
    return None


def _contains_address(segment: ProgramHeader, address: int) -> bool:
    return segment.vaddr <= address < segment.vaddr + segment.memsz


def _contains_range_end(segment: ProgramHeader, address: int) -> bool:
    return segment.vaddr <= address <= segment.vaddr + segment.memsz


def _require_u32_address(value: int, what: str) -> None:
    if value < 0 or value > UINT32_MAX:
        raise ParseError(f"{what} falls outside the 32-bit address space")


def _require_u32_range(start: int, size: int, what: str) -> None:
    _require_u32_address(start, what)
    if size < 0 or start + size > UINT32_LIMIT:
        raise ParseError(f"{what} extends outside the 32-bit address space")


def _validate_rebased_layout(elf: ElfImage, delta: int) -> None:
    for segment in _loaded_segments(elf):
        new_vaddr = segment.vaddr + delta
        new_paddr = segment.paddr + delta
        _require_u32_range(new_vaddr, segment.memsz, f"PT_LOAD segment {segment.index}")
        _require_u32_address(new_paddr, f"PT_LOAD segment {segment.index} physical address")

    for section in elf.sections:
        if not section.flags & SHF_ALLOC or section.size <= 0:
            continue
        _require_u32_range(
            section.addr + delta,
            section.size,
            f"Allocated section {section.name or section.index}",
        )


def _rebase_loaded_address(elf: ElfImage, address: int, delta: int) -> int:
    if any(_contains_address(segment, address) for segment in _loaded_segments(elf)):
        relocated = address + delta
        _require_u32_address(relocated, "Rebased loaded address")
        return relocated
    return address


def _rebase_nonzero_loaded_address(elf: ElfImage, address: int, delta: int) -> int:
    if address == 0:
        return 0
    return _rebase_loaded_address(elf, address, delta)


def _rebase_nonzero_loaded_range_end(elf: ElfImage, address: int, delta: int) -> int:
    if address == 0:
        return 0
    if any(_contains_range_end(segment, address) for segment in _loaded_segments(elf)):
        relocated = address + delta
        _require_u32_address(relocated, "Rebased loaded range end")
        return relocated
    return address


def _rebase_elf(elf: ElfImage, data: bytes, delta: int) -> ElfImage:
    original_loads = _loaded_segments(elf)
    entry = elf.header.entry
    if any(_contains_address(segment, entry) for segment in original_loads):
        entry += delta

    header = replace(elf.header, entry=entry)
    program_headers = [
        replace(
            segment,
            vaddr=segment.vaddr + delta,
            paddr=segment.paddr + delta,
        )
        if segment.type == PT_LOAD
        else replace(segment)
        for segment in elf.program_headers
    ]
    sections = [
        replace(section, addr=section.addr + delta)
        if section.flags & SHF_ALLOC and section.size > 0
        else replace(section)
        for section in elf.sections
    ]
    return ElfImage(
        header=header,
        endianness=elf.endianness,
        program_headers=program_headers,
        sections=sections,
        raw_data=data,
    )


def _rebase_nid_entry(entry, elf: ElfImage, delta: int):
    return replace(
        entry,
        address=_rebase_nonzero_loaded_address(elf, entry.address, delta),
        nid_address=_rebase_nonzero_loaded_address(elf, entry.nid_address, delta),
    )


def _rebase_library(library, elf: ElfImage, delta: int):
    return replace(
        library,
        address=_rebase_loaded_address(elf, library.address, delta),
        functions=[_rebase_nid_entry(entry, elf, delta) for entry in library.functions],
        variables=[_rebase_nid_entry(entry, elf, delta) for entry in library.variables],
    )


def _rebase_model(
    model: ExecutableModel,
    original_elf: ElfImage,
    relocated_elf: ElfImage,
    delta: int,
) -> ExecutableModel:
    module_info = model.module_info
    if module_info is not None:
        module_info = replace(
            module_info,
            gp_value=_rebase_nonzero_loaded_address(original_elf, module_info.gp_value, delta),
            exports_start=_rebase_nonzero_loaded_address(original_elf, module_info.exports_start, delta),
            exports_end=_rebase_nonzero_loaded_range_end(original_elf, module_info.exports_end, delta),
            imports_start=_rebase_nonzero_loaded_address(original_elf, module_info.imports_start, delta),
            imports_end=_rebase_nonzero_loaded_range_end(original_elf, module_info.imports_end, delta),
            address=_rebase_loaded_address(original_elf, module_info.address, delta),
        )

    return replace(
        model,
        elf_header=relocated_elf.header,
        program_headers=relocated_elf.program_headers,
        sections=relocated_elf.sections,
        module_info=module_info,
        imports=[_rebase_library(library, original_elf, delta) for library in model.imports],
        exports=[_rebase_library(library, original_elf, delta) for library in model.exports],
        relocations=[replace(relocation) for relocation in model.relocations],
        warnings=list(model.warnings),
    )


def build_relocated_load_view(
    data: bytes,
    elf: ElfImage,
    model: ExecutableModel,
    *,
    load_address: int,
) -> RelocatedLoadView:
    if elf.endianness != "little":
        raise ParseError("Relocated PSP load views require a little-endian ELF")
    if load_address < 0 or load_address > UINT32_MAX:
        raise ParseError("PSP load address must fit in an unsigned 32-bit address")

    loads = _loaded_segments(elf)
    if not loads:
        raise ParseError("Relocated PSP load view requires at least one PT_LOAD segment")

    original_image_base = min(segment.vaddr for segment in loads)
    delta = load_address - original_image_base
    if not -UINT32_LIMIT < delta < UINT32_LIMIT:
        raise ParseError("PSP relocation delta is outside the supported 32-bit range")
    _validate_rebased_layout(elf, delta)

    segment_bases = {
        segment.index: segment.vaddr + delta
        for segment in loads
    }
    patched = bytearray(data)
    applied = 0
    relocations = list(model.relocations)

    for index, relocation in enumerate(relocations):
        source_index, target_index = _relocation_segments(relocation)
        _segment(elf, target_index, "target")
        _, file_offset = _source_file_offset(elf, relocation)
        if file_offset < 0 or file_offset + 4 > len(patched):
            raise ParseError("Relocation source word extends beyond the input")

        word = int.from_bytes(patched[file_offset : file_offset + 4], "little")
        lo16 = None
        if relocation.type == 5 and relocation.addend is None:
            lo16 = _type_a_hi16_low_half(data, elf, relocations, index)
        relocated = apply_psp_relocation_word(
            word,
            relocation,
            segment_bases[target_index],
            lo16=lo16,
        )
        patched[file_offset : file_offset + 4] = relocated.to_bytes(4, "little")
        applied += 1

    relocated_elf = _rebase_elf(elf, bytes(patched), delta)
    relocated_model = _rebase_model(model, elf, relocated_elf, delta)
    return RelocatedLoadView(
        load_address=load_address,
        original_image_base=original_image_base,
        address_delta=delta,
        segment_bases=segment_bases,
        applied_relocations=applied,
        elf=relocated_elf,
        model=relocated_model,
    )
