from __future__ import annotations

from dataclasses import dataclass, replace

from .errors import ParseError
from .model import ElfImage, ExecutableModel, ProgramHeader
from .prxreloc2 import apply_psp_relocation_word


PT_LOAD = 1
SHF_ALLOC = 0x2


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


def _segment_index(relocation, shift: int, explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    return (relocation.info >> shift) & 0xFF


def _segment(elf: ElfImage, index: int, role: str) -> ProgramHeader:
    if index < 0 or index >= len(elf.program_headers):
        raise ParseError(f"Relocation {role} segment index {index} is out of range")
    segment = elf.program_headers[index]
    if segment.type != PT_LOAD:
        raise ParseError(f"Relocation {role} segment {index} is not PT_LOAD")
    return segment


def _contains_address(segment: ProgramHeader, address: int) -> bool:
    return segment.vaddr <= address < segment.vaddr + segment.memsz


def _rebase_elf(elf: ElfImage, data: bytes, delta: int) -> ElfImage:
    original_loads = _loaded_segments(elf)
    entry = elf.header.entry
    if any(_contains_address(segment, entry) for segment in original_loads):
        entry = (entry + delta) & 0xFFFFFFFF

    header = replace(elf.header, entry=entry)
    program_headers = [
        replace(
            segment,
            vaddr=(segment.vaddr + delta) & 0xFFFFFFFF,
            paddr=(segment.paddr + delta) & 0xFFFFFFFF,
        )
        if segment.type == PT_LOAD
        else replace(segment)
        for segment in elf.program_headers
    ]
    sections = [
        replace(section, addr=(section.addr + delta) & 0xFFFFFFFF)
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


def _rebase_model(model: ExecutableModel, relocated_elf: ElfImage) -> ExecutableModel:
    return replace(
        model,
        elf_header=relocated_elf.header,
        program_headers=relocated_elf.program_headers,
        sections=relocated_elf.sections,
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
    if load_address < 0 or load_address > 0xFFFFFFFF:
        raise ParseError("PSP load address must fit in an unsigned 32-bit address")

    loads = _loaded_segments(elf)
    if not loads:
        raise ParseError("Relocated PSP load view requires at least one PT_LOAD segment")

    original_image_base = min(segment.vaddr for segment in loads)
    if load_address < original_image_base:
        delta = load_address - original_image_base
    else:
        delta = load_address - original_image_base
    if not -(1 << 32) < delta < (1 << 32):
        raise ParseError("PSP relocation delta is outside the supported 32-bit range")

    segment_bases = {
        segment.index: (segment.vaddr + delta) & 0xFFFFFFFF
        for segment in loads
    }
    patched = bytearray(data)
    applied = 0

    for relocation in model.relocations:
        source_index = _segment_index(relocation, 8, relocation.source_segment_index)
        target_index = _segment_index(relocation, 16, relocation.target_segment_index)
        source = _segment(elf, source_index, "source")
        _segment(elf, target_index, "target")

        if relocation.offset < 0 or relocation.offset + 4 > source.filesz:
            raise ParseError(
                f"Relocation source offset 0x{relocation.offset:X} is not a complete file-backed word "
                f"inside PT_LOAD segment {source_index}"
            )
        file_offset = source.offset + relocation.offset
        if file_offset < 0 or file_offset + 4 > len(patched):
            raise ParseError("Relocation source word extends beyond the input")

        word = int.from_bytes(patched[file_offset : file_offset + 4], "little")
        relocated = apply_psp_relocation_word(
            word,
            relocation,
            segment_bases[target_index],
        )
        patched[file_offset : file_offset + 4] = relocated.to_bytes(4, "little")
        applied += 1

    relocated_elf = _rebase_elf(elf, bytes(patched), delta)
    relocated_model = _rebase_model(model, relocated_elf)
    return RelocatedLoadView(
        load_address=load_address,
        original_image_base=original_image_base,
        address_delta=delta,
        segment_bases=segment_bases,
        applied_relocations=applied,
        elf=relocated_elf,
        model=relocated_model,
    )
