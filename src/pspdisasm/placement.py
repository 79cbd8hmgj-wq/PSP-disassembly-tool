from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ParseError
from .model import ExecutableModel, ProgramHeader


ET_EXEC = 2
PT_LOAD = 1
PSP_USER_MEMORY_BASE = 0x08800000
PSP_USER_RESERVED_PREFIX = 0x4000
PSP_FIRST_USER_ALLOCATION = PSP_USER_MEMORY_BASE + PSP_USER_RESERVED_PREFIX
PSP_ALLOCATOR_GRAIN = 0x10
UINT32_LIMIT = 1 << 32


@dataclass(slots=True)
class ModulePlacementInput:
    path: str
    is_boot: bool
    model: ExecutableModel


@dataclass(slots=True)
class ModulePlacement:
    path: str
    load_address: int
    original_image_base: int
    image_size: int
    image_end: int
    alignment: int
    placement_kind: str
    placement_confidence: float
    runtime_address_claim: bool
    requires_relocation: bool
    placement_evidence: list[str] = field(default_factory=list)


def _loaded_segments(model: ExecutableModel) -> list[ProgramHeader]:
    return sorted(
        [segment for segment in model.program_headers if segment.type == PT_LOAD and segment.memsz > 0],
        key=lambda segment: (segment.vaddr, segment.index),
    )


def _layout(model: ExecutableModel) -> tuple[int, int, int]:
    segments = _loaded_segments(model)
    if not segments:
        raise ParseError("Runtime placement requires at least one non-empty PT_LOAD segment")

    image_base = min(segment.vaddr for segment in segments)
    image_end = max(segment.vaddr + segment.memsz for segment in segments)
    image_size = image_end - image_base
    if image_size <= 0 or image_end > UINT32_LIMIT:
        raise ParseError("Runtime placement image extends outside the 32-bit address space")

    requested = segments[0].align
    if requested <= 1 or requested & (requested - 1):
        requested = PSP_ALLOCATOR_GRAIN
    alignment = max(PSP_ALLOCATOR_GRAIN, requested)
    return image_base, image_size, alignment


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _overlap(start: int, end: int, occupied: list[tuple[int, int]]) -> tuple[int, int] | None:
    for existing_start, existing_end in sorted(occupied):
        if start < existing_end and existing_start < end:
            return existing_start, existing_end
    return None


def _find_free(
    start: int,
    image_size: int,
    alignment: int,
    occupied: list[tuple[int, int]],
) -> int:
    candidate = _align_up(start, alignment)
    while True:
        end = candidate + image_size
        if candidate < 0 or end > UINT32_LIMIT:
            raise ParseError("No 32-bit address range remains for module analysis placement")
        collision = _overlap(candidate, end, occupied)
        if collision is None:
            return candidate
        candidate = _align_up(collision[1], alignment)


def _fixed_placement(item: ModulePlacementInput) -> ModulePlacement:
    image_base, image_size, alignment = _layout(item.model)
    image_end = image_base + image_size
    return ModulePlacement(
        path=item.path,
        load_address=image_base,
        original_image_base=image_base,
        image_size=image_size,
        image_end=image_end,
        alignment=alignment,
        placement_kind="fixed",
        placement_confidence=1.0,
        runtime_address_claim=True,
        requires_relocation=False,
        placement_evidence=[
            "ET_EXEC carries fixed PT_LOAD virtual addresses, so no PSP relocation placement is required."
        ],
    )


def _boot_placement(item: ModulePlacementInput) -> ModulePlacement:
    image_base, image_size, alignment = _layout(item.model)
    load_address = _align_up(PSP_FIRST_USER_ALLOCATION, alignment)
    image_end = load_address + image_size
    if image_end > UINT32_LIMIT:
        raise ParseError("Relocatable boot module extends outside the 32-bit address space")

    if load_address == PSP_FIRST_USER_ALLOCATION:
        evidence = [
            "Relocatable boot module uses the PSP low-allocation path; user memory starts at 0x08800000 and the initial 0x4000 bytes are reserved, making 0x08804000 the first default allocation."
        ]
    else:
        evidence = [
            "Relocatable boot module uses the PSP low-allocation path; the first default allocation is 0x08804000 and the module's PT_LOAD alignment moves the selected base to "
            f"0x{load_address:08X}."
        ]

    return ModulePlacement(
        path=item.path,
        load_address=load_address,
        original_image_base=image_base,
        image_size=image_size,
        image_end=image_end,
        alignment=alignment,
        placement_kind="boot_inferred",
        placement_confidence=0.95,
        runtime_address_claim=True,
        requires_relocation=True,
        placement_evidence=evidence,
    )


def plan_module_placements(inputs: list[ModulePlacementInput]) -> list[ModulePlacement]:
    """Choose deterministic PSP addresses while separating runtime evidence from analysis-only placement.

    Fixed ET_EXEC addresses and the boot module's low-allocation address are
    independent runtime claims: separately loaded modules are not assumed to
    coexist merely because they are present on the same disc. Synthetic
    placements for secondary relocatable PRXs, however, avoid all recorded
    ranges so the combined analysis address space remains deterministic and
    collision-free.
    """

    ordered = sorted(inputs, key=lambda item: item.path.casefold())
    fixed: dict[str, ModulePlacement] = {}

    for item in ordered:
        header = item.model.elf_header
        if header is None:
            raise ParseError(f"Runtime placement requires an ELF header for {item.path}")
        if header.file_type == ET_EXEC:
            fixed[item.path] = _fixed_placement(item)

    relocatable = [item for item in ordered if item.path not in fixed]
    boot_items = sorted(
        [item for item in relocatable if item.is_boot],
        key=lambda item: item.path.casefold(),
    )
    secondary_items = sorted(
        [item for item in relocatable if not item.is_boot],
        key=lambda item: item.path.casefold(),
    )

    planned: dict[str, ModulePlacement] = dict(fixed)
    boot_ranges: list[tuple[int, int]] = []
    cursor = PSP_FIRST_USER_ALLOCATION

    for index, item in enumerate(boot_items):
        if index == 0:
            placement = _boot_placement(item)
        else:
            # A normal PSP disc has only one selected boot module. If callers
            # supply more than one, keep the first evidence-backed boot claim
            # and treat the rest conservatively as analysis-only modules.
            image_base, image_size, alignment = _layout(item.model)
            load_address = _find_free(cursor, image_size, alignment, boot_ranges)
            placement = ModulePlacement(
                path=item.path,
                load_address=load_address,
                original_image_base=image_base,
                image_size=image_size,
                image_end=load_address + image_size,
                alignment=alignment,
                placement_kind="analysis",
                placement_confidence=0.50,
                runtime_address_claim=False,
                requires_relocation=True,
                placement_evidence=[
                    "Only one boot module can receive the PSP default boot-placement claim; this additional boot-marked image uses a deterministic analysis-only placement."
                ],
            )
        planned[item.path] = placement
        boot_ranges.append((placement.load_address, placement.image_end))
        cursor = max(cursor, placement.image_end)

    occupied = [
        (placement.load_address, placement.image_end)
        for placement in fixed.values()
    ]
    occupied.extend(boot_ranges)

    for item in secondary_items:
        image_base, image_size, alignment = _layout(item.model)
        load_address = _find_free(cursor, image_size, alignment, occupied)
        image_end = load_address + image_size
        placement = ModulePlacement(
            path=item.path,
            load_address=load_address,
            original_image_base=image_base,
            image_size=image_size,
            image_end=image_end,
            alignment=alignment,
            placement_kind="analysis",
            placement_confidence=0.50,
            runtime_address_claim=False,
            requires_relocation=True,
            placement_evidence=[
                "Secondary PRX runtime load order and allocation direction/options are not encoded on disc; this deterministic low-memory placement is for analysis only."
            ],
        )
        planned[item.path] = placement
        occupied.append((load_address, image_end))
        cursor = image_end

    return [planned[item.path] for item in ordered]
