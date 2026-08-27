from __future__ import annotations

from pspdisasm.model import ElfHeader, ExecutableModel, ProgramHeader
from pspdisasm.placement import ModulePlacementInput, plan_module_placements


def _model(file_type: int, base: int, size: int) -> ExecutableModel:
    header = ElfHeader(
        file_type=file_type,
        machine=8,
        version=1,
        entry=base,
        phoff=0x34,
        shoff=0,
        flags=0,
        ehsize=0x34,
        phentsize=0x20,
        phnum=1,
        shentsize=0x28,
        shnum=0,
        shstrndx=0,
    )
    segment = ProgramHeader(
        index=0,
        type=1,
        offset=0x100,
        vaddr=base,
        paddr=base,
        filesz=size,
        memsz=size,
        flags=7,
        align=0x10,
    )
    return ExecutableModel(
        source_name="fixture.prx",
        input_kind="elf",
        executable_kind="prx" if file_type != 2 else "elf",
        needs_decryption=False,
        endianness="little",
        elf_header=header,
        program_headers=[segment],
    )


def _model_with_stricter_later_alignment() -> ExecutableModel:
    model = _model(0xFFA0, 0, 0x200)
    model.elf_header.phnum = 2
    model.program_headers.append(
        ProgramHeader(
            index=1,
            type=1,
            offset=0x8000,
            vaddr=0x8000,
            paddr=0x8000,
            filesz=0x100,
            memsz=0x100,
            flags=6,
            align=0x8000,
        )
    )
    return model


def test_relocatable_boot_evidence_is_not_displaced_by_independently_loaded_fixed_module():
    boot = ModulePlacementInput(
        path="PSP_GAME/SYSDIR/EBOOT.BIN",
        is_boot=True,
        model=_model(0xFFA0, 0, 0x200),
    )
    fixed_secondary = ModulePlacementInput(
        path="PSP_GAME/USRDIR/FIXED.PRX",
        is_boot=False,
        model=_model(2, 0x08804000, 0x1000),
    )

    placements = {item.path: item for item in plan_module_placements([fixed_secondary, boot])}

    assert placements[boot.path].load_address == 0x08804000
    assert placements[boot.path].placement_kind == "boot_inferred"
    assert placements[boot.path].runtime_address_claim is True
    assert placements[fixed_secondary.path].load_address == 0x08804000
    assert placements[fixed_secondary.path].placement_kind == "fixed"


def test_relocatable_placement_honors_strictest_pt_load_alignment():
    boot = ModulePlacementInput(
        path="PSP_GAME/SYSDIR/EBOOT.BIN",
        is_boot=True,
        model=_model_with_stricter_later_alignment(),
    )

    placement = plan_module_placements([boot])[0]

    assert placement.alignment == 0x8000
    assert placement.load_address == 0x08808000
    assert placement.load_address % 0x8000 == 0
