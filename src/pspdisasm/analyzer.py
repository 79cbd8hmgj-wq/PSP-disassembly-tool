from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .detect import InputKind, detect_input
from .elf32 import parse_elf32
from .model import ExecutableModel
from .prx import ET_SCE_PSPRELEXEC, MODULE_INFO_SECTION, analyze_prx
from .psp_container import parse_psp_container_header


def analyze_bytes(data: bytes, source_name: str = "<memory>") -> ExecutableModel:
    kind = detect_input(data)
    if kind is InputKind.PSP_CONTAINER:
        header = parse_psp_container_header(data)
        return ExecutableModel(
            source_name=source_name,
            input_kind=kind.value,
            executable_kind="encrypted_psp_container",
            needs_decryption=True,
            container_header=header,
            warnings=[
                "PSP ~PSP container header parsed; executable body requires decryption/decompression before ELF disassembly."
            ],
        )

    elf = parse_elf32(data)
    warnings: list[str] = []
    if elf.header.machine != 8:
        warnings.append(f"ELF machine is {elf.header.machine}, not EM_MIPS (8); PSP analysis may not apply")
    if elf.endianness != "little":
        warnings.append("PSP executables are expected to be little-endian; this ELF is not")

    has_module_section = any(section.name == MODULE_INFO_SECTION for section in elf.sections)
    is_prx = elf.header.file_type == ET_SCE_PSPRELEXEC
    module_info = None
    imports = []
    exports = []
    relocations = []
    if is_prx or has_module_section:
        prx = analyze_prx(data, elf)
        module_info = prx.module_info
        imports = prx.imports
        exports = prx.exports
        relocations = prx.relocations
        warnings.extend(prx.warnings)

    return ExecutableModel(
        source_name=source_name,
        input_kind=kind.value,
        executable_kind="prx" if is_prx else "elf",
        needs_decryption=False,
        endianness=elf.endianness,
        elf_header=elf.header,
        program_headers=elf.program_headers,
        sections=elf.sections,
        module_info=module_info,
        imports=imports,
        exports=exports,
        relocations=relocations,
        warnings=warnings,
    )


def analyze_file(path: Path | str) -> ExecutableModel:
    source = Path(path)
    return analyze_bytes(source.read_bytes(), str(source))


def model_to_dict(model: ExecutableModel) -> dict[str, Any]:
    return asdict(model)
