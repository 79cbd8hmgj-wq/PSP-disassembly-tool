from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .analyzer import analyze_bytes
from .elf32 import parse_elf32
from .engines.spim import SpimdisasmAdapter
from .errors import DisassemblyError
from .load_view import build_relocated_load_view
from .model import DisassemblyResult


def disassemble_bytes(
    data: bytes,
    source_name: str = "<memory>",
    *,
    load_address: int | None = None,
) -> DisassemblyResult:
    model = analyze_bytes(data, source_name)
    if model.needs_decryption:
        raise DisassemblyError(
            "Instruction disassembly requires decrypted ELF/PRX bytes; this ~PSP container requires decryption first."
        )
    elf = parse_elf32(data)
    if load_address is not None:
        view = build_relocated_load_view(
            data,
            elf,
            model,
            load_address=load_address,
        )
        elf = view.elf
        model = view.model
    return SpimdisasmAdapter().analyze(elf, model)


def disassemble_file(
    path: Path | str,
    *,
    load_address: int | None = None,
) -> DisassemblyResult:
    source = Path(path)
    return disassemble_bytes(
        source.read_bytes(),
        str(source),
        load_address=load_address,
    )


def result_to_dict(result: DisassemblyResult) -> dict[str, Any]:
    return asdict(result)
