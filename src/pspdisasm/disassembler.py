from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .analyzer import analyze_bytes
from .elf32 import parse_elf32
from .engines.spim import SpimdisasmAdapter
from .errors import DisassemblyError
from .model import DisassemblyResult


def disassemble_bytes(data: bytes, source_name: str = "<memory>") -> DisassemblyResult:
    model = analyze_bytes(data, source_name)
    if model.needs_decryption:
        raise DisassemblyError(
            "Instruction disassembly requires decrypted ELF/PRX bytes; this ~PSP container requires decryption first."
        )
    elf = parse_elf32(data)
    return SpimdisasmAdapter().analyze(elf, model)


def disassemble_file(path: Path | str) -> DisassemblyResult:
    source = Path(path)
    return disassemble_bytes(source.read_bytes(), str(source))


def result_to_dict(result: DisassemblyResult) -> dict[str, Any]:
    return asdict(result)
