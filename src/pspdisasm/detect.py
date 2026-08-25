from __future__ import annotations

from enum import Enum

from .errors import ParseError


class InputKind(str, Enum):
    ELF32 = "elf32"
    PSP_CONTAINER = "psp_container"


def detect_input(data: bytes) -> InputKind:
    if data.startswith(b"\x7fELF"):
        return InputKind.ELF32
    if data.startswith(b"~PSP"):
        return InputKind.PSP_CONTAINER
    raise ParseError("Unsupported input format: expected ELF or ~PSP header")
