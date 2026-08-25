import pytest

from pspdisasm.detect import InputKind, detect_input
from pspdisasm.errors import ParseError


def test_detects_elf32_magic():
    assert detect_input(b"\x7fELF" + b"\x00" * 64) is InputKind.ELF32


def test_detects_psp_container_magic():
    assert detect_input(b"~PSP" + b"\x00" * 64) is InputKind.PSP_CONTAINER


def test_rejects_unknown_input():
    with pytest.raises(ParseError, match="Unsupported input format"):
        detect_input(b"not a psp executable")
