"""PSP executable analysis and Allegrex disassembly toolkit."""

from .analyzer import analyze_bytes, analyze_file
from .disassembler import disassemble_bytes, disassemble_file
from .project import generate_project

__version__ = "0.3.0"

__all__ = [
    "analyze_bytes",
    "analyze_file",
    "disassemble_bytes",
    "disassemble_file",
    "generate_project",
]
