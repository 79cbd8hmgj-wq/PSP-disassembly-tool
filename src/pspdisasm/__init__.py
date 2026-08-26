"""PSP executable analysis and Allegrex disassembly toolkit."""

from .advanced import analyze_advanced
from .analyzer import analyze_bytes, analyze_file
from .disassembler import disassemble_bytes, disassemble_file
from .decompiler import decompile_project_function
from .matcher import match_project_function
from .project import generate_project

__version__ = "0.6.0"

__all__ = [
    "analyze_advanced",
    "analyze_bytes",
    "analyze_file",
    "disassemble_bytes",
    "disassemble_file",
    "decompile_project_function",
    "match_project_function",
    "generate_project",
]
