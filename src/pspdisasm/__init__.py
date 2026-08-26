"""PSP executable analysis and Allegrex disassembly toolkit."""

from .advanced import analyze_advanced
from .analyzer import analyze_bytes, analyze_file
from .asset_discovery import analyze_assets
from .data_typing import analyze_data_types
from .disassembler import disassemble_bytes, disassemble_file
from .decompiler import decompile_project_function
from .game_image import analyze_game_image, extract_game_executables, parse_param_sfo, read_game_file
from .linker import ModuleAnalysisInput, link_modules
from .matcher import match_project_function
from .nids import NidDatabase, load_nid_databases
from .project import generate_project

__version__ = "0.10.0"

__all__ = [
    "ModuleAnalysisInput",
    "NidDatabase",
    "analyze_advanced",
    "analyze_assets",
    "analyze_bytes",
    "analyze_data_types",
    "analyze_file",
    "analyze_game_image",
    "disassemble_bytes",
    "disassemble_file",
    "decompile_project_function",
    "extract_game_executables",
    "generate_project",
    "link_modules",
    "load_nid_databases",
    "match_project_function",
    "parse_param_sfo",
    "read_game_file",
]
