"""PSP executable analysis and Allegrex disassembly toolkit."""

from .advanced import analyze_advanced
from .analyzer import analyze_bytes, analyze_file
from .asset_discovery import analyze_assets
from .data_typing import analyze_data_types
from .disc import scan_game_disc
from .disassembler import disassemble_bytes, disassemble_file
from .decompiler import decompile_project_function
from .game_project import generate_game_project
from .game_resources import analyze_game_resources
from .linker import ModuleAnalysisInput, link_modules
from .matcher import match_project_function
from .nids import NidDatabase, load_nid_databases
from .project import generate_project
from .prxreloc2 import apply_psp_relocation_word, decode_prxreloc2
from .resource_containers import (
    ContainerCandidateProfile,
    ContainerEntry,
    ContainerFamily,
    ContainerInspection,
    ResourceContainerParser,
    group_container_families,
    profile_container_candidate,
    select_container_parser,
)

__version__ = "0.9.0"

__all__ = [
    "ContainerCandidateProfile",
    "ContainerEntry",
    "ContainerFamily",
    "ContainerInspection",
    "ModuleAnalysisInput",
    "NidDatabase",
    "ResourceContainerParser",
    "analyze_advanced",
    "analyze_assets",
    "analyze_bytes",
    "analyze_data_types",
    "analyze_file",
    "analyze_game_resources",
    "apply_psp_relocation_word",
    "decode_prxreloc2",
    "decompile_project_function",
    "disassemble_bytes",
    "disassemble_file",
    "generate_game_project",
    "generate_project",
    "group_container_families",
    "link_modules",
    "load_nid_databases",
    "match_project_function",
    "profile_container_candidate",
    "scan_game_disc",
    "select_container_parser",
]
