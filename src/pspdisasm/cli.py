from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import re
import sys
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_file, model_to_dict
from .disc import scan_game_disc
from .disassembler import disassemble_file, result_to_dict
from .decompiler import DEFAULT_M2C_TARGET, decompile_project_function
from .errors import (
    DecompilationError,
    DecompilerUnavailableError,
    DisassemblyError,
    EngineUnavailableError,
    MatcherUnavailableError,
    MatchingError,
    ParseError,
)
from .game_project import generate_game_project
from .linker import ModuleAnalysisInput, link_modules
from .matcher import match_project_function
from .model import DisassemblyResult, ExecutableModel, ModuleLinkAnalysis
from .nids import load_nid_databases
from .project import generate_project


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pspdisasm", description="PSP executable intelligence and disassembly toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    game = sub.add_parser("game", help="Inventory a PSP ISO/CSO and extract executable candidates")
    game.add_argument("input", type=Path)
    game.add_argument("output", type=Path)

    game_project = sub.add_parser(
        "game-project",
        help="Analyze PSP ISO/CSO modules and resources and build game-wide decompilation workspaces",
    )
    game_project.add_argument("input", type=Path)
    game_project.add_argument("output", type=Path)
    game_project.add_argument(
        "--nid-db",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="NID JSON or PSPLibDoc-style CSV database; may be repeated and later files win",
    )

    analyze = sub.add_parser("analyze", help="Analyze PSP ELF/PRX/~PSP metadata")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--json", metavar="PATH", help="Write normalized JSON; use '-' for stdout")

    disasm = sub.add_parser("disasm", help="Disassemble decrypted PSP ELF/PRX Allegrex code")
    disasm.add_argument("input", type=Path)
    disasm.add_argument("--json", metavar="PATH", help="Write normalized disassembly JSON; use '-' for stdout")
    disasm.add_argument("--asm-dir", type=Path, metavar="DIR", help="Write one assembly file per executable section")
    disasm.add_argument(
        "--load-address",
        type=lambda value: int(value, 0),
        metavar="ADDRESS",
        help="Explicit PSP runtime load address in decimal or 0x hexadecimal form",
    )

    project = sub.add_parser("project", help="Generate a Splat PSP decompilation workspace")
    project.add_argument("input", type=Path)
    project.add_argument("output", type=Path)
    project.add_argument(
        "--nid-db",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="NID JSON or PSPLibDoc-style CSV database; may be repeated and later files win",
    )

    link = sub.add_parser("link", help="Resolve and link PSP imports/exports across multiple modules")
    link.add_argument("inputs", type=Path, nargs="+", metavar="MODULE")
    link.add_argument(
        "--nid-db",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="NID JSON or PSPLibDoc-style CSV database; may be repeated and later files win",
    )
    link.add_argument("--json", metavar="PATH", help="Write module-link JSON; use '-' for stdout")

    decompile = sub.add_parser("decompile", help="Generate an assisted C draft for one project function using m2c")
    decompile.add_argument("project", type=Path)
    decompile.add_argument("function", help="Function name, decimal address, or 0x hexadecimal address")
    decompile.add_argument("--m2c", type=Path, metavar="PATH", help="Path to m2c executable or m2c.py")
    decompile.add_argument("--context", type=Path, action="append", default=[], metavar="FILE", help="Preprocessed C context file; may be repeated")
    decompile.add_argument("--output", type=Path, metavar="PATH", help="Override generated C output path")
    decompile.add_argument("--target", default=DEFAULT_M2C_TARGET, metavar="TARGET", help=f"m2c target triple (default: {DEFAULT_M2C_TARGET})")

    match = sub.add_parser("match", help="Compare one recompiled function against original PSP instructions with asm-differ")
    match.add_argument("project", type=Path)
    match.add_argument("function", help="Function name, decimal address, or 0x hexadecimal address")
    match.add_argument("--object", dest="candidate_object", type=Path, required=True, metavar="PATH", help="Recompiled object containing the selected function")
    match.add_argument("--asm-differ", type=Path, metavar="PATH", help="Path to asm-differ executable or diff.py")
    match.add_argument("--objdump", type=Path, metavar="PATH", help="Path to a MIPS-capable objdump, preferably psp-objdump")
    match.add_argument("--reference-object", type=Path, metavar="PATH", help="Use an explicit original/reference object instead of synthesizing one")
    match.add_argument("--build-command", metavar="COMMAND", help="Command to run from the project directory before matching; parsed without a shell")
    match.add_argument("--section", default=".text", metavar="SECTION", help="Object section to compare (default: .text)")
    match.add_argument("--ignore-large-imms", action="store_true", help="Pass asm-differ's large-immediate normalization flag")
    match.add_argument("--timeout", type=float, default=120.0, metavar="SECONDS", help="Timeout for build and asm-differ commands (default: 120)")
    return parser


def _summary(model: ExecutableModel) -> str:
    lines = [
        f"Input: {model.source_name}",
        f"Kind: {model.executable_kind}",
        f"Needs decryption: {'yes' if model.needs_decryption else 'no'}",
    ]
    if model.elf_header is not None:
        lines.extend(
            [
                f"Entry: 0x{model.elf_header.entry:08X}",
                f"Sections: {len(model.sections)}",
                f"Program headers: {len(model.program_headers)}",
                f"Relocations: {len(model.relocations)}",
            ]
        )
    if model.module_info is not None:
        lines.extend(
            [
                f"Module: {model.module_info.name}",
                f"Imports: {len(model.imports)} libraries",
                f"Exports: {len(model.exports)} libraries",
            ]
        )
    if model.container_header is not None:
        lines.extend(
            [
                f"Module: {model.container_header.module_name}",
                f"Declared ELF size: 0x{model.container_header.elf_size:X}",
                f"Decrypt mode: {model.container_header.decrypt_mode}",
            ]
        )
    if model.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in model.warnings)
    return "\n".join(lines)


def _disasm_summary(result: DisassemblyResult) -> str:
    lines = [
        f"Input: {result.source_name}",
        "Engines: " + ", ".join(f"{engine.name} {engine.version}" for engine in result.engines),
        f"Functions: {len(result.functions)}",
        f"Symbols: {len(result.symbols)}",
        f"References: {len(result.references)}",
        f"Strings: {len(result.strings)}",
        f"Executable sections: {len(result.assembly_sections)}",
    ]
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    return "\n".join(lines)


def _link_summary(result: ModuleLinkAnalysis) -> str:
    lines = [
        f"Modules: {len(result.modules)}",
        f"NID resolutions: {len(result.resolutions)}",
        f"Cross-module links: {len(result.links)}",
        f"Propagated symbols: {len(result.propagated_symbols)}",
    ]
    for link in result.links:
        lines.append(
            f"  {link.importing_module} -> {link.exporting_module}: "
            f"{link.name} ({link.library}/0x{link.nid:08X})"
        )
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    return "\n".join(lines)


def _write_json(payload: dict, output: str | None) -> bool:
    if not output:
        return False
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if output == "-":
        print(encoded)
    else:
        Path(output).write_text(encoded + "\n", encoding="utf-8")
    return True


def _assembly_filename(name: str, address: int, used: set[str]) -> str:
    base = name.lstrip(".")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    if not base:
        base = f"section_{address:08X}"
    filename = f"{base}.s"
    if filename in used:
        filename = f"{base}_{address:08X}.s"
    used.add(filename)
    return filename


def _write_assembly(result: DisassemblyResult, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    for section in result.assembly_sections:
        filename = _assembly_filename(section.name, section.address, used)
        (directory / filename).write_text(section.assembly, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "game":
            manifest = scan_game_disc(args.input, args.output)
            print(f"Game: {manifest.title or '<unknown>'}")
            if manifest.disc_id:
                print(f"Disc ID: {manifest.disc_id}")
            print(f"Image: {manifest.image_format.upper()}")
            print(f"Boot: {manifest.boot_path}")
            print(f"Files: {len(manifest.files)}")
            print(f"Executable candidates: {len(manifest.modules)}")
            print(f"Manifest: {args.output / 'metadata' / 'disc.json'}")
            for warning in manifest.warnings:
                print(f"Warning: {warning}")
            return 0

        if args.command == "game-project":
            result = generate_game_project(args.input, args.output, nid_databases=args.nid_db)
            analysis = json.loads(result.analysis_path.read_text(encoding="utf-8"))
            print(f"Game: {analysis.get('title') or '<unknown>'}")
            if analysis.get("disc_id"):
                print(f"Disc ID: {analysis['disc_id']}")
            print(f"Executable candidates: {result.module_count}")
            print(f"Analyzed modules: {result.analyzed_count}")
            print(f"Needs decryption: {result.needs_decryption_count}")
            print(f"Failed modules: {result.failed_count}")
            print(f"Cross-module links: {len(analysis.get('links', {}).get('links', []))}")
            print(f"Resources: {result.resource_count}")
            print(f"Known resources: {result.known_resource_count}")
            print(f"Unknown resources: {result.unknown_resource_count}")
            print(f"Embedded resources: {result.embedded_resource_count}")
            print(f"Container candidates: {result.container_candidate_count}")
            print(f"Inspected containers: {result.container_inspection_count}")
            print(f"Container entries: {result.container_entry_count}")
            print(f"Game analysis: {result.analysis_path}")
            if result.resources_path is not None:
                print(f"Resource analysis: {result.resources_path}")
            if result.containers_path is not None:
                print(f"Container analysis: {result.containers_path}")
            return 0

        if args.command == "analyze":
            model = analyze_file(args.input)
            if not _write_json(model_to_dict(model), args.json):
                print(_summary(model))
            return 0

        if args.command == "disasm":
            result = disassemble_file(args.input, load_address=args.load_address)
            if args.asm_dir is not None:
                _write_assembly(result, args.asm_dir)
            if not _write_json(result_to_dict(result), args.json):
                print(_disasm_summary(result))
            return 0

        if args.command == "project":
            result = generate_project(args.input, args.output, nid_databases=args.nid_db)
            print(f"Project: {result.output_dir}")
            print(f"Base VRAM: 0x{result.base_vram:08X}")
            print(f"Target size: 0x{result.target_size:X}")
            print(f"Splat config: {result.config_path}")
            return 0

        if args.command == "link":
            database = load_nid_databases(args.nid_db)
            units: list[ModuleAnalysisInput] = []
            for module_path in args.inputs:
                model = analyze_file(module_path)
                disassembly = disassemble_file(module_path)
                units.append(ModuleAnalysisInput(model, disassembly))
            result = link_modules(units, database)
            if not _write_json(asdict(result), args.json):
                print(_link_summary(result))
            return 0

        if args.command == "decompile":
            result = decompile_project_function(
                args.project,
                args.function,
                m2c_path=args.m2c,
                contexts=args.context,
                output_path=args.output,
                target=args.target,
            )
            project_dir = result.project_dir
            try:
                c_display = result.output_path.relative_to(project_dir)
                metadata_display = result.metadata_path.relative_to(project_dir)
            except ValueError:
                c_display = result.output_path
                metadata_display = result.metadata_path
            print(f"Function: {result.function_name} @ 0x{result.function_address:08X}")
            print(f"C draft: {c_display}")
            print(f"Metadata: {metadata_display}")
            if result.backend_version:
                print(f"Backend: {result.backend_name} {result.backend_version}")
            else:
                print(f"Backend: {result.backend_name}")
            for warning in result.warnings:
                print(f"Warning: {warning}")
            return 0

        if args.command == "match":
            result = match_project_function(
                args.project,
                args.function,
                candidate_object=args.candidate_object,
                asm_differ_path=args.asm_differ,
                objdump_path=args.objdump,
                reference_object=args.reference_object,
                build_command=args.build_command,
                section=args.section,
                ignore_large_imms=args.ignore_large_imms,
                timeout=args.timeout,
            )
            project_dir = result.project_dir

            def display(path: Path) -> Path:
                try:
                    return path.relative_to(project_dir)
                except ValueError:
                    return path

            print(f"Function: {result.function_name} @ 0x{result.function_address:08X}")
            print(f"Similarity: {result.similarity_percent:.2f}%")
            print(f"Score: {result.raw_score} / {result.max_score}")
            print(
                "Rows: "
                f"{result.matching_rows} matching, {result.changed_rows} changed, "
                f"{result.added_rows} added, {result.removed_rows} removed"
            )
            print(f"Candidate object: {display(result.candidate_object)}")
            print(f"Reference object: {display(result.reference_object)}")
            print(f"Metadata: {display(result.metadata_path)}")
            print(f"Raw report: {display(result.raw_report_path)}")
            if result.backend_version:
                print(f"Backend: {result.backend_name} {result.backend_version}")
            else:
                print(f"Backend: {result.backend_name}")
            for warning in result.warnings:
                print(f"Warning: {warning}")
            return 0
    except (
        OSError,
        ValueError,
        ParseError,
        EngineUnavailableError,
        DisassemblyError,
        DecompilerUnavailableError,
        DecompilationError,
        MatcherUnavailableError,
        MatchingError,
    ) as exc:
        print(f"pspdisasm: {exc}", file=sys.stderr)
        return 2
    return 2
