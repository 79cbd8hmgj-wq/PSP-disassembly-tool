from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_file, model_to_dict
from .errors import ParseError
from .model import ExecutableModel


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pspdisasm", description="PSP executable intelligence and disassembly toolkit")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="Analyze PSP ELF/PRX/~PSP metadata")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--json", metavar="PATH", help="Write normalized JSON; use '-' for stdout")
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "analyze":
        return 2
    try:
        model = analyze_file(args.input)
    except (OSError, ParseError) as exc:
        print(f"pspdisasm: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = json.dumps(model_to_dict(model), indent=2, sort_keys=True)
        if args.json == "-":
            print(payload)
        else:
            Path(args.json).write_text(payload + "\n", encoding="utf-8")
    else:
        print(_summary(model))
    return 0
