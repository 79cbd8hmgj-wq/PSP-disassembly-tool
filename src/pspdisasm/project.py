from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

import yaml

from .advanced import analyze_advanced
from .analyzer import analyze_bytes, model_to_dict
from .data_typing import analyze_data_types
from .disassembler import disassemble_bytes, result_to_dict
from .elf32 import parse_elf32
from .errors import DisassemblyError
from .linker import ModuleAnalysisInput, link_modules
from .model import (
    AdvancedAnalysisResult,
    DataTypeRecord,
    DataTypingResult,
    DisassemblyResult,
    ElfImage,
    ModuleLinkAnalysis,
    PropagatedSymbol,
    Section,
    TypedCallEdge,
)
from .nids import load_nid_databases

SHF_ALLOC = 0x2
SHT_NOBITS = 8
MAX_FLAT_IMAGE_SIZE = 128 * 1024 * 1024


@dataclass(slots=True)
class ProjectArtifacts:
    base_vram: int
    target: bytes
    splat_yaml: str
    symbols: str
    executable_json: str
    disassembly_json: str
    advanced_json: str
    data_typing_json: str
    disassembly: DisassemblyResult
    advanced: AdvancedAnalysisResult
    data_typing: DataTypingResult
    nid_analysis: ModuleLinkAnalysis | None = None


@dataclass(slots=True)
class ProjectResult:
    output_dir: Path
    target_path: Path
    config_path: Path
    base_vram: int
    target_size: int


def _allocated_sections(elf: ElfImage) -> list[Section]:
    return sorted(
        [section for section in elf.sections if section.size > 0 and section.flags & SHF_ALLOC],
        key=lambda section: (section.addr, section.index),
    )


def _flatten_elf(elf: ElfImage) -> tuple[int, bytes, list[Section]]:
    sections = _allocated_sections(elf)
    file_sections = [section for section in sections if section.type != SHT_NOBITS]
    if not file_sections:
        raise DisassemblyError("Splat project generation requires allocated file-backed ELF sections.")

    base_vram = min(section.addr for section in sections)
    end_vram = max(section.addr + section.size for section in file_sections)
    image_size = end_vram - base_vram
    if image_size <= 0 or image_size > MAX_FLAT_IMAGE_SIZE:
        raise DisassemblyError(
            f"Refusing sparse flat image of 0x{image_size:X} bytes; maximum is 0x{MAX_FLAT_IMAGE_SIZE:X}."
        )

    image = bytearray(image_size)
    for section in file_sections:
        source_end = section.offset + section.size
        if source_end > len(elf.raw_data):
            raise DisassemblyError(f"Section {section.name or section.index} extends beyond the ELF file.")
        dest = section.addr - base_vram
        image[dest : dest + section.size] = elf.raw_data[section.offset:source_end]
    return base_vram, bytes(image), sections


def _segment_type(section: Section) -> str:
    known = {
        ".text": "asm",
        ".data": "data",
        ".rodata": "rodata",
        ".sdata": "sdata",
        ".sbss": "sbss",
        ".bss": "bss",
        ".gcc_except_table": "gcc_except_table",
        ".eh_frame": "eh_frame",
    }
    if section.type == SHT_NOBITS:
        return "sbss" if section.name == ".sbss" else "bss"
    if section.name in known:
        return known[section.name]
    if section.kind == "executable":
        return "asm"
    if section.kind == "writable":
        return "data"
    return "rodata"


def _build_subsegments(base_vram: int, target_size: int, sections: list[Section]) -> tuple[list[Any], int]:
    subsegments: list[Any] = []
    file_sections = [section for section in sections if section.type != SHT_NOBITS]
    cursor = 0
    for section in file_sections:
        start = section.addr - base_vram
        if start > cursor:
            subsegments.append([cursor, "bin", f"padding/{cursor:06X}"])
        seg_type = _segment_type(section)
        subsegments.append([start, seg_type, f"main/{start:06X}"])
        cursor = max(cursor, start + section.size)
    if cursor < target_size:
        subsegments.append([cursor, "bin", f"padding/{cursor:06X}"])

    bss_size = 0
    for section in sections:
        if section.type != SHT_NOBITS:
            continue
        seg_type = _segment_type(section)
        subsegments.append(
            {"type": seg_type, "vram": section.addr, "name": f"main/{section.addr:08X}"}
        )
        bss_size += section.size
    return subsegments, bss_size


def _section_order(sections: list[Section]) -> list[str]:
    order: list[str] = []
    for section in sections:
        name = section.name
        if not name.startswith("."):
            continue
        seg_type = _segment_type(section)
        if seg_type not in {"asm", "data", "rodata", "sdata", "sbss", "bss", "gcc_except_table", "eh_frame"}:
            continue
        canonical = ".text" if seg_type == "asm" else (".rodata" if seg_type == "rodata" else f".{seg_type}")
        if canonical not in order:
            order.append(canonical)
    return order or [".text", ".data", ".rodata", ".bss"]


def _render_splat_yaml(source_name: str, target: bytes, base_vram: int, sections: list[Section], gp: int | None) -> str:
    subsegments, bss_size = _build_subsegments(base_vram, len(target), sections)
    options: dict[str, Any] = {
        "basename": Path(source_name).stem or "psp_target",
        "target_path": "target.bin",
        "base_path": ".",
        "platform": "psp",
        "compiler": "GCC",
        "endianness": "little",
        "asm_path": "asm",
        "src_path": "src",
        "build_path": "build",
        "ld_script_path": "linker.ld",
        "create_asm_dependencies": True,
        "find_file_boundaries": False,
        "disassemble_all": True,
        "make_full_disasm_for_code": True,
        "named_regs_for_c_funcs": False,
        "symbol_addrs_path": ["config/symbols.txt"],
        "undefined_funcs_auto_path": "config/undefined_funcs_auto.txt",
        "undefined_syms_auto_path": "config/undefined_syms_auto.txt",
        "section_order": _section_order(sections),
        "global_vram_start": base_vram,
        "global_vram_end": max(section.addr + section.size for section in sections),
    }
    if gp:
        options["gp_value"] = gp

    config = {
        "sha1": hashlib.sha1(target).hexdigest(),
        "options": options,
        "segments": [
            {
                "name": "main",
                "type": "code",
                "start": 0,
                "vram": base_vram,
                "bss_size": bss_size,
                "subalign": None,
                "subsegments": subsegments,
            },
            [len(target)],
        ],
    }
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False, width=120)


def _valid_symbol_name(name: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or fallback


def _is_autogenerated_symbol_name(name: str) -> bool:
    value = name.strip()
    patterns = (
        r"func_[0-9A-Fa-f]+",
        r"D_[0-9A-Fa-f]+",
        r"L[0-9A-Fa-f]+",
        r"label_[0-9A-Fa-f]+",
        r"jtbl_[0-9A-Fa-f]+",
    )
    return any(re.fullmatch(pattern, value) for pattern in patterns)


def _strong_proposals(records: Iterable[PropagatedSymbol]) -> dict[int, PropagatedSymbol]:
    selected: dict[int, PropagatedSymbol] = {}
    for record in records:
        if record.confidence < 0.95:
            continue
        current = selected.get(record.address)
        if current is None or record.confidence > current.confidence:
            selected[record.address] = record
            continue
        if record.confidence == current.confidence and (record.name, record.source) < (current.name, current.source):
            selected[record.address] = record
    return selected


def _strong_type_names(records: Iterable[DataTypeRecord]) -> dict[int, str]:
    prefixes = {
        "function_pointer": "FUNCPTR",
        "pointer": "PTR",
        "function_pointer_table": "FUNCPTRTBL",
        "pointer_table": "PTRTBL",
    }
    selected: dict[int, tuple[float, str]] = {}
    for record in records:
        prefix = prefixes.get(record.type_name)
        if prefix is None or record.confidence < 0.90:
            continue
        name = f"{prefix}_{record.address:08X}"
        current = selected.get(record.address)
        candidate = (record.confidence, name)
        if current is None or candidate[0] > current[0] or (candidate[0] == current[0] and candidate[1] < current[1]):
            selected[record.address] = candidate
    return {address: value[1] for address, value in selected.items()}


def _render_symbols(
    entry: int,
    result: DisassemblyResult,
    propagated_symbols: Iterable[PropagatedSymbol] = (),
    data_types: Iterable[DataTypeRecord] = (),
) -> str:
    lines = ["// Generated by pspdisasm; curate this file as the decompilation progresses."]
    used_addresses: set[int] = set()
    proposals = _strong_proposals(propagated_symbols)
    type_names = _strong_type_names(data_types)

    if entry:
        lines.append(f"_start = 0x{entry:08X}; // type:func")
        used_addresses.add(entry)

    strings_by_address = {record.address: record for record in result.strings}
    for record in sorted(result.strings, key=lambda item: item.address):
        if record.address in used_addresses:
            continue
        lines.append(f"STR_{record.address:08X} = 0x{record.address:08X}; // type:asciz")
        used_addresses.add(record.address)

    for function in sorted(result.functions, key=lambda item: (item.address, item.name)):
        if function.address in used_addresses:
            continue
        proposal = proposals.get(function.address)
        raw_name = function.name
        if proposal is not None and _is_autogenerated_symbol_name(function.name):
            raw_name = proposal.name
        name = _valid_symbol_name(raw_name, f"func_{function.address:08X}")
        lines.append(f"{name} = 0x{function.address:08X}; // type:func")
        used_addresses.add(function.address)

    for symbol in sorted(result.symbols, key=lambda item: (item.address, item.name)):
        if symbol.address in used_addresses or symbol.address in strings_by_address:
            continue
        if symbol.kind in {"label", "branchlabel"}:
            continue
        proposal = proposals.get(symbol.address)
        raw_name = symbol.name
        if _is_autogenerated_symbol_name(symbol.name):
            if proposal is not None:
                raw_name = proposal.name
            elif symbol.address in type_names:
                raw_name = type_names[symbol.address]
        name = _valid_symbol_name(raw_name, f"D_{symbol.address:08X}")
        suffix = " // type:func" if proposal is not None and proposal.kind == "function" else ""
        lines.append(f"{name} = 0x{symbol.address:08X};{suffix}")
        used_addresses.add(symbol.address)

    for address, proposal in sorted(proposals.items(), key=lambda item: (item[0], item[1].name)):
        if address in used_addresses or address in strings_by_address:
            continue
        fallback = f"func_{address:08X}" if proposal.kind == "function" else f"D_{address:08X}"
        name = _valid_symbol_name(proposal.name, fallback)
        suffix = " // type:func" if proposal.kind == "function" else ""
        lines.append(f"{name} = 0x{address:08X};{suffix}")
        used_addresses.add(address)

    for address, raw_name in sorted(type_names.items()):
        if address in used_addresses or address in strings_by_address:
            continue
        name = _valid_symbol_name(raw_name, f"D_{address:08X}")
        lines.append(f"{name} = 0x{address:08X};")
        used_addresses.add(address)

    return "\n".join(lines) + "\n"


def _dedup_typed_call_edges(
    advanced: AdvancedAnalysisResult,
    data_typing: DataTypingResult,
) -> list[TypedCallEdge]:
    existing_indirect = {
        (edge.source_function, edge.target_function, edge.source_address, edge.target_address)
        for edge in advanced.call_edges
        if edge.kind == "indirect"
    }
    return [
        edge
        for edge in data_typing.call_edges
        if (edge.source_function, edge.target_function, edge.source_address, edge.target_address) not in existing_indirect
    ]


def build_project_artifacts(
    data: bytes,
    source_name: str = "<memory>",
    *,
    nid_databases: Iterable[Path | str] = (),
) -> ProjectArtifacts:
    model = analyze_bytes(data, source_name)
    if model.needs_decryption:
        raise DisassemblyError("Splat project generation requires a decrypted PSP ELF/PRX input.")
    elf = parse_elf32(data)
    result = disassemble_bytes(data, source_name)
    advanced = analyze_advanced(model, result)

    database_paths = tuple(nid_databases)
    nid_analysis: ModuleLinkAnalysis | None = None
    if database_paths:
        database = load_nid_databases(database_paths)
        nid_analysis = link_modules([ModuleAnalysisInput(model, result)], database)

    data_typing = analyze_data_types(model, result, elf)
    base_vram, target, sections = _flatten_elf(elf)
    gp = model.module_info.gp_value if model.module_info is not None else None
    splat_yaml = _render_splat_yaml(source_name, target, base_vram, sections, gp)
    propagated = nid_analysis.propagated_symbols if nid_analysis is not None else ()
    symbols = _render_symbols(elf.header.entry, result, propagated, data_typing.data_types)
    return ProjectArtifacts(
        base_vram=base_vram,
        target=target,
        splat_yaml=splat_yaml,
        symbols=symbols,
        executable_json=json.dumps(model_to_dict(model), indent=2, sort_keys=True) + "\n",
        disassembly_json=json.dumps(result_to_dict(result), indent=2, sort_keys=True) + "\n",
        advanced_json=json.dumps(asdict(advanced), indent=2, sort_keys=True) + "\n",
        data_typing_json=json.dumps(asdict(data_typing), indent=2, sort_keys=True) + "\n",
        disassembly=result,
        advanced=advanced,
        data_typing=data_typing,
        nid_analysis=nid_analysis,
    )


def _assembly_filename(name: str, address: int, used: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", name.lstrip(".")).strip("._")
    if not base:
        base = f"section_{address:08X}"
    filename = f"{base}.s"
    if filename in used:
        filename = f"{base}_{address:08X}.s"
    used.add(filename)
    return filename


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate_project(
    source: Path | str,
    output_dir: Path | str,
    *,
    nid_databases: Iterable[Path | str] = (),
) -> ProjectResult:
    source_path = Path(source)
    output = Path(output_dir)
    artifacts = build_project_artifacts(
        source_path.read_bytes(),
        str(source_path),
        nid_databases=nid_databases,
    )

    for directory in ("config", "metadata", "asm", "asm/nonmatchings", "src", "build", "reports", "assets"):
        (output / directory).mkdir(parents=True, exist_ok=True)

    (output / "target.bin").write_bytes(artifacts.target)
    (output / "splat.yaml").write_text(artifacts.splat_yaml, encoding="utf-8")
    (output / "config" / "symbols.txt").write_text(artifacts.symbols, encoding="utf-8")
    (output / "config" / "undefined_funcs_auto.txt").write_text("", encoding="utf-8")
    (output / "config" / "undefined_syms_auto.txt").write_text("", encoding="utf-8")
    (output / "metadata" / "executable.json").write_text(artifacts.executable_json, encoding="utf-8")
    (output / "metadata" / "disassembly.json").write_text(artifacts.disassembly_json, encoding="utf-8")
    (output / "metadata" / "advanced.json").write_text(artifacts.advanced_json, encoding="utf-8")
    (output / "metadata" / "data_typing.json").write_text(artifacts.data_typing_json, encoding="utf-8")

    normalized = result_to_dict(artifacts.disassembly)
    for key in ("functions", "symbols", "references", "strings"):
        _write_json(output / "metadata" / f"{key}.json", normalized[key])

    advanced = asdict(artifacts.advanced)
    _write_json(output / "metadata" / "callgraph.json", advanced["call_edges"])
    _write_json(output / "metadata" / "jump_tables.json", advanced["jump_tables"])
    _write_json(output / "metadata" / "function_confidence.json", advanced["function_confidence"])

    data_typing = asdict(artifacts.data_typing)
    _write_json(output / "metadata" / "data_types.json", data_typing["data_types"])
    _write_json(output / "metadata" / "typed_references.json", data_typing["typed_references"])
    _write_json(
        output / "metadata" / "typed_callgraph.json",
        [asdict(edge) for edge in _dedup_typed_call_edges(artifacts.advanced, artifacts.data_typing)],
    )

    if artifacts.nid_analysis is not None:
        nid_analysis = asdict(artifacts.nid_analysis)
        _write_json(output / "metadata" / "nids.json", nid_analysis["resolutions"])
        _write_json(
            output / "metadata" / "propagated_symbols.json",
            nid_analysis["propagated_symbols"],
        )

    used: set[str] = set()
    for section in artifacts.disassembly.assembly_sections:
        filename = _assembly_filename(section.name, section.address, used)
        (output / "asm" / filename).write_text(section.assembly, encoding="utf-8")

    return ProjectResult(
        output_dir=output,
        target_path=output / "target.bin",
        config_path=output / "splat.yaml",
        base_vram=artifacts.base_vram,
        target_size=len(artifacts.target),
    )
