from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path, PurePosixPath
from typing import Iterable

from .analyzer import analyze_file
from .disc import scan_game_disc
from .disassembler import disassemble_file
from .model import ModuleLinkAnalysis
from .project import generate_project


@dataclass(slots=True)
class GameModuleAnalysisRecord:
    path: str
    extracted_path: str | None
    executable_kind: str
    is_boot: bool
    status: str
    module_name: str | None = None
    project_path: str | None = None
    function_count: int = 0
    symbol_count: int = 0
    reference_count: int = 0
    string_count: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GameProjectAnalysis:
    source_name: str
    title: str | None
    disc_id: str | None
    image_format: str
    boot_path: str | None
    modules: list[GameModuleAnalysisRecord]
    links: ModuleLinkAnalysis
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GameProjectResult:
    output_dir: Path
    analysis_path: Path
    links_path: Path
    module_count: int
    analyzed_count: int
    needs_decryption_count: int
    failed_count: int


def _safe_relative_target(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"Unsafe game project path: {relative_path}")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*pure.parts)).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"Unsafe game project path: {relative_path}")
    return target


def _module_name(model) -> str | None:
    if model.module_info is not None and model.module_info.name.strip():
        return model.module_info.name.strip()
    if model.container_header is not None and model.container_header.module_name.strip():
        return model.container_header.module_name.strip()
    return None


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate_game_project(
    source: Path | str,
    output_dir: Path | str,
    *,
    nid_databases: Iterable[Path | str] = (),
) -> GameProjectResult:
    source_path = Path(source)
    output = Path(output_dir)
    database_paths = tuple(nid_databases)
    manifest = scan_game_disc(source_path, output)

    module_records: list[GameModuleAnalysisRecord] = []
    analyzed_count = 0
    needs_decryption_count = 0
    failed_count = 0

    for candidate in sorted(manifest.modules, key=lambda item: item.path.casefold()):
        if candidate.output_path is None:
            module_records.append(
                GameModuleAnalysisRecord(
                    path=candidate.path,
                    extracted_path=None,
                    executable_kind=candidate.executable_kind,
                    is_boot=candidate.is_boot,
                    status="failed",
                    warnings=["Phase 7A did not provide an extracted module path"],
                )
            )
            failed_count += 1
            continue

        extracted = _safe_relative_target(output, candidate.output_path)
        model = analyze_file(extracted)
        name = _module_name(model)
        if model.needs_decryption:
            module_records.append(
                GameModuleAnalysisRecord(
                    path=candidate.path,
                    extracted_path=str(extracted.relative_to(output.resolve())),
                    executable_kind=candidate.executable_kind,
                    is_boot=candidate.is_boot,
                    status="needs_decryption",
                    module_name=name,
                    warnings=list(model.warnings),
                )
            )
            needs_decryption_count += 1
            continue

        disassembly = disassemble_file(extracted)
        project_root = _safe_relative_target(output / "projects", candidate.path)
        generate_project(extracted, project_root, nid_databases=database_paths)
        module_records.append(
            GameModuleAnalysisRecord(
                path=candidate.path,
                extracted_path=str(extracted.relative_to(output.resolve())),
                executable_kind=candidate.executable_kind,
                is_boot=candidate.is_boot,
                status="analyzed",
                module_name=name,
                project_path=str(project_root.relative_to(output.resolve())),
                function_count=len(disassembly.functions),
                symbol_count=len(disassembly.symbols),
                reference_count=len(disassembly.references),
                string_count=len(disassembly.strings),
                warnings=[*model.warnings, *disassembly.warnings],
            )
        )
        analyzed_count += 1

    links = ModuleLinkAnalysis()
    analysis = GameProjectAnalysis(
        source_name=str(source_path),
        title=manifest.title,
        disc_id=manifest.disc_id,
        image_format=manifest.image_format,
        boot_path=manifest.boot_path,
        modules=module_records,
        links=links,
        warnings=list(manifest.warnings),
    )
    analysis_path = output / "metadata" / "game_analysis.json"
    links_path = output / "metadata" / "module_links.json"
    _write_json(analysis_path, asdict(analysis))
    _write_json(links_path, asdict(links))
    _write_json(output / "metadata" / "propagated_symbols.json", [])

    return GameProjectResult(
        output_dir=output,
        analysis_path=analysis_path,
        links_path=links_path,
        module_count=len(module_records),
        analyzed_count=analyzed_count,
        needs_decryption_count=needs_decryption_count,
        failed_count=failed_count,
    )
