from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path, PurePosixPath
from typing import Iterable

from .analyzer import analyze_file
from .disc import extract_disc_resources, scan_game_disc
from .disassembler import disassemble_file
from .errors import DisassemblyError, EngineUnavailableError, ParseError
from .game_resources import analyze_game_resources
from .linker import ModuleAnalysisInput, link_modules
from .model import ModuleLinkAnalysis
from .nids import load_nid_databases
from .project import generate_project
from .resource_containers import ResourceContainerParser


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
    resource_count: int = 0
    known_resource_count: int = 0
    unknown_resource_count: int = 0
    embedded_resource_count: int = 0
    container_candidate_count: int = 0
    container_inspection_count: int = 0
    container_entry_count: int = 0
    resources_path: Path | None = None
    containers_path: Path | None = None


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


def _relative_display(path: Path, output: Path) -> str:
    return str(path.relative_to(output.resolve()))


def generate_game_project(
    source: Path | str,
    output_dir: Path | str,
    *,
    nid_databases: Iterable[Path | str] = (),
    container_parsers: Iterable[ResourceContainerParser] = (),
) -> GameProjectResult:
    source_path = Path(source)
    output = Path(output_dir)
    database_paths = tuple(nid_databases)
    parsers = tuple(container_parsers)
    manifest = scan_game_disc(source_path, output)

    resource_files = extract_disc_resources(source_path, output, manifest=manifest)
    resource_analysis = analyze_game_resources(
        str(source_path),
        output,
        resource_files,
        container_parsers=parsers,
    )

    module_records: list[GameModuleAnalysisRecord] = []
    link_units: list[ModuleAnalysisInput] = []
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

        # Containment failures are game-level integrity errors, not ordinary
        # module-analysis failures. Validate both roots before entering the
        # per-module isolation boundary so traversal/symlink escapes are fatal.
        extracted = _safe_relative_target(output, candidate.output_path)
        project_root = _safe_relative_target(output / "projects", candidate.path)
        model = None
        try:
            model = analyze_file(extracted)
            name = _module_name(model)
            if model.needs_decryption:
                module_records.append(
                    GameModuleAnalysisRecord(
                        path=candidate.path,
                        extracted_path=_relative_display(extracted, output),
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
            generate_project(extracted, project_root, nid_databases=database_paths)
            module_records.append(
                GameModuleAnalysisRecord(
                    path=candidate.path,
                    extracted_path=_relative_display(extracted, output),
                    executable_kind=candidate.executable_kind,
                    is_boot=candidate.is_boot,
                    status="analyzed",
                    module_name=name,
                    project_path=_relative_display(project_root, output),
                    function_count=len(disassembly.functions),
                    symbol_count=len(disassembly.symbols),
                    reference_count=len(disassembly.references),
                    string_count=len(disassembly.strings),
                    warnings=[*model.warnings, *disassembly.warnings],
                )
            )
            link_units.append(ModuleAnalysisInput(model, disassembly))
            analyzed_count += 1
        except EngineUnavailableError:
            raise
        except (ParseError, DisassemblyError, OSError, ValueError) as exc:
            module_records.append(
                GameModuleAnalysisRecord(
                    path=candidate.path,
                    extracted_path=_relative_display(extracted, output),
                    executable_kind=candidate.executable_kind,
                    is_boot=candidate.is_boot,
                    status="failed",
                    module_name=_module_name(model) if model is not None else None,
                    warnings=[str(exc)],
                )
            )
            failed_count += 1

    database = load_nid_databases(database_paths)
    links = link_modules(link_units, database)
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
    resources_path = output / "metadata" / "game_resources.json"
    containers_path = output / "metadata" / "container_candidates.json"
    _write_json(analysis_path, asdict(analysis))
    _write_json(links_path, asdict(links))
    _write_json(
        output / "metadata" / "propagated_symbols.json",
        [asdict(record) for record in links.propagated_symbols],
    )

    known_resource_count = sum(
        1 for record in resource_analysis.resources if record.detected_format != "unknown"
    )
    resource_count = len(resource_analysis.resources)

    return GameProjectResult(
        output_dir=output,
        analysis_path=analysis_path,
        links_path=links_path,
        module_count=len(module_records),
        analyzed_count=analyzed_count,
        needs_decryption_count=needs_decryption_count,
        failed_count=failed_count,
        resource_count=resource_count,
        known_resource_count=known_resource_count,
        unknown_resource_count=resource_count - known_resource_count,
        embedded_resource_count=len(resource_analysis.embedded_resources),
        container_candidate_count=len(resource_analysis.container_candidates),
        container_inspection_count=len(resource_analysis.container_inspections),
        container_entry_count=len(resource_analysis.container_entries),
        resources_path=resources_path,
        containers_path=containers_path,
    )
