from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path, PurePosixPath
from typing import Iterable

from .analyzer import analyze_file
from .disc import (
    GameModuleRecord,
    extract_directory_resources,
    extract_disc_resources,
    scan_game_directory,
    scan_game_disc,
)
from .disassembler import disassemble_file
from .elf32 import parse_elf32
from .errors import DisassemblyError, EngineUnavailableError, ParseError
from .game_resources import analyze_game_resources
from .linker import ModuleAnalysisInput, link_modules
from .load_view import build_relocated_load_view
from .model import ExecutableModel, ModuleLinkAnalysis
from .nids import load_nid_databases
from .placement import ModulePlacement, ModulePlacementInput, plan_module_placements
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
    load_address: int | None = None
    placement_kind: str | None = None
    placement_confidence: float | None = None
    runtime_address_claim: bool | None = None
    requires_relocation: bool | None = None
    placement_evidence: list[str] = field(default_factory=list)
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
    placements_path: Path | None = None


@dataclass(slots=True)
class _PreparedModule:
    candidate: GameModuleRecord
    extracted: Path
    project_root: Path
    model: ExecutableModel
    module_name: str | None


def _safe_relative_target(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"Unsafe game project path: {relative_path}")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*pure.parts)).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"Unsafe game project path: {relative_path}")
    return target


def _module_name(model: ExecutableModel) -> str | None:
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


def _placement_fields(placement: ModulePlacement) -> dict[str, object]:
    return {
        "load_address": placement.load_address,
        "placement_kind": placement.placement_kind,
        "placement_confidence": placement.placement_confidence,
        "runtime_address_claim": placement.runtime_address_claim,
        "requires_relocation": placement.requires_relocation,
        "placement_evidence": list(placement.placement_evidence),
    }


def _relocated_link_model(prepared: _PreparedModule, placement: ModulePlacement) -> ExecutableModel:
    if not placement.requires_relocation:
        return prepared.model
    data = prepared.extracted.read_bytes()
    elf = parse_elf32(data)
    return build_relocated_load_view(
        data,
        elf,
        prepared.model,
        load_address=placement.load_address,
    ).model


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

    if source_path.is_dir():
        manifest = scan_game_directory(source_path, output)
        resource_files = extract_directory_resources(source_path, output, manifest=manifest)
    else:
        manifest = scan_game_disc(source_path, output)
        resource_files = extract_disc_resources(source_path, output, manifest=manifest)

    resource_analysis = analyze_game_resources(
        str(source_path),
        output,
        resource_files,
        container_parsers=parsers,
    )

    candidates = sorted(manifest.modules, key=lambda item: item.path.casefold())
    records_by_path: dict[str, GameModuleAnalysisRecord] = {}
    prepared_modules: list[_PreparedModule] = []

    # First pass: parse every candidate and isolate encrypted/malformed modules.
    # Containment failures remain game-level integrity errors and therefore stay
    # outside the per-module failure boundary.
    for candidate in candidates:
        if candidate.output_path is None:
            records_by_path[candidate.path] = GameModuleAnalysisRecord(
                path=candidate.path,
                extracted_path=None,
                executable_kind=candidate.executable_kind,
                is_boot=candidate.is_boot,
                status="failed",
                warnings=["Phase 7A did not provide an extracted module path"],
            )
            continue

        extracted = _safe_relative_target(output, candidate.output_path)
        project_root = _safe_relative_target(output / "projects", candidate.path)
        model: ExecutableModel | None = None
        try:
            model = analyze_file(extracted)
            name = _module_name(model)
            if model.needs_decryption:
                records_by_path[candidate.path] = GameModuleAnalysisRecord(
                    path=candidate.path,
                    extracted_path=_relative_display(extracted, output),
                    executable_kind=candidate.executable_kind,
                    is_boot=candidate.is_boot,
                    status="needs_decryption",
                    module_name=name,
                    warnings=list(model.warnings),
                )
                continue

            # Validate this module's loadable layout before it participates in
            # the global placement plan. This preserves secondary-module
            # failure isolation for malformed ELF layouts.
            plan_module_placements(
                [ModulePlacementInput(path=candidate.path, is_boot=candidate.is_boot, model=model)]
            )
            prepared_modules.append(
                _PreparedModule(
                    candidate=candidate,
                    extracted=extracted,
                    project_root=project_root,
                    model=model,
                    module_name=name,
                )
            )
        except EngineUnavailableError:
            raise
        except (ParseError, DisassemblyError, OSError, ValueError) as exc:
            records_by_path[candidate.path] = GameModuleAnalysisRecord(
                path=candidate.path,
                extracted_path=_relative_display(extracted, output),
                executable_kind=candidate.executable_kind,
                is_boot=candidate.is_boot,
                status="failed",
                module_name=_module_name(model) if model is not None else None,
                warnings=[str(exc)],
            )

    placements = plan_module_placements(
        [
            ModulePlacementInput(
                path=prepared.candidate.path,
                is_boot=prepared.candidate.is_boot,
                model=prepared.model,
            )
            for prepared in prepared_modules
        ]
    ) if prepared_modules else []
    placement_by_path = {placement.path: placement for placement in placements}

    link_units: list[ModuleAnalysisInput] = []

    # Second pass: run Phase 7F relocated views consistently through both the
    # disassembler and Splat project generator. Fixed ET_EXEC modules keep the
    # addresses encoded in the executable and therefore bypass relocation.
    for prepared in sorted(prepared_modules, key=lambda item: item.candidate.path.casefold()):
        candidate = prepared.candidate
        placement = placement_by_path[candidate.path]
        fields = _placement_fields(placement)
        try:
            if placement.requires_relocation:
                disassembly = disassemble_file(
                    prepared.extracted,
                    load_address=placement.load_address,
                )
                generate_project(
                    prepared.extracted,
                    prepared.project_root,
                    nid_databases=database_paths,
                    load_address=placement.load_address,
                )
            else:
                disassembly = disassemble_file(prepared.extracted)
                generate_project(
                    prepared.extracted,
                    prepared.project_root,
                    nid_databases=database_paths,
                )

            link_model = _relocated_link_model(prepared, placement)
            records_by_path[candidate.path] = GameModuleAnalysisRecord(
                path=candidate.path,
                extracted_path=_relative_display(prepared.extracted, output),
                executable_kind=candidate.executable_kind,
                is_boot=candidate.is_boot,
                status="analyzed",
                module_name=prepared.module_name,
                project_path=_relative_display(prepared.project_root, output),
                function_count=len(disassembly.functions),
                symbol_count=len(disassembly.symbols),
                reference_count=len(disassembly.references),
                string_count=len(disassembly.strings),
                warnings=[*prepared.model.warnings, *disassembly.warnings],
                **fields,
            )
            link_units.append(ModuleAnalysisInput(link_model, disassembly))
        except EngineUnavailableError:
            raise
        except (ParseError, DisassemblyError, OSError, ValueError) as exc:
            records_by_path[candidate.path] = GameModuleAnalysisRecord(
                path=candidate.path,
                extracted_path=_relative_display(prepared.extracted, output),
                executable_kind=candidate.executable_kind,
                is_boot=candidate.is_boot,
                status="failed",
                module_name=prepared.module_name,
                warnings=[str(exc)],
                **fields,
            )

    module_records = [records_by_path[candidate.path] for candidate in candidates]
    analyzed_count = sum(record.status == "analyzed" for record in module_records)
    needs_decryption_count = sum(record.status == "needs_decryption" for record in module_records)
    failed_count = sum(record.status == "failed" for record in module_records)

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
    placements_path = output / "metadata" / "module_placements.json"
    _write_json(analysis_path, asdict(analysis))
    _write_json(links_path, asdict(links))
    _write_json(
        output / "metadata" / "propagated_symbols.json",
        [asdict(record) for record in links.propagated_symbols],
    )
    _write_json(placements_path, [asdict(placement) for placement in placements])

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
        placements_path=placements_path,
    )
