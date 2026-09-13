from __future__ import annotations

import argparse
import contextlib
from dataclasses import asdict
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Sequence

from .analysis_pack import (
    DEFAULT_CONTEXT_BYTES,
    DEFAULT_PACK_MAX_BYTES,
    create_analysis_pack,
)
from .analyzer import analyze_file, model_to_dict
from .disc import scan_game_disc
from .disassembler import disassemble_file, result_to_dict
from .decompile.orchestrator import DEFAULT_MAX_ATTEMPTS, DEFAULT_TIMEOUT_SECONDS, run_and_persist
from .decompile.queue import (
    QueueFilters,
    discover_functions,
    enrich_with_runtime_evidence,
    enrich_with_static_confidence,
    select_functions,
)
from .decompile.reporting import write_match_status_report
from .decompile.toolchain import BuildToolchain, ExternalCompilerToolchain, ProjectBuildCommandToolchain
from .decompiler import DEFAULT_M2C_TARGET, decompile_project_function
from .errors import (
    AnalysisPackError,
    BuildFailedError,
    BuildToolchainUnavailableError,
    DecompilationError,
    DecompilerUnavailableError,
    DisassemblyError,
    EngineUnavailableError,
    MatcherUnavailableError,
    MatchingError,
    ParseError,
    RecoveryBackendUnavailableError,
    RecoveryError,
    RuntimeBackendUnavailableError,
    RuntimeCaptureError,
    RuntimeConnectionError,
    RuntimeMappingError,
    RuntimeProtocolError,
    RuntimeTimeoutError,
    WorkspaceError,
)
from .linker import ModuleAnalysisInput, link_modules
from .matcher import match_project_function
from .model import DisassemblyResult, ExecutableModel, ModuleLinkAnalysis, RuntimeAddress, RuntimeAddressDomain
from .nids import load_nid_databases
from .project import generate_project
from .recovery import (
    DEFAULT_MAX_RECOVERED_BYTES,
    ExternalDecryptorBackend,
    PrebuiltDumpBackend,
    RecoveryBackend,
    recover_bytes,
)
from .runtime.modules import HleModuleListSource, UserProvidedModuleSource, build_runtime_module_map, load_static_placements
from .runtime.reconciliation import ObservationGroup, StaticCandidate, reconcile_workspace
from .runtime.session import DEFAULT_MAX_BACKTRACE_DEPTH, DEFAULT_MAX_TOTAL_MEMORY_BYTES, LaunchSpec, RuntimeSession
from .runtime.workspace import (
    list_sessions,
    load_module_map,
    load_observations,
    save_module_map,
    save_observations,
    save_reconciliation,
    save_session_info,
)
from .workspace import analyze_game_workspace, generate_game_project, load_game_workspace, prepare_game_workspace


def _add_recovery_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--recovery-backend",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "External PSP recovery backend executable/script (invoked as "
            "'--input IN --output OUT'); may be repeated"
        ),
    )
    parser.add_argument(
        "--recovery-manifest",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help=(
            "Prebuilt-dump recovery manifest JSON binding original/recovered SHA-256 pairs "
            "to recovered files; may be repeated"
        ),
    )
    parser.add_argument(
        "--recovery-max-bytes",
        type=int,
        default=DEFAULT_MAX_RECOVERED_BYTES,
        metavar="N",
        help=f"Maximum recovered-output bytes (default: {DEFAULT_MAX_RECOVERED_BYTES})",
    )


def _build_recovery_backends(args: argparse.Namespace) -> list[RecoveryBackend]:
    backends: list[RecoveryBackend] = []
    for path in args.recovery_backend:
        backends.append(ExternalDecryptorBackend(path, max_output_bytes=args.recovery_max_bytes))
    for manifest in args.recovery_manifest:
        backends.append(PrebuiltDumpBackend(manifest, max_output_bytes=args.recovery_max_bytes))
    return backends


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
    _add_recovery_arguments(game_project)

    prepare_game = sub.add_parser(
        "prepare-game",
        help="Prepare a deterministic local workspace for a PSP ISO/CSO or extracted directory",
    )
    prepare_game.add_argument("input", type=Path)
    prepare_game.add_argument("workspace", type=Path)

    analyze_workspace = sub.add_parser(
        "analyze-workspace",
        help="Analyze or resume a prepared local PSP workspace",
    )
    analyze_workspace.add_argument("workspace", type=Path)
    analyze_workspace.add_argument(
        "--nid-db",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="NID JSON or PSPLibDoc-style CSV database; may be repeated and later files win",
    )
    _add_recovery_arguments(analyze_workspace)

    make_pack = sub.add_parser(
        "make-pack",
        help="Create a bounded portable analysis pack from a prepared/analyzed workspace",
    )
    make_pack.add_argument("workspace", type=Path)
    make_pack.add_argument("--output", type=Path, required=True, metavar="PATH")
    make_pack.add_argument("--module", metavar="LOGICAL_PATH")
    make_pack.add_argument("--function", metavar="NAME_OR_ADDRESS")
    make_pack.add_argument("--resource", metavar="LOGICAL_PATH")
    make_pack.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_PACK_MAX_BYTES,
        metavar="N",
        help=f"Maximum uncompressed evidence bytes (default: {DEFAULT_PACK_MAX_BYTES})",
    )
    make_pack.add_argument(
        "--context-bytes",
        type=int,
        default=DEFAULT_CONTEXT_BYTES,
        metavar="N",
        help=f"Function/resource context bytes (default: {DEFAULT_CONTEXT_BYTES})",
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
    project.add_argument(
        "--load-address",
        type=lambda value: int(value, 0),
        metavar="ADDRESS",
        help="Explicit PSP runtime load address in decimal or 0x hexadecimal form",
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

    recover = sub.add_parser(
        "recover",
        help="Attempt to recover one encrypted ~PSP container into an analyzable ELF/PRX",
    )
    recover.add_argument("input", type=Path)
    recover.add_argument("output", type=Path)
    _add_recovery_arguments(recover)
    recover.add_argument("--json", metavar="PATH", help="Write recovery provenance JSON; use '-' for stdout")

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

    decompile_workspace = sub.add_parser(
        "decompile-workspace",
        help="Phase 8D: run the automated decompile -> build -> match pipeline over a workspace's queued functions",
    )
    decompile_workspace.add_argument("workspace", type=Path)
    decompile_workspace.add_argument("--module", metavar="LOGICAL_PATH", help="Restrict to one analyzed module")
    decompile_workspace.add_argument(
        "--function", metavar="SELECTOR", help="Restrict to (and force-retry) one function by name or address"
    )
    decompile_workspace.add_argument(
        "--below-match", type=float, metavar="PERCENT", help="Only functions whose best match is below this percent"
    )
    decompile_workspace.add_argument("--unmatched-only", action="store_true", help="Skip functions already matched_exact")
    decompile_workspace.add_argument("--limit", type=int, metavar="N", help="Process at most N functions")
    decompile_workspace.add_argument(
        "--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS, metavar="N",
        help=f"Bounded retry variants per function (default: {DEFAULT_MAX_ATTEMPTS})",
    )
    decompile_workspace.add_argument("--force", action="store_true", help="Re-run an attempt even if its content-derived id was already tried")
    decompile_workspace.add_argument("--m2c", type=Path, metavar="PATH", help="Path to m2c executable or m2c.py")
    decompile_workspace.add_argument("--context", type=Path, action="append", default=[], metavar="FILE", help="Preprocessed C context file; may be repeated")
    decompile_workspace.add_argument("--target", default=DEFAULT_M2C_TARGET, metavar="TARGET", help=f"m2c target triple (default: {DEFAULT_M2C_TARGET})")
    decompile_workspace.add_argument("--compiler", type=Path, metavar="PATH", help="External compiler invoked directly per function (mutually exclusive with --toolchain-command)")
    decompile_workspace.add_argument("--compiler-flag", action="append", default=[], metavar="FLAG", help="Flag passed to --compiler; may be repeated")
    decompile_workspace.add_argument("--toolchain-command", metavar="TEMPLATE", help="Project build command template with a {function} placeholder, parsed without a shell (mutually exclusive with --compiler)")
    decompile_workspace.add_argument("--toolchain-output", metavar="TEMPLATE", help="Output path template with a {function} placeholder, relative to the project directory; required with --toolchain-command")
    decompile_workspace.add_argument("--asm-differ", type=Path, metavar="PATH", help="Path to asm-differ executable or diff.py")
    decompile_workspace.add_argument("--objdump", type=Path, metavar="PATH", help="Path to a MIPS-capable objdump, preferably psp-objdump")
    decompile_workspace.add_argument("--static-confidence", action="store_true", help="Compute Phase 6A function confidence for queue tie-breaking")
    decompile_workspace.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, metavar="SECONDS", help=f"Timeout for build and asm-differ commands (default: {DEFAULT_TIMEOUT_SECONDS:g})")
    decompile_workspace.add_argument("--json", metavar="PATH", help="Write per-function result JSON; use '-' for stdout")

    match_status = sub.add_parser("match-status", help="Phase 8D: summarize a workspace's persisted decompilation/match state")
    match_status.add_argument("workspace", type=Path)
    match_status.add_argument("--json", metavar="PATH", help="Write the status summary JSON; use '-' for stdout")

    runtime = sub.add_parser("runtime", help="Phase 8C: capture and reconcile PPSSPP runtime evidence against a workspace")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)

    def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--host", default="127.0.0.1", help="PPSSPP debugger host (must be loopback; default: 127.0.0.1)")
        parser.add_argument("--port", type=int, required=True, metavar="PORT", help="PPSSPP debugger port")
        parser.add_argument("--launch", type=Path, metavar="PATH", help="Launch this PPSSPP executable instead of connecting to an already-running one")
        parser.add_argument("--launch-arg", action="append", default=[], metavar="ARG", help="Argument to pass to --launch; may be repeated")
        parser.add_argument("--connect-retry-seconds", type=float, default=10.0, metavar="SECONDS", help="How long to retry connecting after --launch (default: 10)")
        parser.add_argument("--session-id", metavar="ID", help="Explicit session id; default is a generated cli-<random> id")

    def _add_module_base_argument(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--module-base",
            action="append",
            default=[],
            metavar="PATH=ADDRESS",
            help="User-provided runtime base for a workspace module path (e.g. PSP_GAME/USRDIR/LOCKED.PRX=0x09A00000); may be repeated",
        )

    observe = runtime_sub.add_parser("observe", help="Install a breakpoint, resume, capture the hit, and persist the observation")
    observe.add_argument("workspace", type=Path)
    _add_connection_arguments(observe)
    observe.add_argument("--address", required=True, metavar="ADDRESS", help="Runtime breakpoint address, decimal or 0x hexadecimal")
    observe.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS", help="Bounded wait for the breakpoint to hit (default: 5)")
    observe.add_argument("--memory-read", action="append", default=[], metavar="ADDRESS:SIZE", help="Bounded memory read to capture alongside the hit; may be repeated")
    observe.add_argument("--max-total-memory-bytes", type=int, default=DEFAULT_MAX_TOTAL_MEMORY_BYTES, metavar="N", help=f"Bound on total captured memory bytes (default: {DEFAULT_MAX_TOTAL_MEMORY_BYTES})")
    observe.add_argument("--max-backtrace-depth", type=int, default=DEFAULT_MAX_BACKTRACE_DEPTH, metavar="N", help=f"Bound on captured backtrace depth (default: {DEFAULT_MAX_BACKTRACE_DEPTH})")
    observe.add_argument("--no-registers", action="store_true", help="Do not capture registers on hit")
    observe.add_argument("--no-backtrace", action="store_true", help="Do not capture a backtrace on hit")
    observe.add_argument("--json", metavar="PATH", help="Write the observation JSON; use '-' for stdout")

    modules = runtime_sub.add_parser("modules", help="Build and persist a runtime module map for a workspace")
    modules.add_argument("workspace", type=Path)
    _add_connection_arguments(modules)
    _add_module_base_argument(modules)
    modules.add_argument("--json", metavar="PATH", help="Write the module map JSON; use '-' for stdout")

    reconcile = runtime_sub.add_parser("reconcile", help="Reconcile this workspace's persisted runtime observations against its static analysis")
    reconcile.add_argument("workspace", type=Path)
    reconcile.add_argument("--static-candidates", type=Path, metavar="FILE", help="JSON file mapping module path to a list of {kind, address, evidence} static candidates")
    reconcile.add_argument("--json", metavar="PATH", help="Write reconciliation JSON; use '-' for stdout")

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


def _parse_module_base(entries: list[str]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for entry in entries:
        path, separator, value = entry.partition("=")
        if not separator:
            raise ValueError(f"--module-base must be PATH=ADDRESS, got: {entry!r}")
        mapping[path] = int(value, 0)
    return mapping


def _parse_memory_reads(entries: list[str]) -> list[tuple[RuntimeAddress, int]]:
    reads: list[tuple[RuntimeAddress, int]] = []
    for entry in entries:
        address_text, separator, size_text = entry.partition(":")
        if not separator:
            raise ValueError(f"--memory-read must be ADDRESS:SIZE, got: {entry!r}")
        address = RuntimeAddress(domain=RuntimeAddressDomain.RUNTIME.value, value=int(address_text, 0))
        reads.append((address, int(size_text, 0)))
    return reads


def _load_static_candidates(path: Path | None) -> dict[str, list[StaticCandidate]]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"--static-candidates must contain a JSON object: {path}")
    candidates: dict[str, list[StaticCandidate]] = {}
    for module_path, entries in payload.items():
        if not isinstance(entries, list):
            raise ValueError(f"--static-candidates entries for {module_path!r} must be a JSON list")
        candidates[module_path] = [
            StaticCandidate(
                kind=str(entry["kind"]),
                address=int(entry["address"]),
                evidence=list(entry.get("evidence", [])),
            )
            for entry in entries
        ]
    return candidates


def _resolve_session_id(explicit: str | None) -> str:
    if explicit:
        return explicit
    return f"cli-{uuid.uuid4().hex[:12]}"


def _workspace_source_identity(workspace: Path) -> str | None:
    try:
        return load_game_workspace(workspace).source_identity
    except WorkspaceError:
        return None


def _open_runtime_session(args: argparse.Namespace) -> RuntimeSession:
    launch = LaunchSpec(executable=args.launch, args=args.launch_arg) if args.launch is not None else None
    return RuntimeSession(
        session_id=_resolve_session_id(args.session_id),
        host=args.host,
        port=args.port,
        launch=launch,
        connect_retry_seconds=args.connect_retry_seconds,
        workspace_source_identity=_workspace_source_identity(args.workspace),
    )


def _run_runtime_observe(args: argparse.Namespace) -> int:
    memory_reads = _parse_memory_reads(args.memory_read)
    address = RuntimeAddress(domain=RuntimeAddressDomain.RUNTIME.value, value=int(args.address, 0))
    with _open_runtime_session(args) as session:
        observation = session.observe_breakpoint(
            address=address,
            timeout=args.timeout,
            memory_reads=memory_reads,
            capture_registers=not args.no_registers,
            capture_backtrace=not args.no_backtrace,
            max_backtrace_depth=args.max_backtrace_depth,
            max_total_memory_bytes=args.max_total_memory_bytes,
        )
        save_session_info(args.workspace, session.info)
        existing = []
        with contextlib.suppress(WorkspaceError):
            existing = load_observations(args.workspace, session.info.session_id)
        save_observations(args.workspace, session.info.session_id, [*existing, observation])

    if not _write_json(asdict(observation), args.json):
        print(f"Session: {session.info.session_id}")
        print(f"Breakpoint: 0x{observation.breakpoint_address.value:08X}")
        print(f"Hit count: {observation.hit_count}")
        if observation.registers is not None:
            print(f"Registers captured: {len(observation.registers.registers)}")
        print(f"Memory reads captured: {len(observation.memory)}")
        if observation.backtrace is not None:
            print(f"Backtrace frames: {len(observation.backtrace.frames)}")
        for warning in observation.warnings:
            print(f"Warning: {warning}")
    return 0


def _run_runtime_modules(args: argparse.Namespace) -> int:
    module_base = _parse_module_base(args.module_base)
    static_placements = load_static_placements(args.workspace)
    sources = [HleModuleListSource()]
    if module_base:
        sources.append(UserProvidedModuleSource(module_base, static_placements=static_placements))

    with _open_runtime_session(args) as session:
        modules = build_runtime_module_map(session.transport, sources)

    save_module_map(args.workspace, modules)
    if not _write_json([asdict(module) for module in modules], args.json):
        print(f"Modules: {len(modules)}")
        for module in modules:
            size = f"0x{module.runtime_size:X}" if module.runtime_size is not None else "unknown"
            print(
                f"  {module.name or '<unnamed>'} @ 0x{module.runtime_base.value:08X} "
                f"(size {size}, {module.resolution_status})"
            )
    return 0


def _run_runtime_reconcile(args: argparse.Namespace) -> int:
    modules = load_module_map(args.workspace)
    static_placements = load_static_placements(args.workspace)
    static_candidates = _load_static_candidates(args.static_candidates)

    groups: list[ObservationGroup] = []
    for session_id in list_sessions(args.workspace):
        for observation in load_observations(args.workspace, session_id):
            key = f"0x{observation.breakpoint_address.value:08X}"
            groups.append(ObservationGroup(call_site_key=key, observation=observation))

    results = reconcile_workspace(
        groups, modules=modules, module_placements=static_placements, static_candidates=static_candidates
    )
    save_reconciliation(args.workspace, results)

    if not _write_json([asdict(result) for result in results], args.json):
        print(f"Reconciled: {len(results)} observation(s)")
        for result in results:
            target = f"0x{result.static_address.value:08X}" if result.static_address is not None else "none"
            print(
                f"  runtime 0x{result.runtime_address.value:08X} -> static {target} "
                f"[{result.status}] observations={result.observation_count}"
            )
            for conflict in result.conflicts:
                print(f"    conflict: {conflict}")
    return 0


def _run_runtime_command(args: argparse.Namespace) -> int:
    if args.runtime_command == "observe":
        return _run_runtime_observe(args)
    if args.runtime_command == "modules":
        return _run_runtime_modules(args)
    if args.runtime_command == "reconcile":
        return _run_runtime_reconcile(args)
    return 2


def _build_decompile_toolchain(args: argparse.Namespace) -> BuildToolchain:
    if args.toolchain_command:
        if not args.toolchain_output:
            raise ValueError("--toolchain-command requires --toolchain-output")
        return ProjectBuildCommandToolchain(command_template=args.toolchain_command, output_template=args.toolchain_output)
    if args.toolchain_output:
        raise ValueError("--toolchain-output requires --toolchain-command")
    return ExternalCompilerToolchain(args.compiler, flags=args.compiler_flag)


def _run_decompile_workspace(args: argparse.Namespace) -> int:
    functions = discover_functions(args.workspace)
    functions = enrich_with_runtime_evidence(functions, args.workspace)
    if args.static_confidence:
        functions = enrich_with_static_confidence(functions, args.workspace)

    filters = QueueFilters(
        module=args.module,
        function=args.function,
        below_match=args.below_match,
        unmatched_only=args.unmatched_only,
        limit=args.limit,
    )
    selected = select_functions(functions, filters)
    toolchain = _build_decompile_toolchain(args)

    results = []
    for queued in selected:
        state = run_and_persist(
            args.workspace,
            queued,
            m2c_path=args.m2c,
            contexts=args.context,
            target=args.target,
            toolchain=toolchain,
            asm_differ_path=args.asm_differ,
            objdump_path=args.objdump,
            max_attempts=args.max_attempts,
            force=args.force,
            timeout=args.timeout,
        )
        results.append(state)

    report_path = write_match_status_report(args.workspace, discover_functions(args.workspace))

    if not _write_json([asdict(state) for state in results], args.json):
        print(f"Selected: {len(results)} function(s)")
        for state in results:
            match = f" ({state.best_match_percent:.2f}%)" if state.best_match_percent is not None else ""
            print(f"  {state.module}::{state.function} @ 0x{state.address:08X} -> {state.status}{match}")
        print(f"Report: {report_path}")
    return 0


def _run_match_status(args: argparse.Namespace) -> int:
    functions = discover_functions(args.workspace)
    counts: dict[str, int] = {}
    for function in functions:
        counts[function.state.status] = counts.get(function.state.status, 0) + 1
    report_path = write_match_status_report(args.workspace, functions)

    payload = {
        "total": len(functions),
        "counts": counts,
        "report": str(report_path),
        "functions": [
            {
                "module": function.module,
                "function": function.function,
                "address": function.address,
                "status": function.state.status,
                "attempts": function.state.attempts,
                "best_match_percent": function.state.best_match_percent,
            }
            for function in functions
        ],
    }
    if not _write_json(payload, args.json):
        print(f"Functions: {len(functions)}")
        for status, count in sorted(counts.items()):
            print(f"  {status}: {count}")
        print(f"Report: {report_path}")
    return 0


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
            result = generate_game_project(
                args.input,
                args.output,
                nid_databases=args.nid_db,
                recovery_backends=_build_recovery_backends(args),
                recovery_max_output_bytes=args.recovery_max_bytes,
            )
            analysis = json.loads(result.analysis_path.read_text(encoding="utf-8"))
            print(f"Game: {analysis.get('title') or '<unknown>'}")
            if analysis.get("disc_id"):
                print(f"Disc ID: {analysis['disc_id']}")
            print(f"Executable candidates: {result.module_count}")
            print(f"Analyzed modules: {result.analyzed_count}")
            print(f"Recovered modules: {result.recovered_count}")
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

        if args.command == "prepare-game":
            manifest = prepare_game_workspace(args.input, args.workspace)
            print(f"Workspace: {args.workspace}")
            print(f"Source kind: {manifest.source_kind}")
            print(f"Files: {len(manifest.files)}")
            print(f"Source identity: {manifest.source_identity}")
            return 0

        if args.command == "analyze-workspace":
            result = analyze_game_workspace(
                args.workspace,
                nid_databases=args.nid_db,
                recovery_backends=_build_recovery_backends(args),
                recovery_max_output_bytes=args.recovery_max_bytes,
            )
            game = result.game_project
            print(f"Workspace: {args.workspace}")
            print(f"Reused: {'yes' if result.reused else 'no'}")
            print(f"Analysis key: {result.analysis_key}")
            print(f"Executable candidates: {game.module_count}")
            print(f"Analyzed modules: {game.analyzed_count}")
            print(f"Recovered modules: {game.recovered_count}")
            print(f"Needs decryption: {game.needs_decryption_count}")
            print(f"Failed modules: {game.failed_count}")
            print(f"Resources: {game.resource_count}")
            print(f"Known resources: {game.known_resource_count}")
            print(f"Unknown resources: {game.unknown_resource_count}")
            return 0

        if args.command == "make-pack":
            result = create_analysis_pack(
                args.workspace,
                args.output,
                module=args.module,
                function=args.function,
                resource=args.resource,
                max_bytes=args.max_bytes,
                context_bytes=args.context_bytes,
            )
            print(f"Pack: {result.output_path}")
            print(f"Selector: {result.selector_kind} {result.selector_value}")
            print(f"Artifacts: {result.artifact_count}")
            print(f"Total bytes: {result.total_bytes}")
            print(f"Manifest SHA-256: {result.manifest_sha256}")
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
            result = generate_project(
                args.input,
                args.output,
                nid_databases=args.nid_db,
                load_address=args.load_address,
            )
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

        if args.command == "recover":
            backends = _build_recovery_backends(args)
            data = args.input.read_bytes()
            result = recover_bytes(data, backends=backends, max_output_bytes=args.recovery_max_bytes)
            args.output.write_bytes(result.data)
            if not _write_json(asdict(result.provenance), args.json):
                print(f"Recovered: {args.input} -> {args.output}")
                print(f"Backend: {result.provenance.recovery_backend}")
                if result.provenance.backend_version:
                    print(f"Backend version: {result.provenance.backend_version}")
                print(f"Original SHA-256: {result.provenance.original_sha256}")
                print(f"Recovered SHA-256: {result.provenance.recovered_sha256}")
                print(f"Verification: {result.provenance.verification}")
                for warning in result.provenance.warnings:
                    print(f"Warning: {warning}")
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

        if args.command == "decompile-workspace":
            return _run_decompile_workspace(args)

        if args.command == "match-status":
            return _run_match_status(args)

        if args.command == "runtime":
            return _run_runtime_command(args)
    except (
        OSError,
        ValueError,
        ParseError,
        WorkspaceError,
        AnalysisPackError,
        EngineUnavailableError,
        DisassemblyError,
        RecoveryBackendUnavailableError,
        RecoveryError,
        RuntimeBackendUnavailableError,
        RuntimeCaptureError,
        RuntimeConnectionError,
        RuntimeMappingError,
        RuntimeProtocolError,
        RuntimeTimeoutError,
        DecompilerUnavailableError,
        DecompilationError,
        MatcherUnavailableError,
        MatchingError,
        BuildToolchainUnavailableError,
        BuildFailedError,
    ) as exc:
        print(f"pspdisasm: {exc}", file=sys.stderr)
        return 2
    return 2
