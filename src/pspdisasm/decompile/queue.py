from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Iterable

from ..advanced import analyze_advanced
from ..analyzer import analyze_file
from ..disassembler import disassemble_file
from ..errors import EngineUnavailableError, WorkspaceError
from ..model import FunctionDecompilationState
from ..runtime.workspace import load_reconciliation
from .workspace import load_function_state


class DecompilationStatus(str, Enum):
    PENDING = "pending"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    CANDIDATE_GENERATED = "candidate_generated"
    BUILD_FAILED = "build_failed"
    MATCHED_PARTIAL = "matched_partial"
    MATCHED_EXACT = "matched_exact"


_DONE_STATUSES = frozenset(
    {
        DecompilationStatus.MATCHED_EXACT.value,
        DecompilationStatus.SKIPPED.value,
        DecompilationStatus.BLOCKED.value,
        DecompilationStatus.UNSUPPORTED.value,
    }
)

# Preserve conflicts rather than hide them: a function whose runtime evidence
# conflicts is reported first, regardless of which reconciliation matched last.
_RUNTIME_STATUS_RANK = {
    "conflicting": 0,
    "runtime_verified": 1,
    "corroborated": 2,
    "runtime_observed": 3,
    "inferred": 4,
    "unresolved": 5,
}


@dataclass(frozen=True, slots=True)
class QueuedFunction:
    module: str
    project_dir: Path
    function: str
    address: int
    size: int
    instruction_count: int
    state: FunctionDecompilationState


@dataclass(frozen=True, slots=True)
class QueueFilters:
    module: str | None = None
    function: str | None = None
    below_match: float | None = None
    unmatched_only: bool = False
    limit: int | None = None


def _load_game_analysis_modules(workspace_dir: Path | str) -> list[dict]:
    path = Path(workspace_dir) / "analysis" / "game_project" / "metadata" / "game_analysis.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkspaceError(f"workspace has no analyzed game project: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"invalid game analysis metadata: {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("modules"), list):
        raise WorkspaceError(f"invalid game analysis metadata: {path}")
    return [module for module in payload["modules"] if isinstance(module, dict)]


def _read_functions_json(project_dir: Path) -> list[dict]:
    path = project_dir / "metadata" / "functions.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    result: list[dict] = []
    for item in payload:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("address"), int):
            result.append(item)
    return result


def discover_functions(workspace_dir: Path | str) -> list[QueuedFunction]:
    """Enumerate every function in every already-analyzed module's Splat project.

    Reads only what Phase 8A/7 already produced (game_analysis.json,
    metadata/functions.json); computes nothing new. Existing persisted
    Phase 8D state is attached when present, else a fresh pending state.
    """
    workspace = Path(workspace_dir)
    game_root = workspace / "analysis" / "game_project"
    modules = sorted(
        (
            module
            for module in _load_game_analysis_modules(workspace)
            if module.get("status") in ("analyzed", "analyzed_recovered") and module.get("project_path")
        ),
        key=lambda module: str(module["path"]).casefold(),
    )

    queued: list[QueuedFunction] = []
    for module in modules:
        module_path = str(module["path"])
        project_dir = game_root / str(module["project_path"])
        entries = sorted(_read_functions_json(project_dir), key=lambda entry: (entry["address"], entry["name"]))
        for entry in entries:
            function_name = entry["name"]
            state = load_function_state(workspace, module_path, function_name)
            if state is None:
                state = FunctionDecompilationState(
                    module=module_path,
                    function=function_name,
                    address=entry["address"],
                    status=DecompilationStatus.PENDING.value,
                )
            queued.append(
                QueuedFunction(
                    module=module_path,
                    project_dir=project_dir,
                    function=function_name,
                    address=entry["address"],
                    size=int(entry.get("size", 0)),
                    instruction_count=int(entry.get("instruction_count", 0)),
                    state=state,
                )
            )
    return queued


def enrich_with_runtime_evidence(functions: Iterable[QueuedFunction], workspace_dir: Path | str) -> list[QueuedFunction]:
    """Attach Phase 8C reconciliation status where it covers a function's address range.

    Cheap and always safe to call: reads an existing JSON file (empty list if
    absent) and never recomputes anything. Never silently promotes conflicting
    or unresolved evidence into a hard fact -- a conflicting match is surfaced,
    not hidden.
    """
    reconciliations = load_reconciliation(workspace_dir)
    if not reconciliations:
        return list(functions)

    by_module: dict[str, list[tuple[int, str]]] = {}
    for item in reconciliations:
        if item.static_address is None or item.static_address.module_path is None:
            continue
        by_module.setdefault(item.static_address.module_path, []).append((item.static_address.value, item.status))

    enriched: list[QueuedFunction] = []
    for function in functions:
        candidates = by_module.get(function.module, [])
        matches = [
            status
            for address, status in candidates
            if function.address <= address < function.address + max(function.size, 1)
        ]
        if not matches:
            enriched.append(function)
            continue
        best = min(matches, key=lambda status: _RUNTIME_STATUS_RANK.get(status, len(_RUNTIME_STATUS_RANK)))
        enriched.append(replace(function, state=replace(function.state, runtime_status=best)))
    return enriched


def enrich_with_static_confidence(functions: Iterable[QueuedFunction], workspace_dir: Path | str) -> list[QueuedFunction]:
    """Opt-in: compute Phase 6A function confidence per module (one disassembly pass each).

    Degrades gracefully -- if the optional analysis engines aren't installed,
    the queue still works, just without confidence-based tie-breaking.
    """
    functions = list(functions)
    by_module: dict[str, Path] = {}
    for function in functions:
        by_module.setdefault(function.module, function.project_dir)

    workspace = Path(workspace_dir)
    modules_metadata = {str(m["path"]): m for m in _load_game_analysis_modules(workspace)}
    confidence_by_module: dict[str, dict[int, tuple[float, list[str]]]] = {}
    for module_path in by_module:
        module_record = modules_metadata.get(module_path)
        extracted_path = module_record.get("extracted_path") if module_record else None
        if not extracted_path:
            continue
        source = workspace / "analysis" / "game_project" / str(extracted_path)
        try:
            model = analyze_file(source)
            disassembly = disassemble_file(source)
            advanced = analyze_advanced(model, disassembly)
        except EngineUnavailableError:
            continue
        confidence_by_module[module_path] = {
            item.address: (item.score, list(item.evidence)) for item in advanced.function_confidence
        }

    enriched: list[QueuedFunction] = []
    for function in functions:
        scores = confidence_by_module.get(function.module)
        if not scores or function.address not in scores:
            enriched.append(function)
            continue
        score, evidence = scores[function.address]
        enriched.append(replace(function, state=replace(function.state, static_confidence=score, static_evidence=evidence)))
    return enriched


def _needs_work(state: FunctionDecompilationState, filters: QueueFilters) -> bool:
    if filters.below_match is not None:
        current = state.best_match_percent if state.best_match_percent is not None else 0.0
        return current < filters.below_match
    if filters.unmatched_only:
        return state.status != DecompilationStatus.MATCHED_EXACT.value
    return state.status not in _DONE_STATUSES


def _selector_matches(function: QueuedFunction, selector: str) -> bool:
    if function.function == selector:
        return True
    try:
        value = int(selector, 0)
    except ValueError:
        return False
    return function.address == value


def _priority_key(function: QueuedFunction) -> tuple:
    return (function.size, function.module.casefold(), function.function.casefold(), function.address)


def select_functions(functions: Iterable[QueuedFunction], filters: QueueFilters) -> list[QueuedFunction]:
    """Deterministically select and order functions for a decompile-workspace run.

    `--function` bypasses ordering/needs-work filtering entirely (direct
    dispatch, also serving as the "retry one function" use case); otherwise
    already-completed work (matched_exact/skipped/blocked/unsupported) is
    excluded by default, matching functions sort smallest-first, and every
    tie is broken deterministically by module/function/address.
    """
    candidates = list(functions)
    if filters.function is not None:
        matches = [item for item in candidates if _selector_matches(item, filters.function)]
        if filters.module is not None:
            matches = [item for item in matches if item.module == filters.module]
        return sorted(matches, key=_priority_key)

    if filters.module is not None:
        candidates = [item for item in candidates if item.module == filters.module]
    candidates = [item for item in candidates if _needs_work(item.state, filters)]
    ordered = sorted(candidates, key=_priority_key)
    if filters.limit is not None:
        ordered = ordered[: filters.limit]
    return ordered
