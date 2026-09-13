from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any

from ..errors import WorkspaceError
from ..model import DecompilationAttempt, FunctionDecompilationState

DECOMPILATION_SCHEMA_VERSION = 1


def decompilation_root(workspace_dir: Path | str) -> Path:
    return Path(workspace_dir) / "decompilation"


def _atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    try:
        temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def _load_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkspaceError(f"decompilation state is missing: {label}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"decompilation state is invalid: {label}: {exc}") from exc


def _validate_schema_if_present(workspace_dir: Path | str) -> None:
    schema_path = decompilation_root(workspace_dir) / "schema_version.json"
    if not schema_path.is_file():
        return
    payload = _load_json(schema_path, label="decompilation/schema_version.json")
    if not isinstance(payload, dict) or payload.get("schema_version") != DECOMPILATION_SCHEMA_VERSION:
        raise WorkspaceError(f"unsupported decompilation state schema: {payload!r}")


def _ensure_schema(workspace_dir: Path | str) -> None:
    """Decompilation state has its own schema lifecycle, independent of both
    ANALYSIS_SCHEMA_VERSION (Phase 8A) and RUNTIME_SCHEMA_VERSION (Phase 8C):
    recording an attempt must never force a static re-analysis or discard
    runtime evidence, and vice versa."""
    schema_path = decompilation_root(workspace_dir) / "schema_version.json"
    if schema_path.is_file():
        _validate_schema_if_present(workspace_dir)
        return
    _atomic_write_json(schema_path, {"schema_version": DECOMPILATION_SCHEMA_VERSION})


def _safe_function_stem(function: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in function).strip("._")
    return cleaned or "function"


def _function_dir(workspace_dir: Path | str, module: str, function: str) -> Path:
    root = decompilation_root(workspace_dir) / "functions"
    module_pure = PurePosixPath(module.replace("\\", "/"))
    if not module or module_pure.is_absolute() or ".." in module_pure.parts or not module_pure.parts:
        raise WorkspaceError(f"unsafe decompilation module path: {module!r}")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*module_pure.parts) / _safe_function_stem(function)).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise WorkspaceError(f"unsafe decompilation function path: {module!r}/{function!r}")
    return target


def _attempt_from_dict(payload: object) -> DecompilationAttempt:
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid DecompilationAttempt in decompilation state")
    try:
        return DecompilationAttempt(
            attempt_id=str(payload["attempt_id"]),
            variant_reason=str(payload["variant_reason"]),
            assembly_sha256=str(payload["assembly_sha256"]),
            context_sha256=list(payload.get("context_sha256", [])),
            m2c_command=list(payload.get("m2c_command", [])),
            m2c_version=payload.get("m2c_version"),
            target=str(payload["target"]),
            outcome=str(payload["outcome"]),
            candidate_sha256=payload.get("candidate_sha256"),
            toolchain_name=payload.get("toolchain_name"),
            toolchain_identity=payload.get("toolchain_identity"),
            object_sha256=payload.get("object_sha256"),
            match_raw_score=payload.get("match_raw_score"),
            match_max_score=payload.get("match_max_score"),
            match_similarity_percent=payload.get("match_similarity_percent"),
            match_exact=payload.get("match_exact"),
            matching_rows=payload.get("matching_rows"),
            changed_rows=payload.get("changed_rows"),
            added_rows=payload.get("added_rows"),
            removed_rows=payload.get("removed_rows"),
            reference_lacks_relocations=bool(payload.get("reference_lacks_relocations", False)),
            diagnostics=list(payload.get("diagnostics", [])),
            artifact_paths=dict(payload.get("artifact_paths", {})),
        )
    except KeyError as exc:
        raise WorkspaceError(f"DecompilationAttempt is missing {exc.args[0]!r}") from exc


def _state_from_dict(payload: object) -> FunctionDecompilationState:
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid FunctionDecompilationState in decompilation state")
    try:
        return FunctionDecompilationState(
            module=str(payload["module"]),
            function=str(payload["function"]),
            address=int(payload["address"]),
            status=str(payload["status"]),
            attempts=int(payload.get("attempts", 0)),
            best_attempt_id=payload.get("best_attempt_id"),
            best_match_percent=payload.get("best_match_percent"),
            static_confidence=payload.get("static_confidence"),
            static_evidence=list(payload.get("static_evidence", [])),
            runtime_status=payload.get("runtime_status"),
            last_failure=payload.get("last_failure"),
            attempt_history=[_attempt_from_dict(item) for item in payload.get("attempt_history", [])],
        )
    except KeyError as exc:
        raise WorkspaceError(f"FunctionDecompilationState is missing {exc.args[0]!r}") from exc


def save_function_state(workspace_dir: Path | str, state: FunctionDecompilationState) -> Path:
    _ensure_schema(workspace_dir)
    path = _function_dir(workspace_dir, state.module, state.function) / "state.json"
    _atomic_write_json(path, asdict(state))
    return path


def load_function_state(workspace_dir: Path | str, module: str, function: str) -> FunctionDecompilationState | None:
    _validate_schema_if_present(workspace_dir)
    path = _function_dir(workspace_dir, module, function) / "state.json"
    if not path.is_file():
        return None
    payload = _load_json(path, label=f"functions/{module}/{function}/state.json")
    return _state_from_dict(payload)


def list_function_states(workspace_dir: Path | str) -> list[FunctionDecompilationState]:
    _validate_schema_if_present(workspace_dir)
    functions_root = decompilation_root(workspace_dir) / "functions"
    if not functions_root.is_dir():
        return []
    states: list[FunctionDecompilationState] = []
    for state_path in functions_root.rglob("state.json"):
        payload = _load_json(state_path, label=str(state_path))
        states.append(_state_from_dict(payload))
    states.sort(key=lambda state: (state.module.casefold(), state.function.casefold(), state.address))
    return states
