from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..errors import WorkspaceError
from ..model import (
    RuntimeAddress,
    RuntimeBacktrace,
    RuntimeBreakpointObservation,
    RuntimeEvidenceSet,
    RuntimeMemoryObservation,
    RuntimeModule,
    RuntimeReconciliation,
    RuntimeRegisterSnapshot,
    RuntimeSessionInfo,
)

RUNTIME_SCHEMA_VERSION = 1


def runtime_root(workspace_dir: Path | str) -> Path:
    return Path(workspace_dir) / "runtime"


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
        raise WorkspaceError(f"runtime evidence is missing: {label}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"runtime evidence is invalid: {label}: {exc}") from exc


def _validate_schema_if_present(workspace_dir: Path | str) -> None:
    schema_path = runtime_root(workspace_dir) / "schema_version.json"
    if not schema_path.is_file():
        return
    payload = _load_json(schema_path, label="runtime/schema_version.json")
    if not isinstance(payload, dict) or payload.get("schema_version") != RUNTIME_SCHEMA_VERSION:
        raise WorkspaceError(f"unsupported runtime evidence schema: {payload!r}")


def _ensure_schema(workspace_dir: Path | str) -> None:
    """Runtime evidence has its own, independent schema lifecycle from static
    analysis (ANALYSIS_SCHEMA_VERSION): capturing new runtime evidence must
    never force a re-run of static analysis, and vice versa."""
    schema_path = runtime_root(workspace_dir) / "schema_version.json"
    if schema_path.is_file():
        _validate_schema_if_present(workspace_dir)
        return
    _atomic_write_json(schema_path, {"schema_version": RUNTIME_SCHEMA_VERSION})


def _safe_session_id(session_id: str) -> str:
    if not session_id or "/" in session_id or "\\" in session_id or session_id in {".", ".."}:
        raise WorkspaceError(f"unsafe runtime session id: {session_id!r}")
    return session_id


def _address_from_dict(payload: object) -> RuntimeAddress | None:
    if payload is None:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("domain"), str) or not isinstance(
        payload.get("value"), int
    ):
        raise WorkspaceError("invalid RuntimeAddress in runtime evidence")
    module_path = payload.get("module_path")
    return RuntimeAddress(
        domain=payload["domain"], value=payload["value"], module_path=module_path if isinstance(module_path, str) else None
    )


def _required_address_from_dict(payload: object) -> RuntimeAddress:
    address = _address_from_dict(payload)
    if address is None:
        raise WorkspaceError("runtime evidence is missing a required RuntimeAddress")
    return address


def _module_from_dict(payload: object) -> RuntimeModule:
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid RuntimeModule in runtime evidence")
    try:
        return RuntimeModule(
            name=payload.get("name"),
            runtime_base=_required_address_from_dict(payload["runtime_base"]),
            runtime_size=payload.get("runtime_size"),
            static_module_path=payload.get("static_module_path"),
            resolution_status=str(payload["resolution_status"]),
            evidence=list(payload.get("evidence", [])),
        )
    except KeyError as exc:
        raise WorkspaceError(f"RuntimeModule is missing {exc.args[0]!r}") from exc


def _register_snapshot_from_dict(payload: object) -> RuntimeRegisterSnapshot | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid RuntimeRegisterSnapshot in runtime evidence")
    return RuntimeRegisterSnapshot(
        session_id=str(payload["session_id"]),
        sequence=int(payload["sequence"]),
        registers=dict(payload.get("registers", {})),
    )


def _memory_observation_from_dict(payload: object) -> RuntimeMemoryObservation:
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid RuntimeMemoryObservation in runtime evidence")
    return RuntimeMemoryObservation(
        session_id=str(payload["session_id"]),
        sequence=int(payload["sequence"]),
        address=_required_address_from_dict(payload["address"]),
        size=int(payload["size"]),
        sha256=str(payload["sha256"]),
    )


def _backtrace_from_dict(payload: object) -> RuntimeBacktrace | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid RuntimeBacktrace in runtime evidence")
    return RuntimeBacktrace(
        session_id=str(payload["session_id"]),
        sequence=int(payload["sequence"]),
        frames=[_required_address_from_dict(frame) for frame in payload.get("frames", [])],
    )


def _observation_from_dict(payload: object) -> RuntimeBreakpointObservation:
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid RuntimeBreakpointObservation in runtime evidence")
    try:
        return RuntimeBreakpointObservation(
            session_id=str(payload["session_id"]),
            sequence=int(payload["sequence"]),
            breakpoint_address=_required_address_from_dict(payload["breakpoint_address"]),
            hit_count=int(payload["hit_count"]),
            registers=_register_snapshot_from_dict(payload.get("registers")),
            memory=[_memory_observation_from_dict(item) for item in payload.get("memory", [])],
            backtrace=_backtrace_from_dict(payload.get("backtrace")),
            warnings=list(payload.get("warnings", [])),
        )
    except KeyError as exc:
        raise WorkspaceError(f"RuntimeBreakpointObservation is missing {exc.args[0]!r}") from exc


def _reconciliation_from_dict(payload: object) -> RuntimeReconciliation:
    if not isinstance(payload, dict):
        raise WorkspaceError("invalid RuntimeReconciliation in runtime evidence")
    try:
        return RuntimeReconciliation(
            static_kind=str(payload["static_kind"]),
            static_address=_address_from_dict(payload.get("static_address")),
            static_evidence=list(payload.get("static_evidence", [])),
            runtime_address=_required_address_from_dict(payload["runtime_address"]),
            resolved_module_offset=_address_from_dict(payload.get("resolved_module_offset")),
            observation_count=int(payload["observation_count"]),
            status=str(payload["status"]),
            conflicts=list(payload.get("conflicts", [])),
        )
    except KeyError as exc:
        raise WorkspaceError(f"RuntimeReconciliation is missing {exc.args[0]!r}") from exc


def save_session_info(workspace_dir: Path | str, info: RuntimeSessionInfo) -> Path:
    _ensure_schema(workspace_dir)
    session_id = _safe_session_id(info.session_id)
    path = runtime_root(workspace_dir) / "sessions" / f"{session_id}.json"
    _atomic_write_json(path, asdict(info))
    return path


def load_session_info(workspace_dir: Path | str, session_id: str) -> RuntimeSessionInfo:
    _validate_schema_if_present(workspace_dir)
    session_id = _safe_session_id(session_id)
    path = runtime_root(workspace_dir) / "sessions" / f"{session_id}.json"
    payload = _load_json(path, label=f"sessions/{session_id}.json")
    if not isinstance(payload, dict):
        raise WorkspaceError(f"invalid runtime session info: {session_id}")
    try:
        return RuntimeSessionInfo(
            session_id=str(payload["session_id"]),
            host=str(payload["host"]),
            port=int(payload["port"]),
            ppsspp_revision=payload.get("ppsspp_revision"),
            workspace_source_identity=payload.get("workspace_source_identity"),
        )
    except KeyError as exc:
        raise WorkspaceError(f"runtime session info is missing {exc.args[0]!r}") from exc


def save_observations(
    workspace_dir: Path | str, session_id: str, observations: list[RuntimeBreakpointObservation]
) -> Path:
    _ensure_schema(workspace_dir)
    session_id = _safe_session_id(session_id)
    path = runtime_root(workspace_dir) / "evidence" / session_id / "observations.json"
    _atomic_write_json(path, [asdict(observation) for observation in observations])
    return path


def load_observations(workspace_dir: Path | str, session_id: str) -> list[RuntimeBreakpointObservation]:
    _validate_schema_if_present(workspace_dir)
    session_id = _safe_session_id(session_id)
    path = runtime_root(workspace_dir) / "evidence" / session_id / "observations.json"
    payload = _load_json(path, label=f"evidence/{session_id}/observations.json")
    if not isinstance(payload, list):
        raise WorkspaceError(f"invalid runtime observations: {session_id}")
    return [_observation_from_dict(entry) for entry in payload]


def save_evidence_set(workspace_dir: Path | str, evidence: RuntimeEvidenceSet) -> None:
    save_session_info(workspace_dir, evidence.session)
    save_observations(workspace_dir, evidence.session.session_id, evidence.observations)
    save_module_map(workspace_dir, evidence.modules)


def save_module_map(workspace_dir: Path | str, modules: list[RuntimeModule]) -> Path:
    _ensure_schema(workspace_dir)
    path = runtime_root(workspace_dir) / "modules.json"
    _atomic_write_json(path, [asdict(module) for module in modules])
    return path


def load_module_map(workspace_dir: Path | str) -> list[RuntimeModule]:
    _validate_schema_if_present(workspace_dir)
    path = runtime_root(workspace_dir) / "modules.json"
    if not path.is_file():
        return []
    payload = _load_json(path, label="modules.json")
    if not isinstance(payload, list):
        raise WorkspaceError("invalid runtime module map")
    return [_module_from_dict(entry) for entry in payload]


def save_reconciliation(workspace_dir: Path | str, reconciliations: list[RuntimeReconciliation]) -> Path:
    _ensure_schema(workspace_dir)
    path = runtime_root(workspace_dir) / "reconciliation.json"
    _atomic_write_json(path, [asdict(item) for item in reconciliations])
    return path


def load_reconciliation(workspace_dir: Path | str) -> list[RuntimeReconciliation]:
    _validate_schema_if_present(workspace_dir)
    path = runtime_root(workspace_dir) / "reconciliation.json"
    if not path.is_file():
        return []
    payload = _load_json(path, label="reconciliation.json")
    if not isinstance(payload, list):
        raise WorkspaceError("invalid runtime reconciliation evidence")
    return [_reconciliation_from_dict(entry) for entry in payload]


def list_sessions(workspace_dir: Path | str) -> list[str]:
    sessions_dir = runtime_root(workspace_dir) / "sessions"
    if not sessions_dir.is_dir():
        return []
    return sorted(path.stem for path in sessions_dir.glob("*.json"))
