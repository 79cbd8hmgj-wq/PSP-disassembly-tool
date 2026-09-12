from __future__ import annotations

import json

import pytest

from pspdisasm.errors import WorkspaceError
from pspdisasm.model import (
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
from pspdisasm.runtime.workspace import (
    RUNTIME_SCHEMA_VERSION,
    list_sessions,
    load_module_map,
    load_observations,
    load_reconciliation,
    load_session_info,
    runtime_root,
    save_evidence_set,
    save_module_map,
    save_observations,
    save_reconciliation,
    save_session_info,
)


def _address(value: int, domain: str = "runtime") -> RuntimeAddress:
    return RuntimeAddress(domain=domain, value=value)


def _session_info(session_id: str = "sess-1") -> RuntimeSessionInfo:
    return RuntimeSessionInfo(
        session_id=session_id, host="127.0.0.1", port=56244, ppsspp_revision="abc123",
        workspace_source_identity="deadbeef",
    )


def test_save_and_load_session_info_round_trips(tmp_path):
    info = _session_info()
    save_session_info(tmp_path, info)

    loaded = load_session_info(tmp_path, "sess-1")
    assert loaded == info


def test_save_session_info_writes_schema_version_file(tmp_path):
    save_session_info(tmp_path, _session_info())
    payload = json.loads((runtime_root(tmp_path) / "schema_version.json").read_text())
    assert payload == {"schema_version": RUNTIME_SCHEMA_VERSION}


def test_load_session_info_rejects_unsupported_schema(tmp_path):
    save_session_info(tmp_path, _session_info())
    schema_path = runtime_root(tmp_path) / "schema_version.json"
    schema_path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")

    with pytest.raises(WorkspaceError, match="unsupported runtime evidence schema"):
        load_session_info(tmp_path, "sess-1")
    with pytest.raises(WorkspaceError, match="unsupported runtime evidence schema"):
        save_session_info(tmp_path, _session_info("sess-2"))


def test_session_id_path_traversal_is_rejected(tmp_path):
    with pytest.raises(WorkspaceError, match="unsafe"):
        save_session_info(tmp_path, _session_info("../escape"))
    with pytest.raises(WorkspaceError, match="unsafe"):
        load_session_info(tmp_path, "../escape")


def test_save_and_load_observations_round_trip_with_nested_addresses(tmp_path):
    observation = RuntimeBreakpointObservation(
        session_id="sess-1",
        sequence=1,
        breakpoint_address=_address(0x08800000),
        hit_count=1,
        registers=RuntimeRegisterSnapshot(session_id="sess-1", sequence=2, registers={"pc": 0x08800000}),
        memory=[
            RuntimeMemoryObservation(
                session_id="sess-1", sequence=3, address=_address(0x08810000), size=16, sha256="a" * 64
            )
        ],
        backtrace=RuntimeBacktrace(session_id="sess-1", sequence=4, frames=[_address(0x08800004)]),
        warnings=["synthetic warning"],
    )

    save_observations(tmp_path, "sess-1", [observation])
    loaded = load_observations(tmp_path, "sess-1")

    assert loaded == [observation]


def test_load_observations_missing_session_raises_workspace_error(tmp_path):
    with pytest.raises(WorkspaceError):
        load_observations(tmp_path, "never-existed")


def test_save_and_load_module_map_round_trips(tmp_path):
    modules = [
        RuntimeModule(
            name="EBOOT.BIN",
            runtime_base=_address(0x08800000),
            runtime_size=0x10000,
            static_module_path="PSP_GAME/SYSDIR/EBOOT.BIN",
            resolution_status="user_provided",
            evidence=["user-provided mapping"],
        )
    ]
    save_module_map(tmp_path, modules)
    assert load_module_map(tmp_path) == modules


def test_load_module_map_missing_file_returns_empty_list(tmp_path):
    assert load_module_map(tmp_path) == []


def test_save_and_load_reconciliation_round_trips_and_preserves_conflicts(tmp_path):
    reconciliations = [
        RuntimeReconciliation(
            static_kind="function",
            static_address=_address(0x0881B420, domain="analysis"),
            static_evidence=["sub_0881B420"],
            runtime_address=_address(0x09A17420),
            resolved_module_offset=_address(0x17420, domain="module_relative"),
            observation_count=27,
            status="runtime_verified",
            conflicts=[],
        )
    ]
    save_reconciliation(tmp_path, reconciliations)
    assert load_reconciliation(tmp_path) == reconciliations


def test_load_reconciliation_missing_file_returns_empty_list(tmp_path):
    assert load_reconciliation(tmp_path) == []


def test_save_evidence_set_writes_session_observations_and_modules(tmp_path):
    evidence = RuntimeEvidenceSet(
        session=_session_info(),
        modules=[
            RuntimeModule(
                name="A", runtime_base=_address(1), runtime_size=None, static_module_path=None,
                resolution_status="unresolved",
            )
        ],
        observations=[
            RuntimeBreakpointObservation(
                session_id="sess-1", sequence=1, breakpoint_address=_address(1), hit_count=1
            )
        ],
    )
    save_evidence_set(tmp_path, evidence)

    assert load_session_info(tmp_path, "sess-1") == evidence.session
    assert load_observations(tmp_path, "sess-1") == evidence.observations
    assert load_module_map(tmp_path) == evidence.modules


def test_runtime_persistence_never_touches_static_analysis_tree(tmp_path):
    analysis_marker = tmp_path / "analysis" / "state.json"
    analysis_marker.parent.mkdir(parents=True)
    analysis_marker.write_text('{"analysis_key": "unchanged"}', encoding="utf-8")

    save_session_info(tmp_path, _session_info())
    save_module_map(tmp_path, [])
    save_reconciliation(tmp_path, [])

    assert analysis_marker.read_text(encoding="utf-8") == '{"analysis_key": "unchanged"}'


def test_list_sessions_is_sorted_and_deterministic(tmp_path):
    save_session_info(tmp_path, _session_info("zeta"))
    save_session_info(tmp_path, _session_info("alpha"))
    assert list_sessions(tmp_path) == ["alpha", "zeta"]


def test_list_sessions_empty_workspace(tmp_path):
    assert list_sessions(tmp_path) == []


def test_writes_are_atomic_no_leftover_temp_files(tmp_path):
    save_session_info(tmp_path, _session_info())
    save_module_map(tmp_path, [])
    save_reconciliation(tmp_path, [])

    leftovers = list(runtime_root(tmp_path).rglob(".*.tmp"))
    assert leftovers == []
