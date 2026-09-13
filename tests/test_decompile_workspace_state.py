from __future__ import annotations

import json

import pytest

from pspdisasm.errors import WorkspaceError
from pspdisasm.model import DecompilationAttempt, FunctionDecompilationState
from pspdisasm.decompile.workspace import (
    DECOMPILATION_SCHEMA_VERSION,
    decompilation_root,
    list_function_states,
    load_function_state,
    save_function_state,
)


def _attempt(attempt_id: str = "abc123", **overrides: object) -> DecompilationAttempt:
    defaults = dict(
        attempt_id=attempt_id,
        variant_reason="default",
        assembly_sha256="a" * 64,
        context_sha256=[],
        m2c_command=["m2c"],
        m2c_version="1.0",
        target="mipsel-gcc-c",
        outcome="matched_partial",
    )
    defaults.update(overrides)
    return DecompilationAttempt(**defaults)


def _state(**overrides: object) -> FunctionDecompilationState:
    defaults = dict(
        module="PSP_GAME/SYSDIR/EBOOT.BIN",
        function="func_08812340",
        address=0x08812340,
        status="pending",
    )
    defaults.update(overrides)
    return FunctionDecompilationState(**defaults)


def test_save_and_load_function_state_round_trips(tmp_path):
    state = _state(attempt_history=[_attempt()], attempts=1, best_attempt_id="abc123", best_match_percent=87.34)
    save_function_state(tmp_path, state)

    loaded = load_function_state(tmp_path, state.module, state.function)
    assert loaded == state


def test_load_missing_function_state_returns_none(tmp_path):
    assert load_function_state(tmp_path, "PSP_GAME/SYSDIR/EBOOT.BIN", "func_00000000") is None


def test_save_writes_schema_version_file(tmp_path):
    save_function_state(tmp_path, _state())
    payload = json.loads((decompilation_root(tmp_path) / "schema_version.json").read_text())
    assert payload == {"schema_version": DECOMPILATION_SCHEMA_VERSION}


def test_load_rejects_unsupported_schema(tmp_path):
    save_function_state(tmp_path, _state())
    schema_path = decompilation_root(tmp_path) / "schema_version.json"
    schema_path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")

    with pytest.raises(WorkspaceError, match="unsupported decompilation state schema"):
        load_function_state(tmp_path, "PSP_GAME/SYSDIR/EBOOT.BIN", "func_08812340")


def test_function_path_traversal_is_rejected(tmp_path):
    with pytest.raises(WorkspaceError, match="unsafe"):
        save_function_state(tmp_path, _state(module="../escape"))


def test_function_path_absolute_module_is_rejected(tmp_path):
    with pytest.raises(WorkspaceError, match="unsafe"):
        save_function_state(tmp_path, _state(module="/etc/passwd"))


def test_function_name_is_sanitized_for_filesystem_safety(tmp_path):
    state = _state(function="weird/../name!!")
    # Must not raise and must not escape the functions root.
    save_function_state(tmp_path, state)
    functions_root = (decompilation_root(tmp_path) / "functions").resolve()
    for path in functions_root.rglob("state.json"):
        assert functions_root in path.resolve().parents


def test_list_function_states_is_sorted_and_deterministic(tmp_path):
    save_function_state(tmp_path, _state(module="PSP_GAME/SYSDIR/EBOOT.BIN", function="func_zzz", address=2))
    save_function_state(tmp_path, _state(module="PSP_GAME/SYSDIR/EBOOT.BIN", function="func_aaa", address=1))
    save_function_state(tmp_path, _state(module="PSP_GAME/USRDIR/OTHER.PRX", function="func_mmm", address=3))

    states = list_function_states(tmp_path)
    assert [(state.module, state.function) for state in states] == [
        ("PSP_GAME/SYSDIR/EBOOT.BIN", "func_aaa"),
        ("PSP_GAME/SYSDIR/EBOOT.BIN", "func_zzz"),
        ("PSP_GAME/USRDIR/OTHER.PRX", "func_mmm"),
    ]


def test_list_function_states_empty_workspace(tmp_path):
    assert list_function_states(tmp_path) == []


def test_writes_are_atomic_no_leftover_temp_files(tmp_path):
    save_function_state(tmp_path, _state())
    leftovers = list(decompilation_root(tmp_path).rglob(".*.tmp"))
    assert leftovers == []


def test_attempt_history_is_preserved_and_never_erased_on_resave(tmp_path):
    state = _state(attempt_history=[_attempt("first")], attempts=1)
    save_function_state(tmp_path, state)

    updated = _state(attempt_history=[_attempt("first"), _attempt("second")], attempts=2, best_attempt_id="second")
    save_function_state(tmp_path, updated)

    loaded = load_function_state(tmp_path, state.module, state.function)
    assert [attempt.attempt_id for attempt in loaded.attempt_history] == ["first", "second"]


def test_decompilation_state_never_touches_static_or_runtime_trees(tmp_path):
    analysis_marker = tmp_path / "analysis" / "state.json"
    analysis_marker.parent.mkdir(parents=True)
    analysis_marker.write_text('{"analysis_key": "unchanged"}', encoding="utf-8")
    runtime_marker = tmp_path / "runtime" / "modules.json"
    runtime_marker.parent.mkdir(parents=True)
    runtime_marker.write_text("[]", encoding="utf-8")

    save_function_state(tmp_path, _state())

    assert analysis_marker.read_text(encoding="utf-8") == '{"analysis_key": "unchanged"}'
    assert runtime_marker.read_text(encoding="utf-8") == "[]"
