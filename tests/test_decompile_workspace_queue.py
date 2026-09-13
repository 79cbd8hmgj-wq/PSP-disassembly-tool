from __future__ import annotations

import json

import pytest

from pspdisasm.errors import WorkspaceError
from pspdisasm.model import FunctionDecompilationState
from pspdisasm.decompile.queue import (
    DecompilationStatus,
    QueueFilters,
    discover_functions,
    enrich_with_runtime_evidence,
    select_functions,
)
from pspdisasm.decompile.workspace import save_function_state


def _write_game_analysis(workspace, modules: list[dict]) -> None:
    metadata_dir = workspace / "analysis" / "game_project" / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (metadata_dir / "game_analysis.json").write_text(json.dumps({"modules": modules}), encoding="utf-8")


def _write_functions_json(workspace, project_path: str, functions: list[dict]) -> None:
    project_dir = workspace / "analysis" / "game_project" / project_path / "metadata"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "functions.json").write_text(json.dumps(functions), encoding="utf-8")


def _basic_workspace(tmp_path):
    _write_game_analysis(
        tmp_path,
        [
            {
                "path": "PSP_GAME/SYSDIR/EBOOT.BIN",
                "status": "analyzed",
                "project_path": "projects/PSP_GAME/SYSDIR/EBOOT.BIN",
                "extracted_path": "modules/PSP_GAME/SYSDIR/EBOOT.BIN",
            },
            {
                "path": "PSP_GAME/USRDIR/OTHER.PRX",
                "status": "needs_decryption",
                "project_path": None,
            },
        ],
    )
    _write_functions_json(
        tmp_path,
        "projects/PSP_GAME/SYSDIR/EBOOT.BIN",
        [
            {"name": "func_08800000", "address": 0x08800000, "size": 64, "instruction_count": 16},
            {"name": "func_08800100", "address": 0x08800100, "size": 8, "instruction_count": 2},
        ],
    )
    return tmp_path


def test_discover_functions_reads_only_analyzed_modules(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)

    assert len(functions) == 2
    assert {f.function for f in functions} == {"func_08800000", "func_08800100"}
    assert all(f.module == "PSP_GAME/SYSDIR/EBOOT.BIN" for f in functions)


def test_discover_functions_skips_modules_without_a_project(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)
    assert all(f.module != "PSP_GAME/USRDIR/OTHER.PRX" for f in functions)


def test_discover_functions_requires_analyzed_workspace(tmp_path):
    with pytest.raises(WorkspaceError):
        discover_functions(tmp_path)


def test_discover_functions_attaches_existing_persisted_state(tmp_path):
    workspace = _basic_workspace(tmp_path)
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800000",
            address=0x08800000,
            status=DecompilationStatus.MATCHED_EXACT.value,
            best_match_percent=100.0,
        ),
    )

    functions = discover_functions(workspace)
    by_name = {f.function: f for f in functions}
    assert by_name["func_08800000"].state.status == DecompilationStatus.MATCHED_EXACT.value
    assert by_name["func_08800100"].state.status == DecompilationStatus.PENDING.value


def test_select_functions_default_excludes_matched_exact(tmp_path):
    workspace = _basic_workspace(tmp_path)
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800000",
            address=0x08800000,
            status=DecompilationStatus.MATCHED_EXACT.value,
            best_match_percent=100.0,
        ),
    )
    functions = discover_functions(workspace)

    selected = select_functions(functions, QueueFilters())
    assert [f.function for f in selected] == ["func_08800100"]


def test_select_functions_orders_smallest_function_first(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)

    selected = select_functions(functions, QueueFilters())
    assert [f.function for f in selected] == ["func_08800100", "func_08800000"]


def test_select_functions_ordering_is_deterministic_across_runs(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)

    first = select_functions(functions, QueueFilters())
    second = select_functions(functions, QueueFilters())
    assert [f.function for f in first] == [f.function for f in second]


def test_select_functions_module_filter(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)

    selected = select_functions(functions, QueueFilters(module="PSP_GAME/SYSDIR/EBOOT.BIN"))
    assert len(selected) == 2
    selected_none = select_functions(functions, QueueFilters(module="PSP_GAME/USRDIR/NOTHING.PRX"))
    assert selected_none == []


def test_select_functions_function_filter_by_name_and_address_bypasses_ordering(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)

    by_name = select_functions(functions, QueueFilters(function="func_08800000"))
    assert [f.function for f in by_name] == ["func_08800000"]

    by_address = select_functions(functions, QueueFilters(function="0x08800100"))
    assert [f.function for f in by_address] == ["func_08800100"]


def test_select_functions_function_filter_ignores_default_done_exclusion(tmp_path):
    workspace = _basic_workspace(tmp_path)
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800000",
            address=0x08800000,
            status=DecompilationStatus.MATCHED_EXACT.value,
            best_match_percent=100.0,
        ),
    )
    functions = discover_functions(workspace)

    # --function explicitly requested must still be selectable even though it's
    # already matched_exact -- this is how a forced re-run/retry is expressed.
    selected = select_functions(functions, QueueFilters(function="func_08800000"))
    assert [f.function for f in selected] == ["func_08800000"]


def test_select_functions_below_match_threshold(tmp_path):
    workspace = _basic_workspace(tmp_path)
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800000",
            address=0x08800000,
            status=DecompilationStatus.MATCHED_PARTIAL.value,
            best_match_percent=90.0,
        ),
    )
    functions = discover_functions(workspace)

    selected = select_functions(functions, QueueFilters(below_match=95.0))
    assert {f.function for f in selected} == {"func_08800000", "func_08800100"}

    selected_strict = select_functions(functions, QueueFilters(below_match=50.0))
    assert {f.function for f in selected_strict} == {"func_08800100"}


def test_select_functions_unmatched_only(tmp_path):
    workspace = _basic_workspace(tmp_path)
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800000",
            address=0x08800000,
            status=DecompilationStatus.MATCHED_EXACT.value,
            best_match_percent=100.0,
        ),
    )
    functions = discover_functions(workspace)

    selected = select_functions(functions, QueueFilters(unmatched_only=True))
    assert [f.function for f in selected] == ["func_08800100"]


def test_select_functions_limit(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)

    selected = select_functions(functions, QueueFilters(limit=1))
    assert len(selected) == 1


def test_select_functions_blocked_and_unsupported_are_excluded_by_default(tmp_path):
    workspace = _basic_workspace(tmp_path)
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800000",
            address=0x08800000,
            status=DecompilationStatus.BLOCKED.value,
        ),
    )
    save_function_state(
        workspace,
        FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN",
            function="func_08800100",
            address=0x08800100,
            status=DecompilationStatus.UNSUPPORTED.value,
        ),
    )
    functions = discover_functions(workspace)

    assert select_functions(functions, QueueFilters()) == []


def test_enrich_with_runtime_evidence_is_a_noop_without_reconciliation_file(tmp_path):
    workspace = _basic_workspace(tmp_path)
    functions = discover_functions(workspace)
    enriched = enrich_with_runtime_evidence(functions, workspace)
    assert all(f.state.runtime_status is None for f in enriched)


def test_enrich_with_runtime_evidence_attaches_matching_status(tmp_path):
    from pspdisasm.model import RuntimeAddress, RuntimeReconciliation
    from pspdisasm.runtime.workspace import save_reconciliation

    workspace = _basic_workspace(tmp_path)
    save_reconciliation(
        workspace,
        [
            RuntimeReconciliation(
                static_kind="function",
                static_address=RuntimeAddress(domain="analysis", value=0x08800000, module_path="PSP_GAME/SYSDIR/EBOOT.BIN"),
                static_evidence=["sub_08800000"],
                runtime_address=RuntimeAddress(domain="runtime", value=0x09A00000),
                resolved_module_offset=None,
                observation_count=3,
                status="runtime_verified",
            )
        ],
    )
    functions = discover_functions(workspace)

    enriched = enrich_with_runtime_evidence(functions, workspace)
    by_name = {f.function: f for f in enriched}
    assert by_name["func_08800000"].state.runtime_status == "runtime_verified"
    assert by_name["func_08800100"].state.runtime_status is None


def test_enrich_with_runtime_evidence_prefers_conflicting_over_other_matches(tmp_path):
    from pspdisasm.model import RuntimeAddress, RuntimeReconciliation
    from pspdisasm.runtime.workspace import save_reconciliation

    workspace = _basic_workspace(tmp_path)
    save_reconciliation(
        workspace,
        [
            RuntimeReconciliation(
                static_kind="function",
                static_address=RuntimeAddress(domain="analysis", value=0x08800000, module_path="PSP_GAME/SYSDIR/EBOOT.BIN"),
                static_evidence=[],
                runtime_address=RuntimeAddress(domain="runtime", value=1),
                resolved_module_offset=None,
                observation_count=1,
                status="runtime_verified",
            ),
            RuntimeReconciliation(
                static_kind="function",
                static_address=RuntimeAddress(domain="analysis", value=0x08800000, module_path="PSP_GAME/SYSDIR/EBOOT.BIN"),
                static_evidence=[],
                runtime_address=RuntimeAddress(domain="runtime", value=2),
                resolved_module_offset=None,
                observation_count=1,
                status="conflicting",
            ),
        ],
    )
    functions = discover_functions(workspace)

    enriched = enrich_with_runtime_evidence(functions, workspace)
    by_name = {f.function: f for f in enriched}
    assert by_name["func_08800000"].state.runtime_status == "conflicting"
