from __future__ import annotations

import json
from pathlib import Path

import pytest

from pspdisasm.decompile.orchestrator import (
    AttemptOutcome,
    run_and_persist,
    run_function,
    select_best_attempt,
)
from pspdisasm.decompile.queue import DecompilationStatus, QueuedFunction
from pspdisasm.decompile.toolchain import ExternalCompilerToolchain
from pspdisasm.decompile.workspace import load_function_state
from pspdisasm.errors import BuildToolchainUnavailableError, UnsupportedFunctionError
from pspdisasm.model import DecompilationAttempt, FunctionDecompilationState


def _write_orchestrator_project(
    tmp_path: Path, *, function_name: str = "func_08800000", assembly: str | None = None
) -> Path:
    project = tmp_path / "project"
    (project / "metadata").mkdir(parents=True)
    if assembly is None:
        assembly = "glabel func_08800000\n    addiu $v0, $zero, 1\n    jr $ra\n    nop\nendlabel func_08800000\n"
    functions = [
        {
            "name": function_name,
            "address": 0x08800000,
            "size": 12,
            "section": ".text",
            "assembly": assembly,
            "instruction_count": 3,
            "instructions": [
                {"address": 0x08800000, "word": 0x24020001, "text": "addiu $v0, $zero, 1", "valid": True, "implemented": True},
                {"address": 0x08800004, "word": 0x03E00008, "text": "jr $ra", "valid": True, "implemented": True},
                {"address": 0x08800008, "word": 0x00000000, "text": "nop", "valid": True, "implemented": True},
            ],
        }
    ]
    (project / "metadata" / "functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (project / "metadata" / "references.json").write_text("[]", encoding="utf-8")
    return project


def _write_unsupported_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "metadata").mkdir(parents=True)
    functions = [
        {
            "name": "func_empty",
            "address": 0x08800000,
            "size": 0,
            "section": ".text",
            "assembly": "",
            "instruction_count": 0,
            "instructions": [],
        }
    ]
    (project / "metadata" / "functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (project / "metadata" / "references.json").write_text("[]", encoding="utf-8")
    return project


def _queued(
    project: Path,
    *,
    function: str = "func_08800000",
    address: int = 0x08800000,
    size: int = 12,
    state: FunctionDecompilationState | None = None,
) -> QueuedFunction:
    if state is None:
        state = FunctionDecompilationState(
            module="PSP_GAME/SYSDIR/EBOOT.BIN", function=function, address=address, status=DecompilationStatus.PENDING.value
        )
    return QueuedFunction(
        module="PSP_GAME/SYSDIR/EBOOT.BIN",
        project_dir=project,
        function=function,
        address=address,
        size=size,
        instruction_count=3,
        state=state,
    )


def _write_fake_m2c(path: Path, *, output: str = "s32 func_08800000(void) { return 1; }\n", exit_code: int = 0) -> Path:
    path.write_text(
        "from __future__ import annotations\n"
        "import sys\n"
        f"sys.stdout.write({output!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return path


def _fake_compiler(tmp_path: Path, *, name: str = "fake-cc", exit_code: int = 0, write_output: bool = True) -> Path:
    body = "#!/bin/sh\n"
    if write_output:
        body += (
            "out=\"\"\n"
            "prev=\"\"\n"
            "for arg in \"$@\"; do\n"
            "  if [ \"$prev\" = \"-o\" ]; then out=\"$arg\"; fi\n"
            "  prev=\"$arg\"\n"
            "done\n"
            "if [ -n \"$out\" ]; then printf 'OBJECT' > \"$out\"; fi\n"
        )
    body += f"exit {exit_code}\n"
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_objdump(tmp_path: Path) -> Path:
    path = tmp_path / "objdump"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_asm_differ(tmp_path: Path, payload: dict, *, name: str = "diff.py", exit_code: int = 0) -> Path:
    script = tmp_path / name
    script.write_text(
        "import json, sys\n"
        + f"payload = {payload!r}\n"
        + (f"print('backend failed', file=sys.stderr); sys.exit({exit_code})\n" if exit_code else "print(json.dumps(payload))\n"),
        encoding="utf-8",
    )
    return script


_EXACT_PAYLOAD = {
    "current_score": 0,
    "max_score": 100,
    "rows": [{"key": "a", "is_data_ref": False, "base": {"text": [{"text": "a"}]}, "current": {"text": [{"text": "a"}]}}],
}

_PARTIAL_PAYLOAD = {
    "current_score": 100,
    "max_score": 400,
    "rows": [
        {"key": "same", "is_data_ref": False, "base": {"text": [{"text": "same"}]}, "current": {"text": [{"text": "same"}]}},
        {"key": "changed", "is_data_ref": False, "base": {"text": [{"text": "a"}]}, "current": {"text": [{"text": "b", "format": "diff_change"}]}},
    ],
}


class _AlwaysUnavailableToolchain:
    name = "always-unavailable"

    def identity(self) -> dict[str, object]:
        return {"kind": "always_unavailable"}

    def compile_function(self, source: Path, *, output: Path, project: Path, timeout: float):
        raise BuildToolchainUnavailableError("compiler vanished")


def test_run_function_full_pipeline_reaches_exact_match(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD)
    objdump = _fake_objdump(tmp_path)

    state = run_function(
        _queued(project), m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )

    assert state.status == DecompilationStatus.MATCHED_EXACT.value
    assert state.attempts == 1
    assert state.best_attempt_id == state.attempt_history[0].attempt_id
    assert state.best_match_percent == 100.0
    assert state.attempt_history[0].outcome == AttemptOutcome.MATCHED_EXACT.value


def test_run_function_build_failure_is_isolated(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path, exit_code=1, write_output=False))

    state = run_function(_queued(project), m2c_path=m2c, toolchain=toolchain)

    assert state.status == DecompilationStatus.BUILD_FAILED.value
    assert state.attempts == 1
    attempt = state.attempt_history[0]
    assert attempt.outcome == AttemptOutcome.BUILD_FAILED.value
    assert attempt.candidate_sha256 is not None
    assert attempt.object_sha256 is None
    assert any("exited with code 1" in diagnostic for diagnostic in attempt.diagnostics)


def test_run_function_reaches_partial_match(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    differ = _fake_asm_differ(tmp_path, _PARTIAL_PAYLOAD)
    objdump = _fake_objdump(tmp_path)

    state = run_function(
        _queued(project), m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )

    assert state.status == DecompilationStatus.MATCHED_PARTIAL.value
    assert state.best_match_percent == 75.0
    assert state.attempt_history[0].outcome == AttemptOutcome.MATCHED_PARTIAL.value


def test_select_best_attempt_orders_exact_then_similarity_then_diff_rows_then_id():
    def attempt(**overrides) -> DecompilationAttempt:
        base = dict(
            attempt_id="0" * 16,
            variant_reason="default",
            assembly_sha256="x",
            context_sha256=[],
            m2c_command=["m2c"],
            m2c_version=None,
            target="mipsel-gcc-c",
            outcome=AttemptOutcome.MATCHED_PARTIAL.value,
        )
        base.update(overrides)
        return DecompilationAttempt(**base)

    exact = attempt(attempt_id="a" * 16, match_exact=True, match_similarity_percent=100.0)
    high_similarity = attempt(attempt_id="b" * 16, match_exact=False, match_similarity_percent=90.0)
    low_similarity = attempt(attempt_id="c" * 16, match_exact=False, match_similarity_percent=50.0)
    fewer_diffs = attempt(attempt_id="d" * 16, match_exact=False, match_similarity_percent=90.0, changed_rows=1)
    more_diffs = attempt(attempt_id="e" * 16, match_exact=False, match_similarity_percent=90.0, changed_rows=5)
    tie_a = attempt(attempt_id="f" * 16, match_exact=False, match_similarity_percent=90.0, changed_rows=1)
    tie_b = attempt(attempt_id="g" * 16, match_exact=False, match_similarity_percent=90.0, changed_rows=1)

    assert select_best_attempt([high_similarity, exact, low_similarity]) is exact
    assert select_best_attempt([low_similarity, high_similarity]) is high_similarity
    assert select_best_attempt([more_diffs, fewer_diffs]) is fewer_diffs
    assert select_best_attempt([tie_b, tie_a]).attempt_id == "f" * 16
    assert select_best_attempt([]) is None


def test_run_function_resume_skips_identical_attempt(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    differ = _fake_asm_differ(tmp_path, _PARTIAL_PAYLOAD)
    objdump = _fake_objdump(tmp_path)

    first = run_function(
        _queued(project), m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )
    second = run_function(
        _queued(project, state=first), m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )

    assert first.attempts == second.attempts == 1
    assert [a.attempt_id for a in second.attempt_history] == [a.attempt_id for a in first.attempt_history]


def test_changed_assembly_produces_new_attempt_and_preserves_history(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    differ = _fake_asm_differ(tmp_path, _PARTIAL_PAYLOAD)
    objdump = _fake_objdump(tmp_path)

    first = run_function(
        _queued(project), m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )
    assert first.attempts == 1

    functions_path = project / "metadata" / "functions.json"
    payload = json.loads(functions_path.read_text(encoding="utf-8"))
    payload[0]["assembly"] = payload[0]["assembly"] + "    nop\n"
    functions_path.write_text(json.dumps(payload), encoding="utf-8")

    second = run_function(
        _queued(project, state=first), m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )

    assert second.attempts == 2
    assert second.attempt_history[0].attempt_id == first.attempt_history[0].attempt_id
    assert second.attempt_history[1].attempt_id != first.attempt_history[0].attempt_id


def test_run_function_raises_for_unsupported_function(tmp_path):
    project = _write_unsupported_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))

    with pytest.raises(UnsupportedFunctionError):
        run_function(_queued(project, function="func_empty", size=0), m2c_path=m2c, toolchain=toolchain)


def test_run_and_persist_marks_unsupported_and_saves_state(tmp_path):
    workspace = tmp_path / "workspace"
    project = _write_unsupported_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    queued = _queued(project, function="func_empty", size=0)

    state = run_and_persist(workspace, queued, m2c_path=m2c, toolchain=toolchain)

    assert state.status == DecompilationStatus.UNSUPPORTED.value
    loaded = load_function_state(workspace, queued.module, queued.function)
    assert loaded is not None
    assert loaded.status == DecompilationStatus.UNSUPPORTED.value


def test_run_function_blocked_when_m2c_unavailable(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))

    state = run_function(_queued(project), m2c_path=tmp_path / "does-not-exist.py", toolchain=toolchain)

    assert state.status == DecompilationStatus.BLOCKED.value
    assert state.last_failure
    assert state.attempts == 0


def test_run_function_blocked_when_toolchain_unavailable_mid_run(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")

    state = run_function(_queued(project), m2c_path=m2c, toolchain=_AlwaysUnavailableToolchain())

    assert state.status == DecompilationStatus.BLOCKED.value
    assert state.attempts == 0


def test_run_function_bounds_attempts_by_max_attempts(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    differ = _fake_asm_differ(tmp_path, _PARTIAL_PAYLOAD)
    objdump = _fake_objdump(tmp_path)
    context = tmp_path / "ctx.i"
    context.write_text("typedef unsigned int u32;\n", encoding="utf-8")

    state = run_function(
        _queued(project),
        m2c_path=m2c,
        toolchain=toolchain,
        asm_differ_path=differ,
        objdump_path=objdump,
        contexts=[context],
        max_attempts=1,
    )

    assert state.attempts == 1


def test_worse_attempt_never_replaces_better_attempt(tmp_path):
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    objdump = _fake_objdump(tmp_path)
    good_differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD, name="good_diff.py")

    first = run_function(
        _queued(project), m2c_path=m2c, toolchain=toolchain, asm_differ_path=good_differ, objdump_path=objdump
    )
    assert first.status == DecompilationStatus.MATCHED_EXACT.value
    assert first.attempts == 1

    bad_differ = _fake_asm_differ(tmp_path, _PARTIAL_PAYLOAD, name="bad_diff.py")
    context = tmp_path / "ctx.i"
    context.write_text("typedef unsigned int u32;\n", encoding="utf-8")

    second = run_function(
        _queued(project, state=first),
        m2c_path=m2c,
        toolchain=toolchain,
        asm_differ_path=bad_differ,
        objdump_path=objdump,
        contexts=[context],
    )

    assert second.status == DecompilationStatus.MATCHED_EXACT.value
    assert second.best_match_percent == 100.0
    assert second.best_attempt_id == first.best_attempt_id
    assert second.attempts == 2


def test_run_and_persist_saves_successful_state(tmp_path):
    workspace = tmp_path / "workspace"
    project = _write_orchestrator_project(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    toolchain = ExternalCompilerToolchain(_fake_compiler(tmp_path))
    differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD)
    objdump = _fake_objdump(tmp_path)
    queued = _queued(project)

    state = run_and_persist(
        workspace, queued, m2c_path=m2c, toolchain=toolchain, asm_differ_path=differ, objdump_path=objdump
    )

    loaded = load_function_state(workspace, queued.module, queued.function)
    assert loaded is not None
    assert loaded.status == DecompilationStatus.MATCHED_EXACT.value
    assert loaded.attempt_history[0].attempt_id == state.best_attempt_id
