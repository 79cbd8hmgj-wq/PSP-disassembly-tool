from __future__ import annotations

import json
from pathlib import Path

import pytest

from pspdisasm.decompiler import (
    decompile_project_function,
    resolve_m2c_command,
    resolve_project_function,
)
from pspdisasm.errors import DecompilationError, DecompilerUnavailableError
from pspdisasm.project import generate_project
from tests.fixtures import build_allegrex_elf32


def _write_project_functions(project: Path) -> None:
    (project / "metadata").mkdir(parents=True)
    payload = [
        {
            "name": "func_08800000",
            "address": 0x08800000,
            "size": 8,
            "section": ".text",
            "assembly": "glabel func_08800000\n    jr $ra\n     nop\nendlabel func_08800000\n",
            "instruction_count": 2,
            "instructions": [],
        },
        {
            "name": "func_08800028",
            "address": 0x08800028,
            "size": 12,
            "section": ".text",
            "assembly": "glabel func_08800028\n    addiu $v0, $zero, 1\n    jr $ra\n     nop\nendlabel func_08800028\n",
            "instruction_count": 3,
            "instructions": [],
        },
    ]
    (project / "metadata" / "functions.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_fake_m2c(path: Path, *, output: str = "s32 func_08800028(void) { return 1; }\n", exit_code: int = 0) -> Path:
    path.write_text(
        "from __future__ import annotations\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "required = ['-t', 'mipsel-gcc-c', '--valid-syntax', '--deterministic-vars', '--no-cache', '--globals=used']\n"
        "for item in required:\n"
        "    if item not in args:\n"
        "        print('missing ' + item, file=sys.stderr)\n"
        "        raise SystemExit(9)\n"
        f"sys.stdout.write({output!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return path


def test_resolve_project_function_by_name_and_address(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project_functions(project)

    by_name = resolve_project_function(project, "func_08800028")
    by_hex = resolve_project_function(project, "0x08800028")
    by_decimal = resolve_project_function(project, str(0x08800028))

    assert by_name.name == "func_08800028"
    assert by_hex.address == 0x08800028
    assert by_decimal.name == "func_08800028"


def test_resolve_project_function_rejects_missing_and_malformed_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    with pytest.raises(DecompilationError, match="functions.json"):
        resolve_project_function(project, "func_08800028")

    (project / "metadata").mkdir(parents=True)
    (project / "metadata" / "functions.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DecompilationError, match="list"):
        resolve_project_function(project, "func_08800028")


def test_resolve_project_function_rejects_unknown_selector(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project_functions(project)
    with pytest.raises(DecompilationError, match="not found"):
        resolve_project_function(project, "func_DEADBEEF")


def test_resolve_m2c_command_explicit_python_and_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    script = _write_fake_m2c(tmp_path / "m2c.py")
    explicit = resolve_m2c_command(script)
    assert explicit[-1] == str(script)
    assert Path(explicit[0]).name.startswith("python")

    monkeypatch.setenv("PSPDISASM_M2C", str(script))
    env_command = resolve_m2c_command(None)
    assert env_command[-1] == str(script)


def test_resolve_m2c_command_reports_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PSPDISASM_M2C", raising=False)
    monkeypatch.setenv("PATH", "")
    with pytest.raises(DecompilerUnavailableError, match="m2c"):
        resolve_m2c_command(None)


def test_decompile_materializes_c_assembly_and_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project_functions(project)
    backend = _write_fake_m2c(tmp_path / "m2c.py")

    result = decompile_project_function(project, "func_08800028", m2c_path=backend)

    assert result.function_name == "func_08800028"
    assert result.function_address == 0x08800028
    assert result.output_path == project / "src" / "nonmatching" / "func_08800028.c"
    assert "return 1" in result.output_path.read_text()
    assert (project / "asm" / "nonmatchings" / "func_08800028.s").read_text().startswith("glabel func_08800028")
    metadata = json.loads((project / "metadata" / "decompilations" / "func_08800028.json").read_text())
    assert metadata["target"] == "mipsel-gcc-c"
    assert metadata["function"]["address"] == 0x08800028
    assert metadata["artifacts"]["c"] == "src/nonmatching/func_08800028.c"
    assert metadata["artifacts"]["assembly"] == "asm/nonmatchings/func_08800028.s"


def test_decompile_surfaces_unknown_psp_instruction_markers(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project_functions(project)
    output = "void func_08800000(void) {\n    M2C_ERROR(/* unknown instruction: vzero.s S000 */);\n}\n"
    backend = _write_fake_m2c(tmp_path / "m2c.py", output=output)

    result = decompile_project_function(project, "func_08800000", m2c_path=backend)

    assert result.unsupported_instructions == ["vzero.s S000"]
    assert any("unsupported" in warning.lower() for warning in result.warnings)
    assert "M2C_ERROR" in result.output_path.read_text()


def test_failed_m2c_run_does_not_replace_existing_output(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project_functions(project)
    output = project / "src" / "nonmatching" / "func_08800028.c"
    output.parent.mkdir(parents=True)
    output.write_text("previous good output\n", encoding="utf-8")
    backend = _write_fake_m2c(tmp_path / "bad_m2c.py", output="partial bad output\n", exit_code=3)

    with pytest.raises(DecompilationError, match="exit code 3"):
        decompile_project_function(project, "func_08800028", m2c_path=backend)

    assert output.read_text() == "previous good output\n"


def test_decompile_passes_context_files(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project_functions(project)
    context = tmp_path / "ctx.i"
    context.write_text("typedef unsigned int u32;\n", encoding="utf-8")
    backend = tmp_path / "m2c.py"
    backend.write_text(
        "import sys\n"
        "args=sys.argv[1:]\n"
        f"assert args.count('--context') == 1 and {str(context)!r} in args\n"
        "print('s32 func_08800028(void) { return 1; }')\n",
        encoding="utf-8",
    )

    result = decompile_project_function(project, "func_08800028", m2c_path=backend, contexts=[context])
    assert result.output_path.exists()


def test_supplied_m2c_decompiles_generic_psp_fixture_function(tmp_path: Path) -> None:
    supplied = Path("/mnt/data/psp_tool_sources/m2c-master/m2c-master/m2c.py")
    if not supplied.exists():
        pytest.skip("supplied m2c source is not available")

    source = tmp_path / "sample.elf"
    project = tmp_path / "project"
    source.write_bytes(build_allegrex_elf32())
    generate_project(source, project)

    result = decompile_project_function(project, "func_08800028", m2c_path=supplied)

    assert "return 1;" in result.output_path.read_text()
    assert result.unsupported_instructions == []
