from __future__ import annotations

import json
from pathlib import Path

from pspdisasm.cli import main
from pspdisasm.decompile.queue import DecompilationStatus
from pspdisasm.decompile.workspace import load_function_state


def _write_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    metadata_dir = workspace / "analysis" / "game_project" / "metadata"
    metadata_dir.mkdir(parents=True)
    metadata_dir.joinpath("game_analysis.json").write_text(
        json.dumps(
            {
                "modules": [
                    {
                        "path": "PSP_GAME/SYSDIR/EBOOT.BIN",
                        "status": "analyzed",
                        "project_path": "projects/PSP_GAME/SYSDIR/EBOOT.BIN",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    project_metadata = workspace / "analysis" / "game_project" / "projects" / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN" / "metadata"
    project_metadata.mkdir(parents=True)
    project_metadata.joinpath("functions.json").write_text(
        json.dumps(
            [
                {
                    "name": "func_08800000",
                    "address": 0x08800000,
                    "size": 12,
                    "section": ".text",
                    "assembly": "glabel func_08800000\n    addiu $v0, $zero, 1\n    jr $ra\n    nop\nendlabel func_08800000\n",
                    "instruction_count": 3,
                    "instructions": [
                        {"address": 0x08800000, "word": 0x24020001, "text": "addiu $v0, $zero, 1", "valid": True, "implemented": True},
                        {"address": 0x08800004, "word": 0x03E00008, "text": "jr $ra", "valid": True, "implemented": True},
                        {"address": 0x08800008, "word": 0x00000000, "text": "nop", "valid": True, "implemented": True},
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    project_metadata.joinpath("references.json").write_text("[]", encoding="utf-8")
    return workspace


def _project_dir(workspace: Path) -> Path:
    return workspace / "analysis" / "game_project" / "projects" / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN"


def _write_fake_m2c(path: Path) -> Path:
    path.write_text(
        "from __future__ import annotations\n"
        "import sys\n"
        "sys.stdout.write('s32 func_08800000(void) { return 1; }\\n')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    return path


def _fake_compiler(tmp_path: Path) -> Path:
    path = tmp_path / "fake-cc"
    path.write_text(
        "#!/bin/sh\n"
        "out=\"\"\n"
        "prev=\"\"\n"
        "for arg in \"$@\"; do\n"
        "  if [ \"$prev\" = \"-o\" ]; then out=\"$arg\"; fi\n"
        "  prev=\"$arg\"\n"
        "done\n"
        "if [ -n \"$out\" ]; then printf 'OBJECT' > \"$out\"; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _fake_objdump(tmp_path: Path) -> Path:
    path = tmp_path / "objdump"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_asm_differ(tmp_path: Path, payload: dict) -> Path:
    script = tmp_path / "diff.py"
    script.write_text(
        "import json\nprint(json.dumps(" + repr(payload) + "))\n",
        encoding="utf-8",
    )
    return script


_EXACT_PAYLOAD = {
    "current_score": 0,
    "max_score": 100,
    "rows": [{"key": "a", "is_data_ref": False, "base": {"text": [{"text": "a"}]}, "current": {"text": [{"text": "a"}]}}],
}


def test_cli_decompile_workspace_reaches_exact_match_with_external_compiler(tmp_path, capsys):
    workspace = _write_workspace(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    compiler = _fake_compiler(tmp_path)
    differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD)
    objdump = _fake_objdump(tmp_path)

    code = main(
        [
            "decompile-workspace",
            str(workspace),
            "--m2c",
            str(m2c),
            "--compiler",
            str(compiler),
            "--asm-differ",
            str(differ),
            "--objdump",
            str(objdump),
        ]
    )

    assert code == 0
    stdout = capsys.readouterr().out
    assert "func_08800000" in stdout
    assert "matched_exact" in stdout
    assert "Report:" in stdout

    state = load_function_state(workspace, "PSP_GAME/SYSDIR/EBOOT.BIN", "func_08800000")
    assert state is not None
    assert state.status == DecompilationStatus.MATCHED_EXACT.value
    assert state.best_match_percent == 100.0

    report = workspace / "decompilation" / "reports" / "match_status.csv"
    assert report.is_file()
    assert "func_08800000" in report.read_text(encoding="utf-8")


def test_cli_decompile_workspace_with_project_build_command_toolchain(tmp_path):
    workspace = _write_workspace(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD)
    objdump = _fake_objdump(tmp_path)
    project = _project_dir(workspace)
    build_script = project / "build.sh"
    build_script.write_text(
        "#!/bin/sh\nmkdir -p build\nprintf 'OBJECT' > \"build/$1.o\"\n", encoding="utf-8"
    )
    build_script.chmod(0o755)

    code = main(
        [
            "decompile-workspace",
            str(workspace),
            "--m2c",
            str(m2c),
            "--toolchain-command",
            f"{build_script} {{function}}",
            "--toolchain-output",
            "build/{function}.o",
            "--asm-differ",
            str(differ),
            "--objdump",
            str(objdump),
        ]
    )

    assert code == 0
    state = load_function_state(workspace, "PSP_GAME/SYSDIR/EBOOT.BIN", "func_08800000")
    assert state is not None
    assert state.status == DecompilationStatus.MATCHED_EXACT.value


def test_cli_decompile_workspace_rejects_toolchain_output_without_command(tmp_path, capsys):
    workspace = _write_workspace(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")

    code = main(
        [
            "decompile-workspace",
            str(workspace),
            "--m2c",
            str(m2c),
            "--toolchain-output",
            "build/{function}.o",
        ]
    )

    assert code == 2
    assert "--toolchain-command" in capsys.readouterr().err


def test_cli_decompile_workspace_json_output(tmp_path):
    workspace = _write_workspace(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    compiler = _fake_compiler(tmp_path)
    differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD)
    objdump = _fake_objdump(tmp_path)
    json_path = tmp_path / "result.json"

    code = main(
        [
            "decompile-workspace",
            str(workspace),
            "--m2c",
            str(m2c),
            "--compiler",
            str(compiler),
            "--asm-differ",
            str(differ),
            "--objdump",
            str(objdump),
            "--json",
            str(json_path),
        ]
    )

    assert code == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["function"] == "func_08800000"
    assert payload[0]["status"] == DecompilationStatus.MATCHED_EXACT.value


def test_cli_match_status_reports_counts_and_writes_report(tmp_path, capsys):
    workspace = _write_workspace(tmp_path)
    m2c = _write_fake_m2c(tmp_path / "m2c.py")
    compiler = _fake_compiler(tmp_path)
    differ = _fake_asm_differ(tmp_path, _EXACT_PAYLOAD)
    objdump = _fake_objdump(tmp_path)
    main(
        [
            "decompile-workspace",
            str(workspace),
            "--m2c",
            str(m2c),
            "--compiler",
            str(compiler),
            "--asm-differ",
            str(differ),
            "--objdump",
            str(objdump),
        ]
    )
    capsys.readouterr()

    code = main(["match-status", str(workspace)])

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Functions: 1" in stdout
    assert "matched_exact: 1" in stdout


def test_cli_match_status_json_output(tmp_path):
    workspace = _write_workspace(tmp_path)
    json_path = tmp_path / "status.json"

    code = main(["match-status", str(workspace), "--json", str(json_path)])

    assert code == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["total"] == 1
    assert payload["counts"] == {DecompilationStatus.PENDING.value: 1}
    assert payload["functions"][0]["function"] == "func_08800000"
