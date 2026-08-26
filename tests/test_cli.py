import json

from pspdisasm.cli import main
from tests.fixtures import build_prx_elf32


def test_cli_analyze_emits_json_to_stdout(tmp_path, capsys):
    target = tmp_path / "sample.prx"
    target.write_bytes(build_prx_elf32())
    code = main(["analyze", str(target), "--json", "-"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["executable_kind"] == "prx"
    assert payload["module_info"]["name"] == "TESTPRX"
    assert payload["imports"][0]["functions"][0]["nid"] == 0xAAAA0001


def test_cli_analyze_writes_json_file(tmp_path):
    target = tmp_path / "sample.prx"
    output = tmp_path / "analysis.json"
    target.write_bytes(build_prx_elf32())
    code = main(["analyze", str(target), "--json", str(output)])
    assert code == 0
    payload = json.loads(output.read_text())
    assert payload["source_name"].endswith("sample.prx")


def test_cli_disasm_emits_json_and_assembly_files(tmp_path, capsys):
    from tests.fixtures import build_allegrex_elf32

    target = tmp_path / "sample.elf"
    asm_dir = tmp_path / "asm"
    target.write_bytes(build_allegrex_elf32())

    code = main(["disasm", str(target), "--json", "-", "--asm-dir", str(asm_dir)])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["functions"][0]["address"] == 0x08800000
    assert payload["engines"][0]["name"] == "spimdisasm"
    asm_file = asm_dir / "text.s"
    assert asm_file.exists()
    assembly = asm_file.read_text()
    assert "clz" in assembly
    assert "vzero.s" in assembly


def test_cli_disasm_rejects_encrypted_psp_container(tmp_path, capsys):
    from tests.fixtures import build_psp_container_header

    target = tmp_path / "EBOOT.BIN"
    target.write_bytes(build_psp_container_header())

    code = main(["disasm", str(target)])

    assert code == 2
    assert "decryption" in capsys.readouterr().err.lower()


def test_cli_project_generates_splat_workspace(tmp_path):
    from tests.fixtures import build_allegrex_elf32

    target = tmp_path / "sample.elf"
    output = tmp_path / "project"
    target.write_bytes(build_allegrex_elf32())

    code = main(["project", str(target), str(output)])

    assert code == 0
    assert (output / "splat.yaml").exists()
    assert (output / "config" / "symbols.txt").exists()


def test_cli_decompile_generates_assisted_c(tmp_path, capsys):
    import json as _json

    project = tmp_path / "project"
    (project / "metadata").mkdir(parents=True)
    (project / "metadata" / "functions.json").write_text(
        _json.dumps([
            {
                "name": "func_08800028",
                "address": 0x08800028,
                "size": 12,
                "section": ".text",
                "assembly": "glabel func_08800028\n    addiu $v0, $zero, 1\n    jr $ra\n     nop\nendlabel func_08800028\n",
                "instruction_count": 3,
                "instructions": [],
            }
        ]),
        encoding="utf-8",
    )
    backend = tmp_path / "m2c.py"
    backend.write_text("print('s32 func_08800028(void) { return 1; }')\n", encoding="utf-8")

    code = main(["decompile", str(project), "func_08800028", "--m2c", str(backend)])

    assert code == 0
    output = capsys.readouterr().out
    assert "func_08800028" in output
    assert "src/nonmatching/func_08800028.c" in output
    assert (project / "src" / "nonmatching" / "func_08800028.c").exists()


def test_cli_decompile_reports_missing_backend(tmp_path, capsys):
    import json as _json

    project = tmp_path / "project"
    (project / "metadata").mkdir(parents=True)
    (project / "metadata" / "functions.json").write_text(
        _json.dumps([
            {
                "name": "func_08800028",
                "address": 0x08800028,
                "size": 12,
                "section": ".text",
                "assembly": "glabel func_08800028\n    jr $ra\n     nop\nendlabel func_08800028\n",
                "instruction_count": 2,
                "instructions": [],
            }
        ]),
        encoding="utf-8",
    )

    code = main(["decompile", str(project), "func_08800028", "--m2c", str(tmp_path / "missing.py")])

    assert code == 2
    assert "m2c" in capsys.readouterr().err.lower()
