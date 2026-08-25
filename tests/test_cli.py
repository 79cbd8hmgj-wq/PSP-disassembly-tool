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
