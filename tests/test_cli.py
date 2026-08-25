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
