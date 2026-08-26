import json
from pathlib import Path

import yaml

from pspdisasm.project import build_project_artifacts, generate_project
from tests.fixtures import build_allegrex_elf32, build_psp_container_header


def test_project_artifacts_flatten_alloc_sections_and_render_psp_splat():
    artifacts = build_project_artifacts(build_allegrex_elf32(), "sample.elf")

    assert artifacts.base_vram == 0x08800000
    assert artifacts.target[:4] == bytes.fromhex("16108000")
    assert artifacts.target[0x100:0x10B] == b"Hello PSP!\x00"

    config = yaml.safe_load(artifacts.splat_yaml)
    assert config["options"]["platform"] == "psp"
    assert config["options"]["endianness"] == "little"
    assert config["options"]["compiler"] == "GCC"
    assert config["options"]["target_path"] == "target.bin"
    code = config["segments"][0]
    assert code["type"] == "code"
    assert code["start"] == 0
    assert code["vram"] == 0x08800000
    assert [0, "asm", "main/000000"] in code["subsegments"]
    assert [0x34, "bin", "padding/000034"] in code["subsegments"]
    assert [0x100, "rodata", "main/000100"] in code["subsegments"]

    assert "_start = 0x08800000; // type:func" in artifacts.symbols
    assert "func_08800028 = 0x08800028; // type:func" in artifacts.symbols
    assert "STR_08800100 = 0x08800100; // type:asciz" in artifacts.symbols


def test_generate_project_materializes_workspace(tmp_path: Path):
    source = tmp_path / "sample.elf"
    output = tmp_path / "game_decomp"
    source.write_bytes(build_allegrex_elf32())

    result = generate_project(source, output)

    assert result.output_dir == output
    expected = {
        "splat.yaml",
        "target.bin",
        "config/symbols.txt",
        "config/undefined_funcs_auto.txt",
        "config/undefined_syms_auto.txt",
        "metadata/executable.json",
        "metadata/disassembly.json",
        "metadata/functions.json",
        "metadata/symbols.json",
        "metadata/references.json",
        "metadata/strings.json",
        "metadata/advanced.json",
        "metadata/callgraph.json",
        "metadata/jump_tables.json",
        "metadata/function_confidence.json",
        "asm/text.s",
    }
    for relative in expected:
        assert (output / relative).exists(), relative
    assert (output / "src").is_dir()
    assert (output / "build").is_dir()
    assert (output / "reports").is_dir()

    callgraph = json.loads((output / "metadata" / "callgraph.json").read_text(encoding="utf-8"))
    assert callgraph == [
        {
            "kind": "direct",
            "source_address": 0x08800004,
            "source_function": "func_08800000",
            "target_address": 0x08800028,
            "target_function": "func_08800028",
        }
    ]

    confidence = json.loads((output / "metadata" / "function_confidence.json").read_text(encoding="utf-8"))
    assert [entry["address"] for entry in confidence] == [0x08800000, 0x08800028]
    assert confidence[0]["score"] == 0.85
    assert confidence[1]["score"] == 0.70

    jump_tables = json.loads((output / "metadata" / "jump_tables.json").read_text(encoding="utf-8"))
    assert jump_tables == []

    advanced = json.loads((output / "metadata" / "advanced.json").read_text(encoding="utf-8"))
    assert advanced["call_edges"] == callgraph
    assert advanced["function_confidence"] == confidence
    assert advanced["jump_tables"] == jump_tables


def test_project_rejects_encrypted_psp_container():
    try:
        build_project_artifacts(build_psp_container_header(), "EBOOT.BIN")
    except Exception as exc:
        assert "decrypted" in str(exc).lower()
    else:
        raise AssertionError("expected encrypted container rejection")
