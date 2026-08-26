from __future__ import annotations

import json
import struct

from pspdisasm.cli import main
from tests.fixtures import build_prx_elf32


def _write_nid_db(path) -> None:
    path.write_text(
        json.dumps(
            [
                {
                    "library": "TestEx",
                    "kind": "function",
                    "nid": "11111111",
                    "name": "TestExportFunction",
                    "source": "cli-test",
                },
                {
                    "library": "TestIm",
                    "kind": "function",
                    "nid": "AAAA0001",
                    "name": "TestImportOne",
                    "source": "cli-test",
                },
            ]
        ),
        encoding="utf-8",
    )


def _link_fixture(module_name: str, *, import_testex: bool) -> bytes:
    blob = bytearray(build_prx_elf32())
    encoded = module_name.encode("ascii")[:27]
    blob[0x124:0x140] = encoded + b"\0" * (0x1C - len(encoded))
    if import_testex:
        blob[0x1C0:0x1C7] = b"TestEx\0"
        struct.pack_into("<I", blob, 0x1D0, 0x11111111)
    return bytes(blob)


def test_cli_project_accepts_repeatable_nid_database(tmp_path) -> None:
    target = tmp_path / "sample.prx"
    database = tmp_path / "nids.json"
    output = tmp_path / "project"
    target.write_bytes(build_prx_elf32())
    _write_nid_db(database)

    code = main([
        "project",
        str(target),
        str(output),
        "--nid-db",
        str(database),
    ])

    assert code == 0
    resolutions = json.loads((output / "metadata" / "nids.json").read_text(encoding="utf-8"))
    assert any(item["name"] == "TestExportFunction" for item in resolutions)
    assert "TestExportFunction = 0x00000010; // type:func" in (
        output / "config" / "symbols.txt"
    ).read_text(encoding="utf-8")


def test_cli_link_emits_cross_module_json(tmp_path, capsys) -> None:
    importer = tmp_path / "importer.prx"
    exporter = tmp_path / "exporter.prx"
    database = tmp_path / "nids.json"
    importer.write_bytes(_link_fixture("IMPORTER", import_testex=True))
    exporter.write_bytes(_link_fixture("EXPORTER", import_testex=False))
    _write_nid_db(database)

    code = main([
        "link",
        str(importer),
        str(exporter),
        "--nid-db",
        str(database),
        "--json",
        "-",
    ])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["modules"] == ["IMPORTER", "EXPORTER"]
    assert len(payload["links"]) == 1
    link = payload["links"][0]
    assert link["importing_module"] == "IMPORTER"
    assert link["exporting_module"] == "EXPORTER"
    assert link["library"] == "TestEx"
    assert link["nid"] == 0x11111111
    assert link["name"] == "TestExportFunction"
