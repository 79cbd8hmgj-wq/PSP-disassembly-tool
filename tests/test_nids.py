from __future__ import annotations

import json

import pytest


def test_json_nid_database_resolves_exact_library_kind_and_nid(tmp_path) -> None:
    from pspdisasm.nids import load_nid_databases

    path = tmp_path / "nids.json"
    path.write_text(
        json.dumps(
            [
                {
                    "library": "sceDisplay",
                    "kind": "function",
                    "nid": "0x289D82FE",
                    "name": "sceDisplaySetFrameBuf",
                    "source": "pspsdk",
                },
                {
                    "library": "sceDisplay",
                    "kind": "variable",
                    "nid": "12345678",
                    "name": "sceDisplayGlobal",
                    "source": "synthetic",
                },
            ]
        ),
        encoding="utf-8",
    )

    database = load_nid_databases([path])

    function = database.resolve("sceDisplay", 0x289D82FE, "fun")
    assert function is not None
    assert function.name == "sceDisplaySetFrameBuf"
    assert function.kind == "function"
    assert function.source == "pspsdk"

    variable = database.resolve("sceDisplay", 0x12345678, "variable")
    assert variable is not None
    assert variable.name == "sceDisplayGlobal"

    assert database.resolve("SceDisplay", 0x289D82FE, "function") is None
    assert database.resolve("sceDisplay", 0x289D82FE, "variable") is None


def test_psplibdoc_style_csv_parses_kind_aliases_hex_and_provenance(tmp_path) -> None:
    from pspdisasm.nids import load_nid_databases

    path = tmp_path / "display.csv"
    path.write_text(
        "library,fun/var,NID,name,source\n"
        "sceDisplay,fun,289D82FE,sceDisplaySetFrameBuf,matching\n"
        "sceDisplay,var,0x12345678,sceDisplayGlobal,manual\n",
        encoding="utf-8",
    )

    database = load_nid_databases([path])

    assert database.resolve("sceDisplay", 0x289D82FE, "function").name == "sceDisplaySetFrameBuf"
    assert database.resolve("sceDisplay", 0x12345678, "var").source == "manual"


def test_later_database_wins_and_records_conflicting_strong_names(tmp_path) -> None:
    from pspdisasm.nids import load_nid_databases

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(
        json.dumps([
            {
                "library": "TestLib",
                "kind": "function",
                "nid": "AABBCCDD",
                "name": "FirstName",
                "source": "first",
            }
        ]),
        encoding="utf-8",
    )
    second.write_text(
        json.dumps([
            {
                "library": "TestLib",
                "kind": "function",
                "nid": "0xAABBCCDD",
                "name": "SecondName",
                "source": "second",
            }
        ]),
        encoding="utf-8",
    )

    database = load_nid_databases([first, second])

    resolved = database.resolve("TestLib", 0xAABBCCDD, "function")
    assert resolved.name == "SecondName"
    assert resolved.source == "second"
    assert len(database.warnings) == 1
    assert "FirstName" in database.warnings[0]
    assert "SecondName" in database.warnings[0]


def test_placeholder_names_are_not_strong() -> None:
    from pspdisasm.nids import is_placeholder_name

    assert is_placeholder_name("LoadCoreForKernel", 0x4440853B, "LoadCoreForKernel_4440853B")
    assert not is_placeholder_name("LoadCoreForKernel", 0x4440853B, "sceKernelFindModuleByName")


def test_invalid_kind_is_rejected(tmp_path) -> None:
    from pspdisasm.nids import load_nid_databases

    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps([
            {
                "library": "TestLib",
                "kind": "mystery",
                "nid": "00000001",
                "name": "Mystery",
                "source": "test",
            }
        ]),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="kind"):
        load_nid_databases([path])


def test_package_exports_phase6b_api_and_version() -> None:
    import pspdisasm
    from pspdisasm.linker import link_modules
    from pspdisasm.nids import load_nid_databases

    assert pspdisasm.load_nid_databases is load_nid_databases
    assert pspdisasm.link_modules is link_modules
    assert pspdisasm.__version__ == "0.8.0"
