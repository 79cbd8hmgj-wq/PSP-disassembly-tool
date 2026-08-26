from __future__ import annotations

from pspdisasm.linker import ModuleAnalysisInput, link_modules
from pspdisasm.model import ExecutableModel, LibraryExport, LibraryImport, ModuleInfo, NidEntry


def _module(name: str, source_name: str, *, imports=None, exports=None) -> ExecutableModel:
    return ExecutableModel(
        source_name=source_name,
        input_kind="elf",
        executable_kind="prx",
        needs_decryption=False,
        module_info=ModuleInfo(
            attributes=0,
            version=(1, 0),
            name=name,
            gp_value=0,
            exports_start=0,
            exports_end=0,
            imports_start=0,
            imports_end=0,
            address=0,
            location="test",
        ),
        imports=imports or [],
        exports=exports or [],
    )


def _import(library: str, nid: int, address: int) -> LibraryImport:
    entry = NidEntry(nid=nid, address=address, kind="function", nid_address=address - 4)
    return LibraryImport(
        name=library,
        flags=0,
        entry_length=5,
        function_count=1,
        variable_count=0,
        address=address - 0x20,
        functions=[entry],
    )


def _export(library: str, nid: int, address: int) -> LibraryExport:
    entry = NidEntry(nid=nid, address=address, kind="function", nid_address=address - 4)
    return LibraryExport(
        name=library,
        flags=0,
        entry_length=4,
        function_count=1,
        variable_count=0,
        address=address - 0x20,
        functions=[entry],
    )


def test_duplicate_sce_module_names_are_disambiguated_and_still_link() -> None:
    nid = 0x13572468
    importer = _module(
        "SharedName",
        "/game/importer.prx",
        imports=[_import("SharedLib", nid, 0x08801000)],
    )
    exporter = _module(
        "SharedName",
        "/game/exporter.prx",
        exports=[_export("SharedLib", nid, 0x08902000)],
    )

    result = link_modules([
        ModuleAnalysisInput(importer),
        ModuleAnalysisInput(exporter),
    ])

    assert result.modules == ["SharedName@importer.prx", "SharedName@exporter.prx"]
    assert len(result.links) == 1
    assert result.links[0].importing_module == "SharedName@importer.prx"
    assert result.links[0].exporting_module == "SharedName@exporter.prx"
    assert any("duplicate module name" in warning.lower() for warning in result.warnings)
