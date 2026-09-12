from __future__ import annotations

import json

from pspdisasm.model import RuntimeAddress, RuntimeModule
from pspdisasm.runtime.modules import (
    HleModuleListSource,
    RuntimeModuleResolution,
    UserProvidedModuleSource,
    build_runtime_module_map,
    load_static_placements,
)
from pspdisasm.runtime.transport import PpssppDebuggerTransport
from tests.fake_ppsspp_server import FakeConnection, FakePpssppServer


def _connect(port: int) -> PpssppDebuggerTransport:
    return PpssppDebuggerTransport("127.0.0.1", port)


def test_hle_module_list_source_parses_supported_response():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_ok(
            request,
            modules=[
                {"name": "EBOOT.BIN", "address": 0x08800000, "size": 0x10000},
                {"name": "LOCKED.PRX", "address": 0x09A00000},
                "not-a-dict",
                {"address": "not-an-int"},
            ],
        )

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            modules = HleModuleListSource().discover(transport)
        finally:
            transport.close()
    finally:
        server.join()

    assert [m.name for m in modules] == ["EBOOT.BIN", "LOCKED.PRX"]
    assert modules[0].runtime_base.value == 0x08800000
    assert modules[0].runtime_size == 0x10000
    assert modules[1].runtime_size is None
    assert all(m.resolution_status == RuntimeModuleResolution.HLE_REPORTED.value for m in modules)


def test_hle_module_list_source_falls_through_when_unsupported():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_error(request, "unknown event hle.module.list")

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            modules = HleModuleListSource().discover(transport)
        finally:
            transport.close()
    finally:
        server.join()

    assert modules == []


def test_user_provided_module_source_sizes_from_static_placements():
    source = UserProvidedModuleSource(
        {"PSP_GAME/USRDIR/LOCKED.PRX": 0x09A00000},
        static_placements={"PSP_GAME/USRDIR/LOCKED.PRX": {"image_size": 0x2000}},
    )
    modules = source.discover(transport=None)  # type: ignore[arg-type]

    assert len(modules) == 1
    module = modules[0]
    assert module.static_module_path == "PSP_GAME/USRDIR/LOCKED.PRX"
    assert module.runtime_base.value == 0x09A00000
    assert module.runtime_size == 0x2000
    assert module.resolution_status == RuntimeModuleResolution.USER_PROVIDED.value
    assert any("not toolkit-proven" in note for note in module.evidence)


def test_user_provided_module_source_without_static_placement_is_unsized():
    source = UserProvidedModuleSource({"UNKNOWN.PRX": 0x09B00000})
    modules = source.discover(transport=None)  # type: ignore[arg-type]
    assert modules[0].runtime_size is None


def test_build_runtime_module_map_uses_first_non_empty_tier():
    class EmptySource:
        name = "empty"

        def discover(self, transport):
            return []

    fallback = UserProvidedModuleSource({"A.PRX": 0x08800000})
    modules = build_runtime_module_map(transport=None, sources=[EmptySource(), fallback])  # type: ignore[arg-type]

    assert len(modules) == 1
    assert modules[0].static_module_path == "A.PRX"


def test_build_runtime_module_map_never_merges_tiers():
    class NonEmptySource:
        name = "first"

        def discover(self, transport):
            return [
                RuntimeModule(
                    name="first-tier",
                    runtime_base=RuntimeAddress(domain="runtime", value=1),
                    runtime_size=None,
                    static_module_path=None,
                    resolution_status="hle_reported",
                )
            ]

    fallback = UserProvidedModuleSource({"SHOULD_NOT_APPEAR.PRX": 0x08800000})
    modules = build_runtime_module_map(transport=None, sources=[NonEmptySource(), fallback])  # type: ignore[arg-type]

    assert [m.name for m in modules] == ["first-tier"]


def test_build_runtime_module_map_returns_empty_when_no_tier_succeeds():
    class EmptySource:
        name = "empty"

        def discover(self, transport):
            return []

    assert build_runtime_module_map(transport=None, sources=[EmptySource()]) == []  # type: ignore[arg-type]


def test_load_static_placements_missing_workspace_returns_empty(tmp_path):
    assert load_static_placements(tmp_path) == {}


def test_load_static_placements_reads_module_placements_json(tmp_path):
    metadata_dir = tmp_path / "analysis" / "game_project" / "metadata"
    metadata_dir.mkdir(parents=True)
    (metadata_dir / "module_placements.json").write_text(
        json.dumps(
            [
                {"path": "PSP_GAME/SYSDIR/EBOOT.BIN", "load_address": 0x08800000, "image_size": 0x1000},
                {"path": "PSP_GAME/USRDIR/LOCKED.PRX", "load_address": 0x08804000, "image_size": 0x2000},
            ]
        ),
        encoding="utf-8",
    )

    placements = load_static_placements(tmp_path)

    assert placements["PSP_GAME/USRDIR/LOCKED.PRX"]["image_size"] == 0x2000
    assert placements["PSP_GAME/SYSDIR/EBOOT.BIN"]["load_address"] == 0x08800000
