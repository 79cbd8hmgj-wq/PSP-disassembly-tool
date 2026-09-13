from __future__ import annotations

import json

from pspdisasm.cli import main
from pspdisasm.runtime.workspace import (
    list_sessions,
    load_module_map,
    load_observations,
    load_reconciliation,
)
from tests.fake_ppsspp_server import FakeConnection, FakePpssppServer


def test_cli_runtime_observe_persists_observation_and_prints_summary(tmp_path, capsys):
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        add_request = conn.recv_json()
        conn.reply_ok(add_request)
        conn.recv_json()  # cpu.resume
        conn.send_event("cpu.stepping", hit={"kind": "exec", "address": 0x08800000})
        regs_request = conn.recv_json()
        conn.reply_ok(regs_request, categories=[{"registerNames": ["pc"], "uintValues": [0x08800000]}])
        bt_request = conn.recv_json()
        conn.reply_ok(bt_request, frames=[])
        remove_request = conn.recv_json()
        conn.reply_ok(remove_request)
        conn.recv_json()  # defensive resume

    server = FakePpssppServer(handler)
    try:
        code = main(
            [
                "runtime",
                "observe",
                str(tmp_path),
                "--port",
                str(server.port),
                "--address",
                "0x08800000",
                "--timeout",
                "2.0",
                "--session-id",
                "test-session",
            ]
        )
    finally:
        server.join()

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Session: test-session" in stdout
    assert "Breakpoint: 0x08800000" in stdout

    observations = load_observations(tmp_path, "test-session")
    assert len(observations) == 1
    assert observations[0].breakpoint_address.value == 0x08800000
    assert list_sessions(tmp_path) == ["test-session"]


def test_cli_runtime_observe_appends_across_repeated_calls(tmp_path):
    def make_handler():
        def handler(conn: FakeConnection) -> None:
            conn.bootstrap()
            add_request = conn.recv_json()
            conn.reply_ok(add_request)
            conn.recv_json()
            conn.send_event("cpu.stepping", hit={"kind": "exec", "address": 0x08800000})
            regs_request = conn.recv_json()
            conn.reply_ok(regs_request, categories=[])
            bt_request = conn.recv_json()
            conn.reply_ok(bt_request, frames=[])
            remove_request = conn.recv_json()
            conn.reply_ok(remove_request)
            conn.recv_json()

        return handler

    for _ in range(2):
        server = FakePpssppServer(make_handler())
        try:
            code = main(
                [
                    "runtime",
                    "observe",
                    str(tmp_path),
                    "--port",
                    str(server.port),
                    "--address",
                    "0x08800000",
                    "--session-id",
                    "same-session",
                ]
            )
            assert code == 0
        finally:
            server.join()

    assert len(load_observations(tmp_path, "same-session")) == 2


def test_cli_runtime_observe_writes_json_to_stdout(tmp_path, capsys):
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        add_request = conn.recv_json()
        conn.reply_ok(add_request)
        conn.recv_json()
        conn.send_event("cpu.stepping", hit={"kind": "exec", "address": 0x08800000})
        regs_request = conn.recv_json()
        conn.reply_ok(regs_request, categories=[])
        bt_request = conn.recv_json()
        conn.reply_ok(bt_request, frames=[])
        remove_request = conn.recv_json()
        conn.reply_ok(remove_request)
        conn.recv_json()

    server = FakePpssppServer(handler)
    try:
        code = main(
            [
                "runtime",
                "observe",
                str(tmp_path),
                "--port",
                str(server.port),
                "--address",
                "0x08800000",
                "--json",
                "-",
            ]
        )
    finally:
        server.join()

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["breakpoint_address"]["value"] == 0x08800000


def test_cli_runtime_modules_uses_user_provided_fallback_when_hle_unsupported(tmp_path, capsys):
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_error(request, "unknown event")

    server = FakePpssppServer(handler)
    try:
        code = main(
            [
                "runtime",
                "modules",
                str(tmp_path),
                "--port",
                str(server.port),
                "--module-base",
                "PSP_GAME/USRDIR/LOCKED.PRX=0x09A00000",
            ]
        )
    finally:
        server.join()

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Modules: 1" in stdout
    modules = load_module_map(tmp_path)
    assert modules[0].static_module_path == "PSP_GAME/USRDIR/LOCKED.PRX"
    assert modules[0].runtime_base.value == 0x09A00000


def test_cli_runtime_reconcile_uses_persisted_observations_and_module_map(tmp_path, capsys):
    from pspdisasm.model import (
        RuntimeAddress,
        RuntimeBreakpointObservation,
        RuntimeModule,
        RuntimeSessionInfo,
    )
    from pspdisasm.runtime.workspace import (
        save_module_map,
        save_observations,
        save_session_info,
    )

    module_path = "PSP_GAME/USRDIR/LOCKED.PRX"
    save_session_info(tmp_path, RuntimeSessionInfo(session_id="sess-1", host="127.0.0.1", port=1))
    save_module_map(
        tmp_path,
        [
            RuntimeModule(
                name=module_path,
                runtime_base=RuntimeAddress(domain="runtime", value=0x09A00000),
                runtime_size=None,
                static_module_path=module_path,
                resolution_status="user_provided",
            )
        ],
    )
    save_observations(
        tmp_path,
        "sess-1",
        [
            RuntimeBreakpointObservation(
                session_id="sess-1",
                sequence=1,
                breakpoint_address=RuntimeAddress(domain="runtime", value=0x09A00010),
                hit_count=1,
            )
        ],
    )

    metadata_dir = tmp_path / "analysis" / "game_project" / "metadata"
    metadata_dir.mkdir(parents=True)
    (metadata_dir / "module_placements.json").write_text(
        json.dumps([{"path": module_path, "load_address": 0x08804000, "image_size": 0x10000}]), encoding="utf-8"
    )

    candidates_file = tmp_path / "candidates.json"
    candidates_file.write_text(
        json.dumps({module_path: [{"kind": "function", "address": 0x08804010, "evidence": ["sub_08804010"]}]}),
        encoding="utf-8",
    )

    code = main(["runtime", "reconcile", str(tmp_path), "--static-candidates", str(candidates_file)])

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Reconciled: 1 observation(s)" in stdout
    assert "corroborated" in stdout

    results = load_reconciliation(tmp_path)
    assert len(results) == 1
    assert results[0].static_address.value == 0x08804010
