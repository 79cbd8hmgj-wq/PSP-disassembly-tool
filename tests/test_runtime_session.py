from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pspdisasm.errors import RuntimeBackendUnavailableError, RuntimeCaptureError
from pspdisasm.model import RuntimeAddress, RuntimeAddressDomain
from pspdisasm.runtime.session import LaunchSpec, RuntimeSession
from tests.fake_ppsspp_server import (
    FakeConnection,
    FakePpssppServer,
    allocate_free_port,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _runtime_addr(value: int) -> RuntimeAddress:
    return RuntimeAddress(domain=RuntimeAddressDomain.RUNTIME.value, value=value)


def test_connect_mode_reads_registers_and_closes():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_ok(request, categories=[{"registerNames": ["pc"], "uintValues": [0x08800000]}])

    server = FakePpssppServer(handler)
    try:
        with RuntimeSession(session_id="s1", port=server.port) as session:
            snapshot = session.read_registers()
            assert snapshot.registers == {"pc": 0x08800000}
            assert snapshot.session_id == "s1"
            assert snapshot.sequence == 1
    finally:
        server.join()


def test_observe_breakpoint_hits_and_always_removes_breakpoint():
    events: list[str] = []

    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        add_request = conn.recv_json()
        events.append(add_request["event"])
        conn.reply_ok(add_request)
        resume_request = conn.recv_json()
        events.append(resume_request["event"])
        conn.send_event("cpu.stepping", hit={"kind": "exec", "address": 0x08800000})
        regs_request = conn.recv_json()
        conn.reply_ok(regs_request, categories=[{"registerNames": ["pc"], "uintValues": [0x08800000]}])
        bt_request = conn.recv_json()
        conn.reply_ok(bt_request, frames=[{"pc": 0x08800004}])
        remove_request = conn.recv_json()
        events.append(remove_request["event"])
        conn.reply_ok(remove_request)
        resume_again = conn.recv_json()
        events.append(resume_again["event"])

    server = FakePpssppServer(handler)
    try:
        with RuntimeSession(session_id="s1", port=server.port) as session:
            observation = session.observe_breakpoint(address=_runtime_addr(0x08800000), timeout=2.0)
            assert observation.breakpoint_address.value == 0x08800000
            assert observation.registers.registers == {"pc": 0x08800000}
            assert observation.backtrace.frames[0].value == 0x08800004
            assert observation.warnings == []
    finally:
        server.join()

    assert events == [
        "cpu.breakpoint.add",
        "cpu.resume",
        "cpu.breakpoint.remove",
        "cpu.resume",
    ]


def test_observe_breakpoint_removes_breakpoint_on_wait_timeout():
    events: list[str] = []

    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        add_request = conn.recv_json()
        events.append(add_request["event"])
        conn.reply_ok(add_request)
        resume_request = conn.recv_json()
        events.append(resume_request["event"])
        # Never send cpu.stepping: the wait must time out.
        remove_request = conn.recv_json()
        events.append(remove_request["event"])
        conn.reply_ok(remove_request)
        resume_again = conn.recv_json()
        events.append(resume_again["event"])

    server = FakePpssppServer(handler)
    try:
        with RuntimeSession(session_id="s1", port=server.port) as session:
            with pytest.raises(RuntimeCaptureError):
                session.observe_breakpoint(address=_runtime_addr(0x08800000), timeout=0.3)
    finally:
        server.close()

    assert events == ["cpu.breakpoint.add", "cpu.resume", "cpu.breakpoint.remove", "cpu.resume"]


def test_observe_breakpoint_rejects_memory_reads_exceeding_bound_without_installing_breakpoint():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()

    server = FakePpssppServer(handler)
    try:
        with RuntimeSession(session_id="s1", port=server.port) as session:
            with pytest.raises(RuntimeCaptureError, match="exceeding the bound"):
                session.observe_breakpoint(
                    address=_runtime_addr(0x08800000),
                    timeout=1.0,
                    memory_reads=[(_runtime_addr(0x08800000), 1024)],
                    max_total_memory_bytes=16,
                )
    finally:
        server.close()


def test_close_after_exception_inside_with_block_still_cleans_up():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        add_request = conn.recv_json()
        conn.reply_ok(add_request)
        remove_request = conn.recv_json()
        conn.reply_ok(remove_request)
        # RuntimeSession.close() sends a WebSocket close frame next; just
        # read and discard it rather than treating it as a JSON request.
        conn.recv_frame()

    server = FakePpssppServer(handler)
    try:
        with pytest.raises(ValueError):
            with RuntimeSession(session_id="s1", port=server.port) as session:
                session._transport.add_exec_breakpoint(0x08800000)
                session._installed_breakpoints.add(0x08800000)
                raise ValueError("synthetic failure inside session")
    finally:
        server.join()


def _write_fake_ppsspp_launcher(tmp_path: Path, *, port: int, startup_delay: float = 0.0) -> Path:
    script = tmp_path / "fake_ppsspp.py"
    script.write_text(
        "import sys, time\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from tests.fake_ppsspp_server import FakePpssppServer\n"
        f"time.sleep({startup_delay})\n"
        "def handler(conn):\n"
        "    conn.bootstrap()\n"
        "    time.sleep(0.3)\n"
        f"server = FakePpssppServer(handler, port={port})\n"
        "server.join(timeout=10)\n",
        encoding="utf-8",
    )
    return script


def test_launch_mode_connects_after_startup_delay_and_terminates_process_on_close():
    port = allocate_free_port()

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        script = _write_fake_ppsspp_launcher(Path(tmp), port=port, startup_delay=0.3)
        launch = LaunchSpec(executable=Path(sys.executable), args=[str(script)])

        session = RuntimeSession(session_id="launch1", port=port, launch=launch, connect_retry_seconds=5.0)
        process = session._process
        assert process is not None
        assert process.poll() is None
        session.close()

        assert process.poll() is not None


def test_launch_mode_reports_process_exit_instead_of_hanging():
    port = allocate_free_port()

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "dies_immediately.py"
        script.write_text("raise SystemExit(1)\n", encoding="utf-8")
        launch = LaunchSpec(executable=Path(sys.executable), args=[str(script)])

        with pytest.raises(RuntimeBackendUnavailableError, match="exited"):
            RuntimeSession(session_id="launch2", port=port, launch=launch, connect_retry_seconds=2.0)


def test_launch_mode_rejects_missing_executable():
    with pytest.raises(RuntimeBackendUnavailableError, match="does not exist"):
        RuntimeSession(
            session_id="launch3",
            port=allocate_free_port(),
            launch=LaunchSpec(executable=Path("/nonexistent/ppsspp")),
        )
