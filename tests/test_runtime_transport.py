from __future__ import annotations

import struct

import pytest

from pspdisasm.errors import (
    RuntimeConnectionError,
    RuntimeProtocolError,
    RuntimeTimeoutError,
)
from pspdisasm.runtime.transport import PpssppDebuggerTransport
from tests.fake_ppsspp_server import (
    FakeConnection,
    FakePpssppServer,
    send_bad_handshake,
)


def _connect(port: int, **kwargs) -> PpssppDebuggerTransport:
    return PpssppDebuggerTransport("127.0.0.1", port, **kwargs)


def test_valid_handshake_and_bootstrap_requests_get_sequential_tickets():
    tickets: list[int] = []

    def handler(conn: FakeConnection) -> None:
        version_request = conn.recv_json()
        tickets.append(version_request["ticket"])
        conn.reply_ok(version_request)
        config_request = conn.recv_json()
        tickets.append(config_request["ticket"])
        conn.reply_ok(config_request)
        extra_request = conn.recv_json()
        tickets.append(extra_request["ticket"])
        conn.reply_ok(extra_request, uintValues=[])

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            transport.request("cpu.resume_ack_probe")
        finally:
            transport.close()
    finally:
        server.join()

    assert tickets == [1, 2, 3]


def test_invalid_handshake_raises_connection_error():
    def handler(conn: FakeConnection) -> None:
        pass

    server = FakePpssppServer(handler, handshake=send_bad_handshake)
    try:
        with pytest.raises(RuntimeConnectionError):
            _connect(server.port)
    finally:
        server.close()


def test_response_correlation_skips_unsolicited_events():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.send_event("hle.currentThread", threadId=7)
        conn.reply_ok(request, base64="")

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            response = transport.request("memory.read", address=0, size=0)
            assert response["base64"] == ""
        finally:
            transport.close()
    finally:
        server.join()


def test_malformed_json_raises_protocol_error():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.recv_json()
        conn.send_frame(b"{not valid json")

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            with pytest.raises(RuntimeProtocolError):
                transport.request("cpu.getAllRegs")
        finally:
            transport.close()
    finally:
        server.join()


def test_fragmented_frame_is_rejected_as_malformed():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.recv_json()
        # FIN bit unset (0x01 instead of 0x81): unsupported fragmentation.
        conn.send_raw(bytes((0x01, 0x00)))

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            with pytest.raises(RuntimeProtocolError, match="fragmented"):
                transport.request("cpu.getAllRegs")
        finally:
            transport.close()
    finally:
        server.join()


def test_oversized_frame_is_rejected_before_reading_payload():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.recv_json()
        # Declare an 8-byte extended length far beyond the bound, then send
        # nothing further: a correct client must reject based on the length
        # header alone, never blocking on payload bytes that never arrive.
        header = bytes((0x81, 0x7F)) + struct.pack("!Q", 10**9)
        conn.send_raw(header)

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port, max_frame_bytes=1024)
        try:
            with pytest.raises(RuntimeProtocolError, match="exceeds the maximum"):
                transport.request("cpu.getAllRegs")
        finally:
            transport.close()
    finally:
        server.join()


def test_request_timeout_is_bounded_and_typed():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.recv_json()
        # Never respond.
        import time

        time.sleep(1.0)

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port, request_timeout=0.2)
        try:
            with pytest.raises(RuntimeTimeoutError):
                transport.request("cpu.getAllRegs")
        finally:
            transport.close()
    finally:
        server.close()


def test_disconnect_mid_request_raises_connection_error():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.recv_json()
        # Close without responding.

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            with pytest.raises(RuntimeConnectionError):
                transport.request("cpu.getAllRegs")
        finally:
            transport.close()
    finally:
        server.join()


def test_wait_for_event_returns_queued_event_and_skips_others():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.send_event("hle.currentThread", threadId=1)
        conn.send_event("cpu.stepping", hit={"kind": "exec", "address": 0x08800000})

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            event = transport.wait_for_event("cpu.stepping", timeout=2.0)
            assert event["hit"]["address"] == 0x08800000
        finally:
            transport.close()
    finally:
        server.join()


def test_get_registers_parses_categories():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_ok(
            request,
            categories=[{"registerNames": ["pc", "ra"], "uintValues": [0x08800000, 0x08800010]}],
        )

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            registers = transport.get_registers()
            assert registers == {"pc": 0x08800000, "ra": 0x08800010}
        finally:
            transport.close()
    finally:
        server.join()


def test_read_memory_rejects_request_above_bound_without_contacting_server():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            with pytest.raises(RuntimeProtocolError, match="exceeds the maximum"):
                transport.read_memory(0x08800000, 1024, max_bytes=16)
        finally:
            transport.close()
    finally:
        server.close()


def test_read_memory_decodes_base64_and_checks_size():
    import base64

    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_ok(request, base64=base64.b64encode(b"ABCD").decode("ascii"))

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            data = transport.read_memory(0x08800000, 4, max_bytes=1024)
            assert data == b"ABCD"
        finally:
            transport.close()
    finally:
        server.join()


def test_add_and_remove_breakpoint_and_resume():
    seen_events: list[str] = []

    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        add_request = conn.recv_json()
        seen_events.append(add_request["event"])
        conn.reply_ok(add_request)
        remove_request = conn.recv_json()
        seen_events.append(remove_request["event"])
        conn.reply_ok(remove_request)
        resume_request = conn.recv_json()
        seen_events.append(resume_request["event"])
        # cpu.resume is fire-and-forget: no reply expected/sent.

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            transport.add_exec_breakpoint(0x08800000)
            transport.remove_exec_breakpoint(0x08800000)
            transport.resume()
            import time

            time.sleep(0.05)
        finally:
            transport.close()
    finally:
        server.join()

    assert seen_events == ["cpu.breakpoint.add", "cpu.breakpoint.remove", "cpu.resume"]


def test_backtrace_bounds_depth():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_ok(request, frames=[{"pc": addr} for addr in (1, 2, 3, 4, 5)])

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            frames = transport.backtrace(max_depth=2)
            assert frames == (1, 2)
        finally:
            transport.close()
    finally:
        server.join()


def test_try_request_returns_none_on_error_response():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_error(request, "unsupported event")

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            result = transport.try_request("hle.module.list")
            assert result is None
        finally:
            transport.close()
    finally:
        server.join()


def test_try_request_returns_none_on_timeout_without_raising():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        conn.recv_json()
        import time

        time.sleep(1.0)

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            result = transport.try_request("hle.module.list", timeout=0.2)
            assert result is None
        finally:
            transport.close()
    finally:
        server.close()


def test_try_request_returns_event_on_success():
    def handler(conn: FakeConnection) -> None:
        conn.bootstrap()
        request = conn.recv_json()
        conn.reply_ok(request, modules=[])

    server = FakePpssppServer(handler)
    try:
        transport = _connect(server.port)
        try:
            result = transport.try_request("hle.module.list")
            assert result is not None
            assert result.payload["modules"] == []
        finally:
            transport.close()
    finally:
        server.join()


def test_rejects_non_loopback_host():
    with pytest.raises(RuntimeConnectionError):
        PpssppDebuggerTransport("example.com", 12345)
