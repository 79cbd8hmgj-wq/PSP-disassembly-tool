from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import socket
import struct
import threading
from collections.abc import Callable

_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def allocate_free_port() -> int:
    """Reserve an ephemeral TCP port for a test that needs to know it up front (e.g. before spawning a subprocess)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("fake PPSSPP server: connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_http_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("fake PPSSPP server: closed during handshake")
        data.extend(chunk)
    return bytes(data)


def server_handshake(sock: socket.socket) -> None:
    """Perform the server side of the WebSocket upgrade the transport expects."""
    request = _recv_http_headers(sock).decode("iso-8859-1")
    key = None
    for line in request.split("\r\n")[1:]:
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    if key is None:
        raise ValueError("fake PPSSPP server: missing Sec-WebSocket-Key")
    accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    ).encode("ascii")
    sock.sendall(response)


def send_bad_handshake(sock: socket.socket) -> None:
    """Send a non-101 response so tests can exercise handshake-failure handling."""
    _recv_http_headers(sock)
    sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")


class FakeConnection:
    """Server-side helper: decode masked client frames, encode unmasked server frames."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def recv_frame(self) -> tuple[int, bytes]:
        first, second = _recv_exact(self.sock, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", _recv_exact(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _recv_exact(self.sock, 8))[0]
        mask_key = _recv_exact(self.sock, 4) if second & 0x80 else b""
        payload = _recv_exact(self.sock, length)
        if mask_key:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def recv_json(self) -> dict[str, object]:
        opcode, payload = self.recv_frame()
        if opcode != 0x1:
            raise ValueError(f"fake PPSSPP server: expected a text frame, got opcode {opcode}")
        return json.loads(payload.decode("utf-8"))

    def send_frame(self, payload: bytes, *, opcode: int = 0x1) -> None:
        first = 0x80 | opcode
        length = len(payload)
        if length < 126:
            header = bytes((first, length))
        elif length <= 0xFFFF:
            header = bytes((first, 126)) + struct.pack("!H", length)
        else:
            header = bytes((first, 127)) + struct.pack("!Q", length)
        self.sock.sendall(header + payload)

    def send_raw(self, header_and_payload: bytes) -> None:
        self.sock.sendall(header_and_payload)

    def send_json(self, payload: dict[str, object]) -> None:
        self.send_frame(json.dumps(payload).encode("utf-8"))

    def reply_ok(self, request: dict[str, object], **extra: object) -> None:
        self.send_json({"event": request.get("event"), "ticket": request.get("ticket"), **extra})

    def reply_error(self, request: dict[str, object], message: str) -> None:
        self.send_json({"event": "error", "ticket": request.get("ticket"), "message": message})

    def send_event(self, event: str, **payload: object) -> None:
        self.send_json({"event": event, **payload})

    def bootstrap(self) -> None:
        """Answer the two handshake requests every PpssppDebuggerTransport sends on connect."""
        version_request = self.recv_json()
        self.reply_ok(version_request)
        config_request = self.recv_json()
        self.reply_ok(config_request)


class FakePpssppServer:
    """A minimal real TCP+WebSocket server for testing PpssppDebuggerTransport without PPSSPP."""

    def __init__(
        self,
        handler: Callable[[FakeConnection], None],
        *,
        handshake: Callable[[socket.socket], None] = server_handshake,
        port: int = 0,
    ) -> None:
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("127.0.0.1", port))
        self._server_socket.listen(1)
        self.port = self._server_socket.getsockname()[1]
        self._handler = handler
        self._handshake = handshake
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self._server_socket.settimeout(10.0)
        try:
            conn, _ = self._server_socket.accept()
        except OSError:
            return
        try:
            conn.settimeout(10.0)
            self._handshake(conn)
            self._handler(FakeConnection(conn))
        except BaseException as exc:  # noqa: BLE001 - captured for the test thread to re-raise
            self._error = exc
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def join(self, timeout: float = 5.0) -> None:
        self._thread.join(timeout=timeout)
        if self._error is not None:
            raise self._error

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._server_socket.close()
        self._thread.join(timeout=5.0)
