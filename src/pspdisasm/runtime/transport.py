from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import socket
import struct
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass

from ..errors import RuntimeConnectionError, RuntimeProtocolError, RuntimeTimeoutError

_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_DEBUGGER_PATH = "/debugger"
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_REQUEST_TIMEOUT = 5.0
DEFAULT_MAX_FRAME_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_QUEUED_EVENTS = 256
_MAX_HANDSHAKE_HEADER_BYTES = 65536


@dataclass(frozen=True, slots=True)
class DebuggerEvent:
    event: str
    payload: dict[str, object]
    ticket: int | None


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except TimeoutError as exc:
            raise RuntimeTimeoutError("PPSSPP debugger receive timed out") from exc
        except OSError as exc:
            raise RuntimeConnectionError(f"PPSSPP debugger connection error: {exc}") from exc
        if not chunk:
            raise RuntimeConnectionError("PPSSPP debugger connection closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_http_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        try:
            chunk = sock.recv(1)
        except TimeoutError as exc:
            raise RuntimeTimeoutError("PPSSPP debugger handshake timed out") from exc
        except OSError as exc:
            raise RuntimeConnectionError(f"PPSSPP debugger connection error: {exc}") from exc
        if not chunk:
            raise RuntimeConnectionError("PPSSPP debugger closed during WebSocket handshake")
        data.extend(chunk)
        if len(data) > _MAX_HANDSHAKE_HEADER_BYTES:
            raise RuntimeProtocolError("PPSSPP debugger handshake headers are too large")
    return bytes(data)


def _encode_client_frame(payload: bytes, *, opcode: int, mask_key: bytes | None = None) -> bytes:
    key = os.urandom(4) if mask_key is None else mask_key
    if len(key) != 4:
        raise RuntimeProtocolError("WebSocket mask key must be four bytes")
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
    masked = bytes(value ^ key[index % 4] for index, value in enumerate(payload))
    return header + key + masked


def _receive_frame(sock: socket.socket, *, max_frame_bytes: int) -> tuple[int, bytes]:
    first, second = _recv_exact(sock, 2)
    if not first & 0x80:
        raise RuntimeProtocolError("fragmented PPSSPP WebSocket frames are unsupported")
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if length > max_frame_bytes:
        raise RuntimeProtocolError(
            f"PPSSPP debugger frame exceeds the maximum size ({length} > {max_frame_bytes} bytes)"
        )
    mask_key = _recv_exact(sock, 4) if second & 0x80 else b""
    payload = _recv_exact(sock, length)
    if mask_key:
        payload = bytes(value ^ mask_key[index % 4] for index, value in enumerate(payload))
    return opcode, payload


def _connect_socket(host: str, port: int, *, connect_timeout: float) -> socket.socket:
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
    except TimeoutError as exc:
        raise RuntimeTimeoutError(f"connecting to PPSSPP debugger timed out: {exc}") from exc
    except OSError as exc:
        raise RuntimeConnectionError(f"unable to connect to PPSSPP debugger: {exc}") from exc
    return sock


def _perform_handshake(sock: socket.socket, host: str, port: int) -> None:
    nonce = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {_DEBUGGER_PATH} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {nonce}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    try:
        sock.sendall(request)
    except OSError as exc:
        raise RuntimeConnectionError(f"unable to send PPSSPP WebSocket handshake: {exc}") from exc

    response = _recv_http_headers(sock)
    lines = response.decode("iso-8859-1").split("\r\n")
    if not lines or " 101 " not in f" {lines[0]} ":
        raise RuntimeConnectionError(
            f"unexpected PPSSPP WebSocket handshake status: {lines[0] if lines else ''}"
        )
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.casefold()] = value.strip()
    expected = base64.b64encode(
        hashlib.sha1((nonce + _WEBSOCKET_GUID).encode("ascii")).digest()
    ).decode("ascii")
    if headers.get("sec-websocket-accept") != expected:
        raise RuntimeConnectionError("PPSSPP WebSocket accept key mismatch")


class PpssppDebuggerTransport:
    """A bounded, from-scratch client for PPSSPP's WebSocket JSON debugger protocol.

    This does not reuse or copy PPSSPP's (GPL) implementation; it is an
    independent client for the same documented wire protocol, generalized
    from a project-owned reference client's proven request vocabulary
    (version/config, cpu.getAllRegs, memory.read, cpu.breakpoint.add/remove,
    cpu.resume, hle.backtrace) with explicit bounds added at every I/O
    boundary a single-purpose client did not need.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_queued_events: int = DEFAULT_MAX_QUEUED_EVENTS,
    ) -> None:
        normalized_host = host.casefold()
        if normalized_host not in _LOOPBACK_HOSTS:
            raise RuntimeConnectionError("PPSSPP debugger host must be loopback-only")
        if not 1 <= port <= 65535:
            raise RuntimeConnectionError("PPSSPP debugger port must be between 1 and 65535")
        if connect_timeout <= 0 or request_timeout <= 0:
            raise RuntimeConnectionError("PPSSPP debugger timeouts must be positive")
        if max_frame_bytes <= 0 or max_queued_events <= 0:
            raise RuntimeConnectionError("PPSSPP debugger bounds must be positive")

        self.host = host
        self.port = port
        self.request_timeout = request_timeout
        self.max_frame_bytes = max_frame_bytes
        self._socket = _connect_socket(host, port, connect_timeout=connect_timeout)
        try:
            self._socket.settimeout(request_timeout)
            _perform_handshake(self._socket, host, port)
        except Exception:
            self._socket.close()
            raise

        self._next_ticket = 1
        self._queued_events: dict[str, deque[dict[str, object]]] = defaultdict(
            lambda: deque(maxlen=max_queued_events)
        )
        self.request("version", name="pspdisasm", version="1.0")
        self.request("client.config.set", acknowledgeDeferred=True)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._socket.sendall(_encode_client_frame(b"", opcode=0x8))
        self._socket.close()

    def __enter__(self) -> PpssppDebuggerTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _send_json(self, payload: Mapping[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            self._socket.sendall(_encode_client_frame(encoded, opcode=0x1))
        except OSError as exc:
            raise RuntimeConnectionError(f"PPSSPP debugger send failed: {exc}") from exc

    def _receive_json(self) -> dict[str, object]:
        while True:
            opcode, payload = _receive_frame(self._socket, max_frame_bytes=self.max_frame_bytes)
            if opcode == 0x8:
                raise RuntimeConnectionError("PPSSPP debugger connection closed")
            if opcode == 0x9:
                with contextlib.suppress(OSError):
                    self._socket.sendall(_encode_client_frame(payload, opcode=0xA))
                continue
            if opcode == 0xA:
                continue
            if opcode != 0x1:
                continue
            try:
                decoded: object = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeProtocolError(f"invalid JSON from PPSSPP debugger: {exc}") from exc
            if not isinstance(decoded, dict):
                raise RuntimeProtocolError("PPSSPP debugger JSON response must be an object")
            return {str(key): value for key, value in decoded.items()}

    def _new_ticket(self) -> int:
        ticket = self._next_ticket
        self._next_ticket += 1
        return ticket

    def send(self, event: str, **params: object) -> int:
        ticket = self._new_ticket()
        self._send_json({"event": event, "ticket": ticket, **params})
        return ticket

    def request(self, event: str, *, timeout: float | None = None, **params: object) -> dict[str, object]:
        ticket = self.send(event, **params)
        deadline = time.monotonic() + (timeout if timeout is not None else self.request_timeout)
        while True:
            self._apply_remaining_timeout(deadline)
            response = self._receive_json()
            response_event = response.get("event")
            response_ticket = response.get("ticket")
            if response_ticket == ticket:
                if response_event == "error":
                    message = response.get("message", "unknown debugger error")
                    raise RuntimeProtocolError(f"PPSSPP debugger error: {message}")
                return response
            if isinstance(response_event, str) and response_ticket is None:
                self._queued_events[response_event].append(response)

    def _apply_remaining_timeout(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeTimeoutError("PPSSPP debugger request timed out")
        self._socket.settimeout(remaining)

    def try_request(self, event: str, *, timeout: float | None = None, **params: object) -> DebuggerEvent | None:
        """Like request(), but a debugger 'error' response or a timeout returns None instead of raising.

        Used for capability probing (e.g. an HLE module-list event PPSSPP may
        or may not expose) without treating "unsupported" as a hard failure.
        """
        ticket = self.send(event, **params)
        deadline = time.monotonic() + (timeout if timeout is not None else self.request_timeout)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._socket.settimeout(remaining)
                response = self._receive_json()
                response_event = response.get("event")
                response_ticket = response.get("ticket")
                if response_ticket == ticket:
                    if response_event == "error":
                        return None
                    return DebuggerEvent(
                        event=str(response_event), payload=response, ticket=ticket
                    )
                if isinstance(response_event, str) and response_ticket is None:
                    self._queued_events[response_event].append(response)
        except (RuntimeTimeoutError, RuntimeConnectionError, RuntimeProtocolError):
            return None
        finally:
            with contextlib.suppress(OSError):
                self._socket.settimeout(self.request_timeout)

    def wait_for_event(self, event: str, *, timeout: float) -> dict[str, object]:
        if timeout <= 0:
            raise RuntimeTimeoutError("event wait timeout must be positive")
        queued = self._queued_events[event]
        if queued:
            return queued.popleft()
        deadline = time.monotonic() + timeout
        try:
            while True:
                self._apply_remaining_timeout(deadline)
                response = self._receive_json()
                response_event = response.get("event")
                if response_event == event:
                    return response
                if isinstance(response_event, str) and response.get("ticket") is None:
                    self._queued_events[response_event].append(response)
        finally:
            with contextlib.suppress(OSError):
                self._socket.settimeout(self.request_timeout)

    def get_registers(self) -> dict[str, int]:
        response = self.request("cpu.getAllRegs")
        categories = response.get("categories")
        if not isinstance(categories, list):
            raise RuntimeProtocolError("cpu.getAllRegs response is missing categories")
        registers: dict[str, int] = {}
        for category in categories:
            if not isinstance(category, dict):
                raise RuntimeProtocolError("invalid cpu.getAllRegs category")
            names = category.get("registerNames")
            values = category.get("uintValues")
            if not isinstance(names, list) or not isinstance(values, list):
                raise RuntimeProtocolError("invalid cpu.getAllRegs register arrays")
            if len(names) != len(values):
                raise RuntimeProtocolError("cpu.getAllRegs register arrays differ in length")
            for name, value in zip(names, values, strict=True):
                if not isinstance(name, str) or not isinstance(value, int):
                    raise RuntimeProtocolError("invalid cpu.getAllRegs register value")
                registers[name] = value
        return registers

    def read_memory(self, address: int, size: int, *, max_bytes: int) -> bytes:
        if address < 0 or size <= 0:
            raise RuntimeProtocolError("memory read requires a non-negative address and positive size")
        if size > max_bytes:
            raise RuntimeProtocolError(
                f"memory read of {size} bytes exceeds the maximum of {max_bytes} bytes"
            )
        response = self.request("memory.read", address=address, size=size)
        encoded = response.get("base64")
        if not isinstance(encoded, str):
            raise RuntimeProtocolError("memory.read response is missing base64")
        try:
            data = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RuntimeProtocolError("memory.read returned invalid base64") from exc
        if len(data) != size:
            raise RuntimeProtocolError(
                f"memory.read size mismatch: expected {size}, observed {len(data)}"
            )
        return data

    def add_exec_breakpoint(self, address: int) -> None:
        self.request("cpu.breakpoint.add", address=address, enabled=True, log=False)

    def remove_exec_breakpoint(self, address: int) -> None:
        self.request("cpu.breakpoint.remove", address=address)

    def resume(self) -> int:
        return self.send("cpu.resume")

    def backtrace(self, *, max_depth: int) -> tuple[int, ...]:
        response = self.request("hle.backtrace")
        frames = response.get("frames")
        if not isinstance(frames, list):
            raise RuntimeProtocolError("hle.backtrace response is missing frames")
        pcs: list[int] = []
        for frame in frames[:max_depth]:
            if not isinstance(frame, dict) or not isinstance(frame.get("pc"), int):
                raise RuntimeProtocolError("hle.backtrace frame is missing pc")
            pcs.append(frame["pc"])
        return tuple(pcs)
