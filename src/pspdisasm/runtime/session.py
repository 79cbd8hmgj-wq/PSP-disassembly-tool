from __future__ import annotations

import contextlib
import hashlib
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..errors import (
    RuntimeBackendUnavailableError,
    RuntimeCaptureError,
    RuntimeConnectionError,
    RuntimeProtocolError,
    RuntimeTimeoutError,
)
from ..model import (
    RuntimeAddress,
    RuntimeAddressDomain,
    RuntimeBacktrace,
    RuntimeBreakpointObservation,
    RuntimeMemoryObservation,
    RuntimeRegisterSnapshot,
    RuntimeSessionInfo,
)
from .transport import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT,
    PpssppDebuggerTransport,
)

DEFAULT_MAX_MEMORY_READ_BYTES = 64 * 1024
DEFAULT_MAX_TOTAL_MEMORY_BYTES = 64 * 1024
DEFAULT_MAX_BACKTRACE_DEPTH = 32
DEFAULT_LAUNCH_CONNECT_RETRY_SECONDS = 10.0
DEFAULT_PROCESS_SHUTDOWN_SECONDS = 5.0

TransportFactory = Callable[..., PpssppDebuggerTransport]


@dataclass(frozen=True, slots=True)
class LaunchSpec:
    """A user-supplied PPSSPP executable to launch as a subprocess.

    No shell is ever involved; `args` is passed straight to subprocess.Popen
    as an argument list.
    """

    executable: Path
    args: Sequence[str] = ()
    cwd: Path | None = None


def _launch_process(launch: LaunchSpec) -> subprocess.Popen:
    # A caller-supplied executable path is trusted the same way m2c/asm-differ/
    # recovery-backend paths already are elsewhere in this codebase: a
    # symlinked interpreter or wrapper (venvs, package-manager shims, AppImage
    # extraction) is normal here and is not the same trust boundary as a
    # bundle-relative *contained* file.
    if not launch.executable.is_file():
        raise RuntimeBackendUnavailableError(f"PPSSPP executable does not exist: {launch.executable}")
    args = [str(launch.executable), *launch.args]
    try:
        return subprocess.Popen(
            args,
            cwd=str(launch.cwd) if launch.cwd is not None else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise RuntimeBackendUnavailableError(f"unable to launch PPSSPP: {exc}") from exc


def _terminate_process(process: subprocess.Popen, *, timeout: float) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=timeout)


class RuntimeSession:
    """A higher-level, bounded session over one PpssppDebuggerTransport connection.

    Supports two modes: connect (attach to an already-running PPSSPP) and
    launch (start a user-supplied PPSSPP executable and connect once its
    debugger port is reachable). Either way, closing the session — including
    via a raised exception inside a `with` block — always removes every
    breakpoint this session installed and, in launch mode, always terminates
    the process it started. A connect-mode session never touches a process
    it did not launch.
    """

    def __init__(
        self,
        *,
        session_id: str,
        host: str = "127.0.0.1",
        port: int,
        launch: LaunchSpec | None = None,
        connect_retry_seconds: float = DEFAULT_LAUNCH_CONNECT_RETRY_SECONDS,
        workspace_source_identity: str | None = None,
        ppsspp_revision: str | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        transport_factory: TransportFactory = PpssppDebuggerTransport,
    ) -> None:
        self.info = RuntimeSessionInfo(
            session_id=session_id,
            host=host,
            port=port,
            ppsspp_revision=ppsspp_revision,
            workspace_source_identity=workspace_source_identity,
        )
        self._process: subprocess.Popen | None = None
        self._transport: PpssppDebuggerTransport | None = None
        self._installed_breakpoints: set[int] = set()
        self._sequence = 0

        try:
            if launch is not None:
                self._process = _launch_process(launch)
                self._transport = self._connect_with_retry(
                    host, port, connect_timeout, request_timeout, connect_retry_seconds, transport_factory
                )
            else:
                self._transport = transport_factory(
                    host, port, connect_timeout=connect_timeout, request_timeout=request_timeout
                )
        except Exception:
            self._cleanup_process()
            raise

    def _connect_with_retry(
        self,
        host: str,
        port: int,
        connect_timeout: float,
        request_timeout: float,
        retry_seconds: float,
        factory: TransportFactory,
    ) -> PpssppDebuggerTransport:
        deadline = time.monotonic() + retry_seconds
        last_exc: Exception = RuntimeBackendUnavailableError("PPSSPP debugger never became reachable")
        while True:
            assert self._process is not None
            if self._process.poll() is not None:
                raise RuntimeBackendUnavailableError(
                    f"PPSSPP process exited before its debugger became reachable "
                    f"(exit code {self._process.returncode})"
                ) from last_exc
            try:
                return factory(host, port, connect_timeout=connect_timeout, request_timeout=request_timeout)
            except (RuntimeConnectionError, RuntimeTimeoutError) as exc:
                last_exc = exc
                if time.monotonic() >= deadline:
                    raise RuntimeBackendUnavailableError(
                        f"PPSSPP debugger did not become reachable within {retry_seconds}s: {exc}"
                    ) from exc
                time.sleep(0.1)

    def _require_transport(self) -> PpssppDebuggerTransport:
        if self._transport is None:
            raise RuntimeCaptureError("runtime session is not connected")
        return self._transport

    @property
    def transport(self) -> PpssppDebuggerTransport:
        """The underlying transport, for composing with lower-level helpers (e.g. module mapping)."""
        return self._require_transport()

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def __enter__(self) -> RuntimeSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        transport = self._transport
        if transport is not None:
            for address in list(self._installed_breakpoints):
                with contextlib.suppress(Exception):
                    transport.remove_exec_breakpoint(address)
                self._installed_breakpoints.discard(address)
            with contextlib.suppress(Exception):
                transport.close()
            self._transport = None
        self._cleanup_process()

    def _cleanup_process(self) -> None:
        process = self._process
        if process is None:
            return
        self._process = None
        _terminate_process(process, timeout=DEFAULT_PROCESS_SHUTDOWN_SECONDS)

    def read_registers(self) -> RuntimeRegisterSnapshot:
        transport = self._require_transport()
        try:
            registers = transport.get_registers()
        except (RuntimeConnectionError, RuntimeProtocolError, RuntimeTimeoutError) as exc:
            raise RuntimeCaptureError(f"unable to read registers: {exc}") from exc
        return RuntimeRegisterSnapshot(
            session_id=self.info.session_id, sequence=self._next_sequence(), registers=registers
        )

    def read_memory(
        self,
        address: RuntimeAddress,
        size: int,
        *,
        max_bytes: int = DEFAULT_MAX_MEMORY_READ_BYTES,
    ) -> RuntimeMemoryObservation:
        transport = self._require_transport()
        try:
            data = transport.read_memory(address.value, size, max_bytes=max_bytes)
        except (RuntimeConnectionError, RuntimeProtocolError, RuntimeTimeoutError) as exc:
            raise RuntimeCaptureError(f"unable to read memory at 0x{address.value:08X}: {exc}") from exc
        return RuntimeMemoryObservation(
            session_id=self.info.session_id,
            sequence=self._next_sequence(),
            address=address,
            size=size,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def observe_breakpoint(
        self,
        *,
        address: RuntimeAddress,
        timeout: float,
        memory_reads: Sequence[tuple[RuntimeAddress, int]] = (),
        capture_registers: bool = True,
        capture_backtrace: bool = True,
        max_backtrace_depth: int = DEFAULT_MAX_BACKTRACE_DEPTH,
        max_total_memory_bytes: int = DEFAULT_MAX_TOTAL_MEMORY_BYTES,
    ) -> RuntimeBreakpointObservation:
        """install breakpoint -> resume -> wait (bounded) -> capture (bounded) -> always remove breakpoint."""
        if timeout <= 0:
            raise RuntimeCaptureError("observe_breakpoint timeout must be positive")
        total_requested = sum(size for _address, size in memory_reads)
        if total_requested > max_total_memory_bytes:
            raise RuntimeCaptureError(
                f"requested memory reads total {total_requested} bytes, exceeding the bound of "
                f"{max_total_memory_bytes} bytes"
            )

        transport = self._require_transport()
        warnings: list[str] = []
        installed = False
        try:
            transport.add_exec_breakpoint(address.value)
            installed = True
            self._installed_breakpoints.add(address.value)
            transport.resume()
            event = transport.wait_for_event("cpu.stepping", timeout=timeout)

            hit = event.get("hit")
            hit_address = hit.get("address") if isinstance(hit, dict) else None
            if not isinstance(hit_address, int) or hit_address != address.value:
                observed = f"0x{hit_address:08X}" if isinstance(hit_address, int) else "none"
                warnings.append(f"breakpoint hit event reported address {observed}, expected 0x{address.value:08X}")

            registers = self.read_registers() if capture_registers else None
            memory = [
                self.read_memory(mem_address, size, max_bytes=max_total_memory_bytes)
                for mem_address, size in memory_reads
            ]
            backtrace: RuntimeBacktrace | None = None
            if capture_backtrace:
                try:
                    frames = transport.backtrace(max_depth=max_backtrace_depth)
                except (RuntimeConnectionError, RuntimeProtocolError, RuntimeTimeoutError) as exc:
                    raise RuntimeCaptureError(f"unable to capture backtrace: {exc}") from exc
                backtrace = RuntimeBacktrace(
                    session_id=self.info.session_id,
                    sequence=self._next_sequence(),
                    frames=[
                        RuntimeAddress(domain=RuntimeAddressDomain.RUNTIME.value, value=pc) for pc in frames
                    ],
                )

            return RuntimeBreakpointObservation(
                session_id=self.info.session_id,
                sequence=self._next_sequence(),
                breakpoint_address=address,
                hit_count=1,
                registers=registers,
                memory=memory,
                backtrace=backtrace,
                warnings=warnings,
            )
        except RuntimeCaptureError:
            raise
        except (RuntimeConnectionError, RuntimeProtocolError, RuntimeTimeoutError) as exc:
            raise RuntimeCaptureError(f"breakpoint observation at 0x{address.value:08X} failed: {exc}") from exc
        finally:
            if installed:
                with contextlib.suppress(Exception):
                    transport.remove_exec_breakpoint(address.value)
                self._installed_breakpoints.discard(address.value)
                # Best-effort: never leave a real PPSSPP window paused because
                # this observation failed after the target actually hit.
                with contextlib.suppress(Exception):
                    transport.resume()
