from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Iterable, Protocol, Sequence, cast, runtime_checkable

from .analyzer import analyze_bytes
from .detect import InputKind, detect_input
from .errors import (
    ParseError,
    RecoveryBackendUnavailableError,
    RecoveryError,
    RecoveryOutputTooLargeError,
    RecoveryVerificationError,
)
from .model import ExecutableModel, PspContainerHeader, RecoveryProvenance
from .psp_container import parse_psp_container_header

# A PSP has at most 64 MiB of total RAM (PSP-2000/3000); no genuine decrypted
# PSP ELF/PRX body can exceed that, so it is a safe, conservative upper bound
# against a broken/malicious backend emitting an unbounded file.
DEFAULT_MAX_RECOVERED_BYTES = 64 * 1024 * 1024

DEFAULT_RECOVERY_THRESHOLD = 0.5
_MAX_DIAGNOSTIC_CHARS = 2000


class RecoveryOutcome(str, Enum):
    NO_BACKEND_ACCEPTED = "no_backend_accepted"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    BACKEND_FAILED = "backend_failed"
    OUTPUT_TOO_LARGE = "output_too_large"
    OUTPUT_UNCHANGED = "output_unchanged"
    OUTPUT_INVALID = "output_invalid"
    OUTPUT_STILL_ENCRYPTED = "output_still_encrypted"
    VERIFIED = "verified"


@runtime_checkable
class RecoveryBackend(Protocol):
    name: str

    def probe(self, header: PspContainerHeader, data: bytes) -> float: ...

    def recover(self, data: bytes) -> RecoveredPayload: ...


@dataclass(slots=True)
class RecoveredPayload:
    data: bytes
    backend_version: str | None = None
    diagnostics: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RecoveryResult:
    model: ExecutableModel
    data: bytes
    provenance: RecoveryProvenance


def _provenance(exc: BaseException) -> RecoveryProvenance | None:
    return cast("RecoveryProvenance | None", getattr(exc, "provenance", None))


def _ensure_provenance(
    exc: RecoveryBackendUnavailableError | RecoveryError,
    outcome: RecoveryOutcome,
    *,
    original_sha256: str,
    backend_name: str,
    warnings: Sequence[str],
) -> None:
    if _provenance(exc) is None:
        exc.provenance = RecoveryProvenance(
            outcome=outcome.value,
            original_sha256=original_sha256,
            recovery_backend=backend_name,
            warnings=list(warnings),
        )


def select_recovery_backend(
    header: PspContainerHeader,
    data: bytes,
    backends: Iterable[RecoveryBackend],
    *,
    threshold: float = DEFAULT_RECOVERY_THRESHOLD,
) -> tuple[RecoveryBackend | None, float, list[str]]:
    """Deterministically select the highest-confidence backend for one ~PSP container.

    Mirrors ``resource_containers.select_container_parser``: each backend's
    ``probe`` is isolated from the others' failures, invalid confidences are
    rejected with a warning rather than raised, and ties are broken by
    case-insensitive name then declaration order so selection never depends on
    dict/set iteration order.
    """
    warnings: list[str] = []
    accepted: list[tuple[float, str, int, RecoveryBackend]] = []

    for index, backend in enumerate(backends):
        backend_name = str(getattr(backend, "name", backend.__class__.__name__))
        try:
            score = float(backend.probe(header, data))
        except Exception as exc:
            warnings.append(f"Recovery backend {backend_name} probe failed: {exc}")
            continue
        if not math.isfinite(score) or score < 0.0 or score > 1.0:
            warnings.append(
                f"Recovery backend {backend_name} returned invalid probe confidence {score!r}"
            )
            continue
        if score >= threshold:
            accepted.append((score, backend_name, index, backend))

    if not accepted:
        return None, 0.0, warnings

    accepted.sort(key=lambda item: (-item[0], item[1].casefold(), item[1], item[2]))
    score, _, _, backend = accepted[0]
    return backend, score, warnings


def recover_bytes(
    data: bytes,
    *,
    backends: Sequence[RecoveryBackend],
    max_output_bytes: int = DEFAULT_MAX_RECOVERED_BYTES,
) -> RecoveryResult:
    """Attempt to recover one encrypted ~PSP container into an analyzable ELF/PRX.

    Phase 8B recovery is single-stage only: if the backend's output is itself
    still a ~PSP container, that is a verification failure, not a signal to
    recurse. Every failure path raises a typed error carrying a
    ``RecoveryProvenance`` so callers can distinguish *why* recovery did not
    succeed without parsing warning strings.
    """
    header = parse_psp_container_header(data)
    original_sha256 = hashlib.sha256(data).hexdigest()

    backend, _confidence, probe_warnings = select_recovery_backend(header, data, backends)
    if backend is None:
        raise RecoveryBackendUnavailableError(
            "no configured recovery backend accepted this PSP container",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.NO_BACKEND_ACCEPTED.value,
                original_sha256=original_sha256,
                warnings=list(probe_warnings),
            ),
        )
    backend_name = str(getattr(backend, "name", backend.__class__.__name__))

    try:
        payload = backend.recover(data)
    except RecoveryOutputTooLargeError as exc:
        _ensure_provenance(
            exc, RecoveryOutcome.OUTPUT_TOO_LARGE,
            original_sha256=original_sha256, backend_name=backend_name, warnings=probe_warnings,
        )
        raise
    except RecoveryVerificationError as exc:
        _ensure_provenance(
            exc, RecoveryOutcome.OUTPUT_INVALID,
            original_sha256=original_sha256, backend_name=backend_name, warnings=probe_warnings,
        )
        raise
    except RecoveryBackendUnavailableError as exc:
        _ensure_provenance(
            exc, RecoveryOutcome.BACKEND_UNAVAILABLE,
            original_sha256=original_sha256, backend_name=backend_name, warnings=probe_warnings,
        )
        raise
    except RecoveryError as exc:
        _ensure_provenance(
            exc, RecoveryOutcome.BACKEND_FAILED,
            original_sha256=original_sha256, backend_name=backend_name, warnings=probe_warnings,
        )
        raise
    except Exception as exc:
        wrapped = RecoveryError(f"Recovery backend {backend_name!r} failed: {exc}")
        _ensure_provenance(
            wrapped, RecoveryOutcome.BACKEND_FAILED,
            original_sha256=original_sha256, backend_name=backend_name, warnings=probe_warnings,
        )
        raise wrapped from exc

    if len(payload.data) > max_output_bytes:
        raise RecoveryOutputTooLargeError(
            f"Recovery backend {backend_name!r} returned {len(payload.data)} bytes, "
            f"exceeding the maximum of {max_output_bytes} bytes",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.OUTPUT_TOO_LARGE.value,
                original_sha256=original_sha256,
                recovery_backend=backend_name,
                backend_version=payload.backend_version,
                warnings=[*probe_warnings, *payload.diagnostics],
            ),
        )

    recovered_sha256 = hashlib.sha256(payload.data).hexdigest()
    if recovered_sha256 == original_sha256:
        raise RecoveryVerificationError(
            f"Recovery backend {backend_name!r} returned the input bytes unchanged",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.OUTPUT_UNCHANGED.value,
                original_sha256=original_sha256,
                recovered_sha256=recovered_sha256,
                recovery_backend=backend_name,
                backend_version=payload.backend_version,
                warnings=[*probe_warnings, *payload.diagnostics],
            ),
        )

    try:
        kind = detect_input(payload.data)
    except ParseError as exc:
        raise RecoveryVerificationError(
            f"Recovery backend {backend_name!r} produced output that is not a recognizable "
            f"PSP ELF/PRX: {exc}",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.OUTPUT_INVALID.value,
                original_sha256=original_sha256,
                recovered_sha256=recovered_sha256,
                recovery_backend=backend_name,
                backend_version=payload.backend_version,
                warnings=[*probe_warnings, *payload.diagnostics],
            ),
        ) from exc

    if kind is InputKind.PSP_CONTAINER:
        raise RecoveryVerificationError(
            f"Recovery backend {backend_name!r} produced a still-encrypted ~PSP container; "
            "Phase 8B does not perform multi-stage recovery",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.OUTPUT_STILL_ENCRYPTED.value,
                original_sha256=original_sha256,
                recovered_sha256=recovered_sha256,
                recovery_backend=backend_name,
                backend_version=payload.backend_version,
                warnings=[*probe_warnings, *payload.diagnostics],
            ),
        )

    try:
        model = analyze_bytes(payload.data, source_name="<recovered>")
    except ParseError as exc:
        raise RecoveryVerificationError(
            f"Recovery backend {backend_name!r} produced output that failed ELF/PRX parsing: {exc}",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.OUTPUT_INVALID.value,
                original_sha256=original_sha256,
                recovered_sha256=recovered_sha256,
                recovery_backend=backend_name,
                backend_version=payload.backend_version,
                warnings=[*probe_warnings, *payload.diagnostics],
            ),
        ) from exc

    if model.needs_decryption or model.elf_header is None:
        raise RecoveryVerificationError(
            f"Recovery backend {backend_name!r} produced output that is not a directly "
            "analyzable PSP ELF/PRX",
            provenance=RecoveryProvenance(
                outcome=RecoveryOutcome.OUTPUT_INVALID.value,
                original_sha256=original_sha256,
                recovered_sha256=recovered_sha256,
                recovery_backend=backend_name,
                backend_version=payload.backend_version,
                warnings=[*probe_warnings, *payload.diagnostics],
            ),
        )

    provenance = RecoveryProvenance(
        outcome=RecoveryOutcome.VERIFIED.value,
        original_sha256=original_sha256,
        recovered_sha256=recovered_sha256,
        recovery_backend=backend_name,
        backend_version=payload.backend_version,
        verification="valid_elf32_psp",
        warnings=[*probe_warnings, *payload.diagnostics],
    )
    model.recovery = provenance
    return RecoveryResult(model=model, data=payload.data, provenance=provenance)


def _bounded_diagnostic(raw: bytes | None) -> str:
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace").strip()
    if len(text) > _MAX_DIAGNOSTIC_CHARS:
        text = text[:_MAX_DIAGNOSTIC_CHARS] + "..."
    return text


def _read_bounded_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RecoveryError(f"unable to stat {label}: {path}: {exc}") from exc
    if size > max_bytes:
        raise RecoveryOutputTooLargeError(
            f"{label} exceeds the maximum recovered-output size ({size} > {max_bytes} bytes): {path}"
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RecoveryError(f"unable to read {label}: {path}: {exc}") from exc


def _command_for_path(path: Path) -> list[str]:
    if not path.exists():
        raise RecoveryBackendUnavailableError(f"recovery backend does not exist: {path}")
    if path.is_dir():
        raise RecoveryBackendUnavailableError(
            f"recovery backend path is a directory, not an executable/script: {path}"
        )
    if path.suffix.lower() == ".py":
        return [sys.executable, str(path)]
    return [str(path)]


def resolve_recovery_backend_command(explicit_path: Path | str | None) -> list[str]:
    if explicit_path is not None:
        return _command_for_path(Path(explicit_path))

    configured = os.environ.get("PSPDISASM_RECOVERY_BACKEND")
    if configured:
        return _command_for_path(Path(configured))

    executable = shutil.which("psp-recover")
    if executable:
        return [executable]

    raise RecoveryBackendUnavailableError(
        "no external PSP recovery backend is configured. Pass --recovery-backend PATH, set "
        "PSPDISASM_RECOVERY_BACKEND, or install a psp-recover executable on PATH."
    )


def _detect_backend_version(command: Sequence[str]) -> str | None:
    if not command:
        return None
    candidate = Path(command[-1])
    pyproject = candidate.parent / "pyproject.toml"
    try:
        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        version = payload.get("project", {}).get("version")
        if isinstance(version, str):
            return version
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return None


class ExternalDecryptorBackend:
    """Invokes a user-supplied recovery tool out-of-process.

    The tool is invoked as ``<command> --input INPUT --output OUTPUT`` with no
    shell involved. It must read arbitrary ~PSP bytes from ``--input`` and, on
    success, write a decrypted PSP ELF/PRX to ``--output`` and exit 0. This is
    the entire contract: the MIT core never inspects, links, or bundles the
    tool itself, so it may be GPL-licensed, proprietary, or a thin wrapper
    around PPSSPP/KIRK-compatible tooling the user supplies and is licensed
    to use.
    """

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        name: str | None = None,
        max_output_bytes: int = DEFAULT_MAX_RECOVERED_BYTES,
        timeout_seconds: float = 120.0,
    ) -> None:
        self._command = resolve_recovery_backend_command(path)
        self.name = name or f"external:{' '.join(self._command)}"
        self._max_output_bytes = max_output_bytes
        self._timeout_seconds = timeout_seconds

    def probe(self, header: PspContainerHeader, data: bytes) -> float:
        del header, data
        return 1.0

    def recover(self, data: bytes) -> RecoveredPayload:
        with tempfile.TemporaryDirectory(prefix="pspdisasm-recover-") as temporary:
            temp_dir = Path(temporary)
            input_path = temp_dir / "input.psp"
            output_path = temp_dir / "output.elf"
            input_path.write_bytes(data)
            args = [*self._command, "--input", str(input_path), "--output", str(output_path)]
            try:
                completed = subprocess.run(
                    args,
                    cwd=temp_dir,
                    capture_output=True,
                    timeout=self._timeout_seconds,
                    check=False,
                )
            except OSError as exc:
                raise RecoveryBackendUnavailableError(
                    f"unable to execute recovery backend {self._command[0]!r}: {exc}"
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise RecoveryError(
                    f"recovery backend {self._command[0]!r} timed out after {self._timeout_seconds}s"
                ) from exc

            if completed.returncode != 0:
                detail = _bounded_diagnostic(completed.stderr or completed.stdout)
                suffix = f": {detail}" if detail else ""
                raise RecoveryError(
                    f"recovery backend {self._command[0]!r} exited with code "
                    f"{completed.returncode}{suffix}"
                )
            if not output_path.is_file():
                raise RecoveryError(
                    f"recovery backend {self._command[0]!r} did not produce the expected output file"
                )

            recovered = _read_bounded_file(
                output_path, max_bytes=self._max_output_bytes, label="recovery backend output"
            )
            diagnostics: list[str] = []
            stderr_text = _bounded_diagnostic(completed.stderr)
            if stderr_text:
                diagnostics.append(f"recovery backend wrote diagnostics to stderr: {stderr_text}")
            return RecoveredPayload(
                data=recovered,
                backend_version=_detect_backend_version(self._command),
                diagnostics=diagnostics,
            )


@dataclass(frozen=True, slots=True)
class _PrebuiltEntry:
    original_sha256: str
    recovered_sha256: str
    path: Path


def _safe_manifest_target(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative.replace("\\", "/"))
    if not relative or pure.is_absolute() or ".." in pure.parts:
        raise RecoveryBackendUnavailableError(f"unsafe prebuilt-dump manifest path: {relative}")
    root_resolved = root.resolve()
    literal_target = root_resolved / Path(*pure.parts)
    if literal_target.is_symlink():
        raise RecoveryBackendUnavailableError(
            f"prebuilt-dump manifest path must not be a symlink: {relative}"
        )
    target = literal_target.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise RecoveryBackendUnavailableError(f"unsafe prebuilt-dump manifest path: {relative}")
    return target


def _load_prebuilt_manifest(manifest_path: Path) -> dict[str, _PrebuiltEntry]:
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RecoveryBackendUnavailableError(
            f"prebuilt-dump manifest does not exist: {manifest_path}"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryBackendUnavailableError(
            f"prebuilt-dump manifest is not valid JSON: {manifest_path}: {exc}"
        ) from exc
    if not isinstance(payload, list):
        raise RecoveryBackendUnavailableError(
            f"prebuilt-dump manifest must be a JSON list of objects: {manifest_path}"
        )

    root = manifest_path.resolve().parent
    entries: dict[str, _PrebuiltEntry] = {}
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise RecoveryBackendUnavailableError(
                f"prebuilt-dump manifest entry {index} must be a JSON object: {manifest_path}"
            )
        try:
            original_sha256 = str(item["original_sha256"]).lower()
            recovered_sha256 = str(item["recovered_sha256"]).lower()
            relative_path = str(item["path"])
        except KeyError as exc:
            raise RecoveryBackendUnavailableError(
                f"prebuilt-dump manifest entry {index} is missing {exc.args[0]!r}: {manifest_path}"
            ) from exc
        resolved = _safe_manifest_target(root, relative_path)
        if original_sha256 in entries:
            raise RecoveryBackendUnavailableError(
                f"prebuilt-dump manifest has a duplicate original_sha256: {original_sha256}"
            )
        entries[original_sha256] = _PrebuiltEntry(
            original_sha256=original_sha256,
            recovered_sha256=recovered_sha256,
            path=resolved,
        )
    return entries


class PrebuiltDumpBackend:
    """Verifies and hands over an externally produced decrypted dump.

    The manifest is a JSON list of ``{"original_sha256", "recovered_sha256",
    "path"}`` objects binding both sides of the transformation. This backend
    never decrypts anything itself: it only proves that a specific recovered
    file corresponds to a specific encrypted input by hash, and hands the
    bytes to the same verification gate every other backend goes through.
    ``path`` is resolved relative to the manifest's own directory and is
    rejected if it escapes that directory or resolves through a symlink.
    """

    def __init__(
        self,
        manifest_path: Path | str,
        *,
        max_output_bytes: int = DEFAULT_MAX_RECOVERED_BYTES,
    ) -> None:
        self._manifest_path = Path(manifest_path)
        self._entries = _load_prebuilt_manifest(self._manifest_path)
        self._max_output_bytes = max_output_bytes
        manifest_sha256 = hashlib.sha256(self._manifest_path.read_bytes()).hexdigest()
        self.name = f"prebuilt-dump:{self._manifest_path}:{manifest_sha256[:12]}"

    def probe(self, header: PspContainerHeader, data: bytes) -> float:
        del header
        original_sha256 = hashlib.sha256(data).hexdigest()
        return 1.0 if original_sha256 in self._entries else 0.0

    def recover(self, data: bytes) -> RecoveredPayload:
        original_sha256 = hashlib.sha256(data).hexdigest()
        entry = self._entries.get(original_sha256)
        if entry is None:
            raise RecoveryError(
                f"prebuilt-dump manifest has no entry for original_sha256={original_sha256}"
            )
        if entry.path.is_symlink():
            raise RecoveryError(f"prebuilt-dump recovered file must not be a symlink: {entry.path}")
        if not entry.path.is_file():
            raise RecoveryError(f"prebuilt-dump recovered file does not exist: {entry.path}")

        recovered = _read_bounded_file(
            entry.path, max_bytes=self._max_output_bytes, label="prebuilt-dump recovered file"
        )
        recovered_sha256 = hashlib.sha256(recovered).hexdigest()
        if recovered_sha256 != entry.recovered_sha256:
            raise RecoveryVerificationError(
                f"prebuilt-dump recovered file {entry.path} does not match the manifest "
                "recovered_sha256"
            )
        return RecoveredPayload(data=recovered, backend_version=None, diagnostics=[])
