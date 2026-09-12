from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from pspdisasm.errors import (
    RecoveryBackendUnavailableError,
    RecoveryError,
    RecoveryOutputTooLargeError,
    RecoveryVerificationError,
)
from pspdisasm.model import PspContainerHeader
from pspdisasm.recovery import (
    ExternalDecryptorBackend,
    PrebuiltDumpBackend,
    RecoveredPayload,
    RecoveryOutcome,
    recover_bytes,
    select_recovery_backend,
)
from tests.fixtures import build_allegrex_elf32, build_psp_container_header


@dataclass
class _FakeBackend:
    name: str
    confidence: float
    fail_probe: bool = False

    def probe(self, header: PspContainerHeader, data: bytes) -> float:
        if self.fail_probe:
            raise RuntimeError(f"{self.name} probe failed")
        return self.confidence

    def recover(self, data: bytes) -> RecoveredPayload:
        return RecoveredPayload(data=build_allegrex_elf32())


@dataclass
class _RecoveringBackend:
    """A minimal in-memory backend used to exercise recover_bytes end to end."""

    name: str = "fake"
    payload: bytes = field(default_factory=build_allegrex_elf32)
    version: str | None = "1.0-fake"
    error: Exception | None = None

    def probe(self, header: PspContainerHeader, data: bytes) -> float:
        return 1.0

    def recover(self, data: bytes) -> RecoveredPayload:
        if self.error is not None:
            raise self.error
        return RecoveredPayload(data=self.payload, backend_version=self.version)


HEADER_BYTES = build_psp_container_header()


def _header() -> PspContainerHeader:
    from pspdisasm.psp_container import parse_psp_container_header

    return parse_psp_container_header(HEADER_BYTES)


# ---------------------------------------------------------------------------
# Deterministic backend probing/selection
# ---------------------------------------------------------------------------


def test_select_recovery_backend_picks_highest_confidence():
    backend, confidence, warnings = select_recovery_backend(
        _header(),
        HEADER_BYTES,
        [_FakeBackend("low", 0.6), _FakeBackend("best", 0.95), _FakeBackend("mid", 0.8)],
    )
    assert backend is not None
    assert backend.name == "best"
    assert confidence == pytest.approx(0.95)
    assert warnings == []


def test_select_recovery_backend_ties_break_by_name_then_order():
    backend, confidence, warnings = select_recovery_backend(
        _header(),
        HEADER_BYTES,
        [_FakeBackend("zeta", 0.9), _FakeBackend("alpha", 0.9)],
    )
    assert backend is not None
    assert backend.name == "alpha"
    assert confidence == pytest.approx(0.9)
    assert warnings == []


def test_select_recovery_backend_isolates_probe_exceptions():
    backend, _confidence, warnings = select_recovery_backend(
        _header(),
        HEADER_BYTES,
        [_FakeBackend("broken", 0.99, fail_probe=True), _FakeBackend("ok", 0.7)],
    )
    assert backend is not None
    assert backend.name == "ok"
    assert len(warnings) == 1
    assert "broken" in warnings[0]


def test_select_recovery_backend_rejects_invalid_confidence():
    backend, _confidence, warnings = select_recovery_backend(
        _header(),
        HEADER_BYTES,
        [_FakeBackend("nan", float("nan")), _FakeBackend("too-high", 1.5)],
    )
    assert backend is None
    assert len(warnings) == 2


def test_select_recovery_backend_returns_none_when_no_backends():
    backend, confidence, warnings = select_recovery_backend(_header(), HEADER_BYTES, [])
    assert backend is None
    assert confidence == 0.0
    assert warnings == []


# ---------------------------------------------------------------------------
# recover_bytes: failure classes
# ---------------------------------------------------------------------------


def test_recover_bytes_raises_unavailable_when_no_backend_configured():
    with pytest.raises(RecoveryBackendUnavailableError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.NO_BACKEND_ACCEPTED.value
    assert excinfo.value.provenance.original_sha256 == hashlib.sha256(HEADER_BYTES).hexdigest()


def test_recover_bytes_raises_unavailable_when_no_backend_accepts():
    backend = _FakeBackend("indifferent", 0.0)
    with pytest.raises(RecoveryBackendUnavailableError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.NO_BACKEND_ACCEPTED.value


def test_recover_bytes_reports_backend_execution_failure():
    backend = _RecoveringBackend(error=RuntimeError("boom"))
    with pytest.raises(RecoveryError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.BACKEND_FAILED.value
    assert excinfo.value.provenance.recovery_backend == "fake"


def test_recover_bytes_rejects_oversized_output():
    backend = _RecoveringBackend(payload=b"\x7fELF" + b"\x00" * 32)
    with pytest.raises(RecoveryOutputTooLargeError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend], max_output_bytes=8)
    assert excinfo.value.provenance.outcome == RecoveryOutcome.OUTPUT_TOO_LARGE.value


def test_recover_bytes_rejects_unchanged_output():
    backend = _RecoveringBackend(payload=HEADER_BYTES)
    with pytest.raises(RecoveryVerificationError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.OUTPUT_UNCHANGED.value


def test_recover_bytes_rejects_garbage_output():
    backend = _RecoveringBackend(payload=b"not a real executable at all")
    with pytest.raises(RecoveryVerificationError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.OUTPUT_INVALID.value


def test_recover_bytes_rejects_still_encrypted_output():
    backend = _RecoveringBackend(payload=HEADER_BYTES[:-1] + b"\x01")
    with pytest.raises(RecoveryVerificationError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.OUTPUT_STILL_ENCRYPTED.value


def test_recover_bytes_never_recurses_into_a_second_recovery_pass(monkeypatch):
    backend = _RecoveringBackend(payload=HEADER_BYTES[:-1] + b"\x01")
    calls = []
    original = select_recovery_backend

    def spy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr("pspdisasm.recovery.select_recovery_backend", spy)
    with pytest.raises(RecoveryVerificationError):
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# recover_bytes: success
# ---------------------------------------------------------------------------


def test_recover_bytes_succeeds_for_valid_synthetic_elf():
    backend = _RecoveringBackend()
    result = recover_bytes(HEADER_BYTES, backends=[backend])

    assert result.provenance.outcome == RecoveryOutcome.VERIFIED.value
    assert result.provenance.verification == "valid_elf32_psp"
    assert result.provenance.recovery_backend == "fake"
    assert result.provenance.backend_version == "1.0-fake"
    assert result.provenance.original_sha256 == hashlib.sha256(HEADER_BYTES).hexdigest()
    assert result.provenance.recovered_sha256 == hashlib.sha256(build_allegrex_elf32()).hexdigest()
    assert result.data == build_allegrex_elf32()
    assert result.model.needs_decryption is False
    assert result.model.elf_header is not None
    assert result.model.recovery is result.provenance


# ---------------------------------------------------------------------------
# ExternalDecryptorBackend
# ---------------------------------------------------------------------------


def _write_fake_backend_script(path: Path, *, exit_code: int = 0, write_output: bool = True, output: bytes | None = None) -> Path:
    output_bytes = output if output is not None else build_allegrex_elf32()
    script = f"""
import sys
args = sys.argv[1:]
input_path = args[args.index('--input') + 1]
output_path = args[args.index('--output') + 1]
if {write_output!r}:
    with open(output_path, 'wb') as handle:
        handle.write({output_bytes!r})
raise SystemExit({exit_code})
"""
    path.write_text(script, encoding="utf-8")
    return path


def test_external_decryptor_backend_recovers_via_subprocess(tmp_path):
    script = _write_fake_backend_script(tmp_path / "backend.py")
    backend = ExternalDecryptorBackend(script)

    payload = backend.recover(HEADER_BYTES)

    assert payload.data == build_allegrex_elf32()
    assert payload.backend_version is None


def test_external_decryptor_backend_reports_missing_executable():
    with pytest.raises(RecoveryBackendUnavailableError):
        ExternalDecryptorBackend(Path("/nonexistent/psp-recover-tool"))


def test_external_decryptor_backend_reports_nonzero_exit(tmp_path):
    script = _write_fake_backend_script(tmp_path / "backend.py", exit_code=3, write_output=False)
    backend = ExternalDecryptorBackend(script)

    with pytest.raises(RecoveryError, match="exit"):
        backend.recover(HEADER_BYTES)


def test_external_decryptor_backend_reports_missing_output(tmp_path):
    script = _write_fake_backend_script(tmp_path / "backend.py", write_output=False)
    backend = ExternalDecryptorBackend(script)

    with pytest.raises(RecoveryError, match="output file"):
        backend.recover(HEADER_BYTES)


def test_external_decryptor_backend_rejects_oversized_output_without_full_read(tmp_path, monkeypatch):
    script = tmp_path / "backend.py"
    script.write_text(
        """
import sys
args = sys.argv[1:]
output_path = args[args.index('--output') + 1]
with open(output_path, 'wb') as handle:
    handle.seek(1024 * 1024 - 1)
    handle.write(b'\\x00')
raise SystemExit(0)
""",
        encoding="utf-8",
    )
    backend = ExternalDecryptorBackend(script, max_output_bytes=64)

    read_calls = []
    original_read_bytes = Path.read_bytes

    def spy_read_bytes(self):
        read_calls.append(self)
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)

    with pytest.raises(RecoveryOutputTooLargeError):
        backend.recover(HEADER_BYTES)

    # The oversized backend output file must never be fully read into memory;
    # only the (small) input file may have been read via Path.read_bytes.
    assert all(call.name != "output.elf" for call in read_calls)


def test_external_decryptor_backend_bounds_stderr_diagnostics(tmp_path):
    script = tmp_path / "backend.py"
    script.write_text(
        "import sys\n"
        "sys.stderr.write('x' * 5000)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    backend = ExternalDecryptorBackend(script)
    with pytest.raises(RecoveryError) as excinfo:
        backend.recover(HEADER_BYTES)
    assert len(str(excinfo.value)) < 3000


def test_external_decryptor_backend_accepts_missing_version(tmp_path):
    script = _write_fake_backend_script(tmp_path / "backend.py")
    backend = ExternalDecryptorBackend(script)
    payload = backend.recover(HEADER_BYTES)
    assert payload.backend_version is None


def test_external_decryptor_backend_end_to_end_via_recover_bytes(tmp_path):
    script = _write_fake_backend_script(tmp_path / "backend.py")
    backend = ExternalDecryptorBackend(script)

    result = recover_bytes(HEADER_BYTES, backends=[backend])

    assert result.provenance.outcome == RecoveryOutcome.VERIFIED.value
    assert result.data == build_allegrex_elf32()


# ---------------------------------------------------------------------------
# PrebuiltDumpBackend
# ---------------------------------------------------------------------------


def _write_manifest(tmp_path: Path, entries: list[dict]) -> Path:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(entries), encoding="utf-8")
    return manifest


def test_prebuilt_dump_backend_recovers_matching_entry(tmp_path):
    recovered_bytes = build_allegrex_elf32()
    recovered_file = tmp_path / "dump" / "recovered.elf"
    recovered_file.parent.mkdir(parents=True)
    recovered_file.write_bytes(recovered_bytes)

    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": hashlib.sha256(recovered_bytes).hexdigest(),
                "path": "dump/recovered.elf",
            }
        ],
    )
    backend = PrebuiltDumpBackend(manifest)

    result = recover_bytes(HEADER_BYTES, backends=[backend])
    assert result.provenance.outcome == RecoveryOutcome.VERIFIED.value
    assert result.data == recovered_bytes


def test_prebuilt_dump_backend_rejects_original_hash_mismatch(tmp_path):
    recovered_bytes = build_allegrex_elf32()
    recovered_file = tmp_path / "recovered.elf"
    recovered_file.write_bytes(recovered_bytes)
    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": "0" * 64,
                "recovered_sha256": hashlib.sha256(recovered_bytes).hexdigest(),
                "path": "recovered.elf",
            }
        ],
    )
    backend = PrebuiltDumpBackend(manifest)

    with pytest.raises(RecoveryBackendUnavailableError) as excinfo:
        recover_bytes(HEADER_BYTES, backends=[backend])
    assert excinfo.value.provenance.outcome == RecoveryOutcome.NO_BACKEND_ACCEPTED.value


def test_prebuilt_dump_backend_rejects_recovered_hash_mismatch(tmp_path):
    recovered_bytes = build_allegrex_elf32()
    recovered_file = tmp_path / "recovered.elf"
    recovered_file.write_bytes(recovered_bytes)
    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": "0" * 64,
                "path": "recovered.elf",
            }
        ],
    )
    backend = PrebuiltDumpBackend(manifest)

    with pytest.raises(RecoveryVerificationError, match="recovered_sha256"):
        backend.recover(HEADER_BYTES)


def test_prebuilt_dump_backend_rejects_path_traversal(tmp_path):
    outside = tmp_path.parent / "outside.elf"
    outside.write_bytes(build_allegrex_elf32())
    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": hashlib.sha256(build_allegrex_elf32()).hexdigest(),
                "path": "../outside.elf",
            }
        ],
    )
    with pytest.raises(RecoveryBackendUnavailableError, match="unsafe"):
        PrebuiltDumpBackend(manifest)


def test_prebuilt_dump_backend_rejects_absolute_path(tmp_path):
    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": "0" * 64,
                "path": "/etc/passwd",
            }
        ],
    )
    with pytest.raises(RecoveryBackendUnavailableError, match="unsafe"):
        PrebuiltDumpBackend(manifest)


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="platform lacks symlink support")
def test_prebuilt_dump_backend_rejects_symlink_escape(tmp_path):
    real_target = tmp_path.parent / "real_secret.elf"
    real_target.write_bytes(build_allegrex_elf32())
    link = tmp_path / "linked.elf"
    try:
        link.symlink_to(real_target)
    except OSError:
        pytest.skip("symlinks are not permitted in this environment")

    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": hashlib.sha256(build_allegrex_elf32()).hexdigest(),
                "path": "linked.elf",
            }
        ],
    )
    with pytest.raises(RecoveryBackendUnavailableError, match="symlink"):
        PrebuiltDumpBackend(manifest)


def test_prebuilt_dump_backend_probe_reflects_manifest_membership(tmp_path):
    recovered_file = tmp_path / "recovered.elf"
    recovered_file.write_bytes(build_allegrex_elf32())
    manifest = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": hashlib.sha256(build_allegrex_elf32()).hexdigest(),
                "path": "recovered.elf",
            }
        ],
    )
    backend = PrebuiltDumpBackend(manifest)
    assert backend.probe(_header(), HEADER_BYTES) == 1.0
    assert backend.probe(_header(), b"~PSP" + b"\x00" * 336) == 0.0


def test_prebuilt_dump_backend_name_changes_with_manifest_content(tmp_path):
    recovered_file = tmp_path / "recovered.elf"
    recovered_file.write_bytes(build_allegrex_elf32())
    manifest_a = _write_manifest(
        tmp_path,
        [
            {
                "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                "recovered_sha256": hashlib.sha256(build_allegrex_elf32()).hexdigest(),
                "path": "recovered.elf",
            }
        ],
    )
    name_a = PrebuiltDumpBackend(manifest_a).name

    manifest_a.write_text(
        json.dumps(
            [
                {
                    "original_sha256": hashlib.sha256(HEADER_BYTES).hexdigest(),
                    "recovered_sha256": hashlib.sha256(build_allegrex_elf32()).hexdigest(),
                    "path": "recovered.elf",
                },
                {
                    "original_sha256": "1" * 64,
                    "recovered_sha256": "2" * 64,
                    "path": "recovered.elf",
                },
            ]
        ),
        encoding="utf-8",
    )
    name_b = PrebuiltDumpBackend(manifest_a).name
    assert name_a != name_b
