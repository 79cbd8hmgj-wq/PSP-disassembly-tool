from __future__ import annotations

import hashlib

import pytest

from pspdisasm.errors import RuntimeBackendUnavailableError
from pspdisasm.runtime.bundle import DebuggerBundleProfile, verify_ppsspp_bundle


def test_verify_bundle_minimal_profile_only_checks_executable_exists(tmp_path):
    executable = tmp_path / "ppsspp-headless"
    executable.write_bytes(b"fake binary")

    identity = verify_ppsspp_bundle(tmp_path, profile=DebuggerBundleProfile(executable_relative="ppsspp-headless"))

    assert identity.executable_path == executable.resolve()
    assert identity.executable_sha256 == hashlib.sha256(b"fake binary").hexdigest()
    assert identity.revision is None
    assert identity.port is None


def test_verify_bundle_rejects_missing_executable(tmp_path):
    with pytest.raises(RuntimeBackendUnavailableError, match="missing"):
        verify_ppsspp_bundle(tmp_path, profile=DebuggerBundleProfile(executable_relative="nope"))


def test_verify_bundle_rejects_symlinked_executable(tmp_path):
    real = tmp_path.parent / "real-ppsspp"
    real.write_bytes(b"data")
    link = tmp_path / "ppsspp-headless"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks are not permitted in this environment")

    with pytest.raises(RuntimeBackendUnavailableError, match="symlink"):
        verify_ppsspp_bundle(tmp_path, profile=DebuggerBundleProfile(executable_relative="ppsspp-headless"))


def test_verify_bundle_checks_hash_when_supplied(tmp_path):
    executable = tmp_path / "ppsspp-headless"
    executable.write_bytes(b"fake binary")

    with pytest.raises(RuntimeBackendUnavailableError, match="hash mismatch"):
        verify_ppsspp_bundle(
            tmp_path,
            profile=DebuggerBundleProfile(executable_relative="ppsspp-headless", expected_sha256="0" * 64),
        )


def test_verify_bundle_checks_revision_when_supplied(tmp_path):
    executable = tmp_path / "ppsspp-headless"
    executable.write_bytes(b"fake binary")
    (tmp_path / "revision.txt").write_text("abc123\n", encoding="utf-8")

    identity = verify_ppsspp_bundle(
        tmp_path,
        profile=DebuggerBundleProfile(
            executable_relative="ppsspp-headless",
            revision_relative="revision.txt",
            expected_revision="abc123",
        ),
    )
    assert identity.revision == "abc123"

    with pytest.raises(RuntimeBackendUnavailableError, match="revision mismatch"):
        verify_ppsspp_bundle(
            tmp_path,
            profile=DebuggerBundleProfile(
                executable_relative="ppsspp-headless",
                revision_relative="revision.txt",
                expected_revision="different",
            ),
        )


def test_verify_bundle_rejects_unsafe_startup_config(tmp_path):
    executable = tmp_path / "ppsspp-headless"
    executable.write_bytes(b"fake binary")
    config = tmp_path / "ppsspp-debug.ini"
    config.write_text(
        "[General]\nRemoteDebuggerOnStartup = False\nRemoteDebuggerLocal = True\nRemoteISOPort = 56244\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeBackendUnavailableError, match="start automatically"):
        verify_ppsspp_bundle(
            tmp_path,
            profile=DebuggerBundleProfile(executable_relative="ppsspp-headless", config_relative="ppsspp-debug.ini"),
        )


def test_verify_bundle_rejects_non_local_debugger(tmp_path):
    executable = tmp_path / "ppsspp-headless"
    executable.write_bytes(b"fake binary")
    config = tmp_path / "ppsspp-debug.ini"
    config.write_text(
        "[General]\nRemoteDebuggerOnStartup = True\nRemoteDebuggerLocal = False\nRemoteISOPort = 56244\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeBackendUnavailableError, match="local-only"):
        verify_ppsspp_bundle(
            tmp_path,
            profile=DebuggerBundleProfile(executable_relative="ppsspp-headless", config_relative="ppsspp-debug.ini"),
        )


def test_verify_bundle_accepts_safe_config_and_checks_port(tmp_path):
    executable = tmp_path / "ppsspp-headless"
    executable.write_bytes(b"fake binary")
    config = tmp_path / "ppsspp-debug.ini"
    config.write_text(
        "[General]\nRemoteDebuggerOnStartup = True\nRemoteDebuggerLocal = True\nRemoteISOPort = 56244\n",
        encoding="utf-8",
    )

    identity = verify_ppsspp_bundle(
        tmp_path,
        profile=DebuggerBundleProfile(
            executable_relative="ppsspp-headless", config_relative="ppsspp-debug.ini", expected_port=56244
        ),
    )
    assert identity.port == 56244

    with pytest.raises(RuntimeBackendUnavailableError, match="expected PPSSPP debugger port"):
        verify_ppsspp_bundle(
            tmp_path,
            profile=DebuggerBundleProfile(
                executable_relative="ppsspp-headless", config_relative="ppsspp-debug.ini", expected_port=1
            ),
        )
