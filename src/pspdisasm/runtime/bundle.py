from __future__ import annotations

import configparser
import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..errors import RuntimeBackendUnavailableError

_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class DebuggerBundleProfile:
    """What a caller expects of a PPSSPP install before pspdisasm launches it.

    Every field is optional except `executable_relative`: unlike a
    single-game project's pinned bundle, the toolkit does not know in
    advance how a user's PPSSPP build is packaged, so only checks the
    caller actually supplies are enforced.
    """

    executable_relative: str
    expected_sha256: str | None = None
    expected_revision: str | None = None
    revision_relative: str | None = None
    config_relative: str | None = None
    expected_port: int | None = None


@dataclass(frozen=True, slots=True)
class DebuggerBundleIdentity:
    root: Path
    executable_path: Path
    executable_sha256: str
    revision: str | None
    port: int | None


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _required_file(root: Path, relative: str, label: str) -> Path:
    path = root / relative
    if path.is_symlink():
        raise RuntimeBackendUnavailableError(f"{label} must not be a symlink: {relative}")
    if not path.is_file():
        raise RuntimeBackendUnavailableError(f"{label} is missing: {relative}")
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeBackendUnavailableError(f"{label} escapes the bundle root: {relative}") from exc
    return resolved


def _verify_debug_config(config_path: Path, expected_port: int | None) -> int | None:
    parser = configparser.ConfigParser()
    try:
        with config_path.open("r", encoding="utf-8") as stream:
            parser.read_file(stream)
    except (OSError, configparser.Error) as exc:
        raise RuntimeBackendUnavailableError(f"invalid PPSSPP debug config: {exc}") from exc
    if not parser.has_section("General"):
        raise RuntimeBackendUnavailableError("PPSSPP debug config is missing [General]")
    try:
        on_startup = parser.getboolean("General", "RemoteDebuggerOnStartup")
        local_only = parser.getboolean("General", "RemoteDebuggerLocal")
        port = parser.getint("General", "RemoteISOPort")
    except (ValueError, configparser.Error) as exc:
        raise RuntimeBackendUnavailableError(f"invalid PPSSPP debugger port/startup settings: {exc}") from exc
    if not on_startup:
        raise RuntimeBackendUnavailableError("PPSSPP remote debugger must start automatically")
    if not local_only:
        raise RuntimeBackendUnavailableError("PPSSPP remote debugger must be configured local-only")
    if not 1 <= port <= 65535:
        raise RuntimeBackendUnavailableError("PPSSPP RemoteISOPort must be between 1 and 65535")
    if expected_port is not None and port != expected_port:
        raise RuntimeBackendUnavailableError(
            f"expected PPSSPP debugger port {expected_port}, observed {port}"
        )
    return port


def verify_ppsspp_bundle(root: Path | str, *, profile: DebuggerBundleProfile) -> DebuggerBundleIdentity:
    """Verify a user-supplied PPSSPP install matches the caller's own expectations.

    Unlike a single-game project's bundle verifier, this makes no assumption
    about bundle layout (no hard-coded SDL/Headless/Xvfb filenames): the
    caller names the one executable it cares about and, optionally, a
    revision file and/or debug-config file to check. Every hash/revision/port
    check is skipped when the caller did not supply an expectation for it,
    since the toolkit itself has no opinion on what a "correct" PPSSPP build
    looks like.
    """
    resolved_root = Path(root)
    if resolved_root.is_symlink():
        raise RuntimeBackendUnavailableError("bundle root must not be a symlink")
    resolved_root = resolved_root.expanduser().resolve()
    if not resolved_root.is_dir():
        raise RuntimeBackendUnavailableError(f"bundle root is not a directory: {root}")

    executable_path = _required_file(resolved_root, profile.executable_relative, "PPSSPP executable")
    executable_sha256 = _hash_file(executable_path)
    if profile.expected_sha256 is not None and executable_sha256 != profile.expected_sha256:
        raise RuntimeBackendUnavailableError(
            f"PPSSPP executable hash mismatch: expected {profile.expected_sha256}, "
            f"observed {executable_sha256}"
        )

    revision: str | None = None
    if profile.revision_relative is not None:
        revision_path = _required_file(resolved_root, profile.revision_relative, "PPSSPP revision file")
        revision = revision_path.read_text(encoding="utf-8").strip()
        if profile.expected_revision is not None and revision != profile.expected_revision:
            raise RuntimeBackendUnavailableError(
                f"PPSSPP revision mismatch: expected {profile.expected_revision}, observed {revision}"
            )

    port: int | None = None
    if profile.config_relative is not None:
        config_path = _required_file(resolved_root, profile.config_relative, "PPSSPP debug config")
        port = _verify_debug_config(config_path, profile.expected_port)

    return DebuggerBundleIdentity(
        root=resolved_root,
        executable_path=executable_path,
        executable_sha256=executable_sha256,
        revision=revision,
        port=port,
    )
