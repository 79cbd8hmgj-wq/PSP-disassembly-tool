from __future__ import annotations

from pathlib import Path, PurePosixPath
import subprocess
import sys


OPAQUE_BINARY_LIMIT = 16 * 1024 * 1024

_BLOCKED_SUFFIXES = {
    ".iso",
    ".cso",
    ".zso",
    ".dax",
    ".ppst",
    ".savestate",
    ".memdump",
}

_OPAQUE_BINARY_SUFFIXES = {
    ".bin",
    ".dat",
    ".arc",
    ".pak",
    ".pac",
    ".pkg",
    ".big",
    ".viv",
    ".zlb",
    ".prx",
    ".elf",
}


def _normalize(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _is_small_test_fixture(path: str, size: int) -> bool:
    normalized = _normalize(path).casefold()
    return normalized.startswith("tests/fixtures/") and size <= OPAQUE_BINARY_LIMIT


def _is_generated_payload_tree(path: str) -> bool:
    normalized = _normalize(path).casefold()
    pure = PurePosixPath(normalized)
    parts = pure.parts
    if ".pspdisasm-workspace" in parts:
        return True
    if len(parts) >= 2 and parts[0] == "workspace" and parts[1] in {"cache", "packs"}:
        return True
    if normalized.startswith("workspace/analysis/game_project/resources/files/"):
        return True
    if normalized.startswith("resources/files/"):
        return True
    return False


def violation_for(path: str, size: int) -> str | None:
    """Return a deterministic policy violation for one tracked path, if any."""
    normalized = _normalize(path)
    if _is_small_test_fixture(normalized, size):
        return None
    suffix = PurePosixPath(normalized).suffix.casefold()
    if suffix in _BLOCKED_SUFFIXES:
        return f"blocked retail/runtime payload suffix {suffix}: {normalized}"
    if _is_generated_payload_tree(normalized):
        return f"blocked generated game/workspace payload path: {normalized}"
    if suffix in _OPAQUE_BINARY_SUFFIXES and size > OPAQUE_BINARY_LIMIT:
        return (
            f"oversized opaque binary ({size} > {OPAQUE_BINARY_LIMIT} bytes): "
            f"{normalized}"
        )
    return None


def _tracked_paths() -> list[Path]:
    try:
        output = subprocess.run(
            ["git", "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"unable to enumerate tracked repository files: {exc}") from exc
    paths: list[Path] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        paths.append(Path(raw.decode("utf-8", errors="surrogateescape")))
    return paths


def main() -> int:
    violations: list[str] = []
    for path in _tracked_paths():
        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
        except OSError as exc:
            violations.append(f"unable to inspect tracked file {path.as_posix()}: {exc}")
            continue
        violation = violation_for(path.as_posix(), size)
        if violation is not None:
            violations.append(violation)

    if violations:
        print("Repository payload guard rejected tracked content:", file=sys.stderr)
        for violation in sorted(violations, key=str.casefold):
            print(f"- {violation}", file=sys.stderr)
        return 1
    print("Repository payload guard: tracked content is clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
