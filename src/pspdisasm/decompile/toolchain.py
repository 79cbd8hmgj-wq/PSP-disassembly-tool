from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence, runtime_checkable

from ..errors import BuildFailedError, BuildToolchainUnavailableError

_MAX_DIAGNOSTIC_CHARS = 500


def _bounded(text: str, limit: int = _MAX_DIAGNOSTIC_CHARS) -> str:
    text = text.strip()
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(slots=True)
class BuildResult:
    output_path: Path
    object_sha256: str
    diagnostics: list[str] = field(default_factory=list)


@runtime_checkable
class BuildToolchain(Protocol):
    name: str

    def identity(self) -> dict[str, object]: ...

    def compile_function(
        self, source: Path, *, output: Path, project: Path, timeout: float
    ) -> BuildResult: ...


class ExternalCompilerToolchain:
    """Invokes a user-supplied compiler directly on one translation unit.

    There is no universal PSP compiler, so unlike most backends in this
    codebase there is no PATH-searched default executable name: the caller
    must supply an explicit path or PSPDISASM_BUILD_COMPILER.
    """

    def __init__(
        self,
        compiler_path: Path | str | None = None,
        *,
        flags: Sequence[str] = (),
        name: str | None = None,
        timeout_default: float = 60.0,
    ) -> None:
        resolved = compiler_path if compiler_path is not None else os.environ.get("PSPDISASM_BUILD_COMPILER")
        if not resolved:
            raise BuildToolchainUnavailableError(
                "no build compiler is configured. Pass a compiler path or set PSPDISASM_BUILD_COMPILER."
            )
        path = Path(resolved)
        if path.is_dir() or not path.exists():
            raise BuildToolchainUnavailableError(f"build compiler does not exist: {path}")
        self._compiler = str(path.resolve())
        self._flags = list(flags)
        self.name = name or f"external-compiler:{self._compiler}"
        self._timeout_default = timeout_default

    def identity(self) -> dict[str, object]:
        compiler_path = Path(self._compiler)
        compiler_sha256 = _hash_file(compiler_path) if compiler_path.is_file() else None
        return {
            "kind": "external_compiler",
            "compiler": self._compiler,
            "compiler_sha256": compiler_sha256,
            "flags": list(self._flags),
        }

    def compile_function(self, source: Path, *, output: Path, project: Path, timeout: float) -> BuildResult:
        output.parent.mkdir(parents=True, exist_ok=True)
        args = [self._compiler, *self._flags, "-c", str(source), "-o", str(output)]
        try:
            completed = subprocess.run(
                args,
                cwd=project,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BuildFailedError(f"build compiler timed out after {timeout:g} seconds") from exc
        except OSError as exc:
            raise BuildToolchainUnavailableError(f"unable to execute build compiler {self._compiler!r}: {exc}") from exc

        diagnostics: list[str] = []
        stderr_text = _bounded(completed.stderr) if completed.stderr else ""
        if stderr_text:
            diagnostics.append(stderr_text)

        if completed.returncode != 0:
            detail = _bounded(completed.stderr or completed.stdout)
            suffix = f": {detail}" if detail else ""
            raise BuildFailedError(f"build compiler exited with code {completed.returncode}{suffix}")
        if not output.is_file():
            raise BuildFailedError(f"build compiler did not produce the expected output: {output}")

        return BuildResult(output_path=output, object_sha256=_hash_file(output), diagnostics=diagnostics)


class ProjectBuildCommandToolchain:
    """Runs the project's own build system (e.g. a Splat-generated Makefile rule) for one function.

    `command_template`/`output_template` may contain a `{function}` placeholder,
    substituted with the source file's stem. The command is parsed with
    shlex.split and run as an argument array (never shell=True), matching
    matcher.py's existing --build-command convention exactly. The toolchain's
    own resolved output path (from `output_template`) is authoritative; the
    caller's requested `output` is a hint only, since a build system chooses
    its own output location.
    """

    def __init__(
        self,
        command_template: str,
        output_template: str,
        *,
        name: str | None = None,
        timeout_default: float = 120.0,
    ) -> None:
        if not command_template.strip():
            raise BuildToolchainUnavailableError("build command template must not be empty")
        if not output_template.strip():
            raise BuildToolchainUnavailableError("build output template must not be empty")
        self._command_template = command_template
        self._output_template = output_template
        self.name = name or f"project-build-command:{command_template}"
        self._timeout_default = timeout_default

    def identity(self) -> dict[str, object]:
        identity: dict[str, object] = {
            "kind": "project_build_command",
            "command_template": self._command_template,
            "output_template": self._output_template,
        }
        try:
            first_token = shlex.split(self._command_template)[0]
        except ValueError:
            first_token = None
        if first_token:
            candidate = Path(first_token)
            if candidate.is_file():
                identity["command_sha256"] = _hash_file(candidate)
        return identity

    def compile_function(self, source: Path, *, output: Path, project: Path, timeout: float) -> BuildResult:
        del output  # this toolchain's own output_template is authoritative; see class docstring
        function_stem = source.stem
        try:
            command = shlex.split(self._command_template.format(function=function_stem))
        except (ValueError, KeyError) as exc:
            raise BuildToolchainUnavailableError(f"invalid build command template: {exc}") from exc
        if not command:
            raise BuildToolchainUnavailableError("build command template resolved to an empty command")

        try:
            completed = subprocess.run(
                command,
                cwd=project,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BuildFailedError(f"build command timed out after {timeout:g} seconds") from exc
        except OSError as exc:
            raise BuildToolchainUnavailableError(f"unable to execute build command {command[0]!r}: {exc}") from exc

        diagnostics: list[str] = []
        stderr_text = _bounded(completed.stderr) if completed.stderr else ""
        if stderr_text:
            diagnostics.append(stderr_text)

        if completed.returncode != 0:
            detail = _bounded(completed.stderr or completed.stdout)
            suffix = f": {detail}" if detail else ""
            raise BuildFailedError(f"build command exited with code {completed.returncode}{suffix}")

        resolved_output = project / self._output_template.format(function=function_stem)
        if not resolved_output.is_file():
            raise BuildFailedError(f"build command did not produce the expected output: {resolved_output}")

        return BuildResult(output_path=resolved_output, object_sha256=_hash_file(resolved_output), diagnostics=diagnostics)
