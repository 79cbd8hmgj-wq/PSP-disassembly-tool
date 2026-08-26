from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from typing import Iterable, Sequence

from .errors import DecompilationError, DecompilerUnavailableError
from .model import DecompilationResult


DEFAULT_M2C_TARGET = "mipsel-gcc-c"
_UNKNOWN_INSTRUCTION_RE = re.compile(r"unknown instruction:\s*(.*?)\s*\*/", re.IGNORECASE)
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(slots=True)
class ProjectFunction:
    name: str
    address: int
    size: int
    section: str
    assembly: str
    instruction_count: int


def _functions_path(project_dir: Path) -> Path:
    return project_dir / "metadata" / "functions.json"


def _load_project_functions(project_dir: Path) -> list[ProjectFunction]:
    path = _functions_path(project_dir)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DecompilationError(f"Phase 3 project metadata is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise DecompilationError(f"Unable to read valid project function metadata from {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise DecompilationError(f"Project metadata {path} must contain a JSON list of functions.")

    functions: list[ProjectFunction] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise DecompilationError(f"Function entry {index} in {path} must be a JSON object.")
        try:
            name = item["name"]
            address = item["address"]
            size = item["size"]
            section = item["section"]
            assembly = item["assembly"]
            instruction_count = item["instruction_count"]
        except KeyError as exc:
            raise DecompilationError(f"Function entry {index} in {path} is missing {exc.args[0]!r}.") from exc
        if not isinstance(name, str) or not isinstance(section, str) or not isinstance(assembly, str):
            raise DecompilationError(f"Function entry {index} in {path} has invalid text fields.")
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (address, size, instruction_count)):
            raise DecompilationError(f"Function entry {index} in {path} has invalid numeric fields.")
        functions.append(
            ProjectFunction(
                name=name,
                address=address,
                size=size,
                section=section,
                assembly=assembly,
                instruction_count=instruction_count,
            )
        )
    return functions


def resolve_project_function(project_dir: Path | str, selector: str) -> ProjectFunction:
    project = Path(project_dir)
    functions = _load_project_functions(project)

    by_name = [function for function in functions if function.name == selector]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        raise DecompilationError(f"Function selector {selector!r} is ambiguous in {_functions_path(project)}.")

    address: int | None = None
    try:
        address = int(selector, 0)
    except ValueError:
        if selector.isdecimal():
            address = int(selector, 10)
    if address is not None:
        by_address = [function for function in functions if function.address == address]
        if len(by_address) == 1:
            return by_address[0]
        if len(by_address) > 1:
            raise DecompilationError(f"Function address 0x{address:08X} is ambiguous in {_functions_path(project)}.")

    raise DecompilationError(f"Function {selector!r} was not found in {_functions_path(project)}.")


def _command_for_path(path: Path) -> list[str]:
    if not path.exists():
        raise DecompilerUnavailableError(f"m2c backend does not exist: {path}")
    if path.is_dir():
        raise DecompilerUnavailableError(f"m2c backend path is a directory, not an executable/script: {path}")
    if path.suffix.lower() == ".py":
        return [sys.executable, str(path)]
    return [str(path)]


def resolve_m2c_command(explicit_path: Path | str | None) -> list[str]:
    if explicit_path is not None:
        return _command_for_path(Path(explicit_path))

    configured = os.environ.get("PSPDISASM_M2C")
    if configured:
        return _command_for_path(Path(configured))

    executable = shutil.which("m2c")
    if executable:
        return [executable]

    raise DecompilerUnavailableError(
        "m2c is required for assisted C decompilation. Pass --m2c PATH, set PSPDISASM_M2C, "
        "or install an m2c executable on PATH."
    )


def _detect_m2c_version(command: Sequence[str]) -> str | None:
    if not command:
        return None
    candidate = Path(command[-1])
    if candidate.name == "m2c.py":
        pyproject = candidate.parent / "pyproject.toml"
        try:
            payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            version = payload.get("project", {}).get("version")
            if isinstance(version, str):
                return version
        except (OSError, tomllib.TOMLDecodeError):
            return None
    return None


def _safe_stem(function: ProjectFunction) -> str:
    stem = _SAFE_FILENAME_RE.sub("_", function.name).strip("._")
    return stem or f"func_{function.address:08X}"


def _extract_unsupported_instructions(c_source: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for match in _UNKNOWN_INSTRUCTION_RE.finditer(c_source):
        instruction = " ".join(match.group(1).split())
        if instruction and instruction not in seen:
            seen.add(instruction)
            result.append(instruction)
    return result


def _relative_or_string(path: Path, project: Path) -> str:
    try:
        return path.relative_to(project).as_posix()
    except ValueError:
        return str(path)


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _run_m2c(
    command: Sequence[str],
    function: ProjectFunction,
    *,
    target: str,
    contexts: Sequence[Path],
    project: Path,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="pspdisasm-m2c-") as temporary:
        asm_path = Path(temporary) / f"{_safe_stem(function)}.s"
        asm_path.write_text(function.assembly, encoding="utf-8")
        args = [
            *command,
            "-t",
            target,
            "--valid-syntax",
            "--deterministic-vars",
            "--no-cache",
            "--globals=used",
            "-f",
            function.name,
        ]
        for context in contexts:
            args.extend(["--context", str(context)])
        args.append(str(asm_path))
        try:
            return subprocess.run(
                args,
                cwd=project,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            raise DecompilerUnavailableError(f"Unable to execute m2c backend {command[0]!r}: {exc}") from exc


def decompile_project_function(
    project_dir: Path | str,
    selector: str,
    *,
    m2c_path: Path | str | None = None,
    contexts: Iterable[Path | str] = (),
    output_path: Path | str | None = None,
    target: str = DEFAULT_M2C_TARGET,
) -> DecompilationResult:
    project = Path(project_dir).resolve()
    function = resolve_project_function(project, selector)
    command = resolve_m2c_command(m2c_path)
    context_paths = [Path(context).resolve() for context in contexts]
    for context in context_paths:
        if not context.is_file():
            raise DecompilationError(f"m2c context file does not exist: {context}")

    completed = _run_m2c(command, function, target=target, contexts=context_paths, project=project)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if len(detail) > 500:
            detail = detail[:500] + "..."
        suffix = f": {detail}" if detail else ""
        raise DecompilationError(f"m2c failed for {function.name} with exit code {completed.returncode}{suffix}")

    c_source = completed.stdout
    unsupported = _extract_unsupported_instructions(c_source)
    warnings: list[str] = []
    if unsupported:
        warnings.append(
            f"m2c reported {len(unsupported)} unsupported PSP/Allegrex instruction(s); "
            "the generated C is an assisted draft and contains M2C_ERROR markers."
        )
    if completed.stderr.strip():
        warnings.append("m2c wrote diagnostic output to stderr; inspect metadata or rerun m2c directly if needed.")

    stem = _safe_stem(function)
    if output_path is None:
        c_path = project / "src" / "nonmatching" / f"{stem}.c"
    else:
        requested = Path(output_path)
        c_path = requested if requested.is_absolute() else project / requested
    assembly_path = project / "asm" / "nonmatchings" / f"{stem}.s"
    metadata_path = project / "metadata" / "decompilations" / f"{stem}.json"

    backend_version = _detect_m2c_version(command)
    metadata = {
        "backend": {"name": "m2c", "version": backend_version},
        "target": target,
        "function": {
            "name": function.name,
            "address": function.address,
            "size": function.size,
            "section": function.section,
            "instruction_count": function.instruction_count,
        },
        "artifacts": {
            "assembly": _relative_or_string(assembly_path, project),
            "c": _relative_or_string(c_path, project),
        },
        "contexts": [_relative_or_string(context, project) for context in context_paths],
        "warnings": warnings,
        "unsupported_instructions": unsupported,
    }

    _atomic_write_text(assembly_path, function.assembly)
    _atomic_write_text(c_path, c_source)
    _atomic_write_text(metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    return DecompilationResult(
        project_dir=project,
        function_name=function.name,
        function_address=function.address,
        output_path=c_path,
        assembly_path=assembly_path,
        metadata_path=metadata_path,
        backend_name="m2c",
        backend_version=backend_version,
        target=target,
        warnings=warnings,
        unsupported_instructions=unsupported,
    )
