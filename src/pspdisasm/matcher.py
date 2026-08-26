from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Iterable, Sequence

from .errors import MatcherUnavailableError, MatchingError


_SAFE_FILENAME = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"


@dataclass(slots=True, frozen=True)
class MatchInstruction:
    address: int
    word: int
    text: str
    valid: bool
    implemented: bool


@dataclass(slots=True, frozen=True)
class MatchFunction:
    name: str
    address: int
    size: int
    section: str
    instruction_count: int
    instructions: tuple[MatchInstruction, ...]


@dataclass(slots=True)
class MatchResult:
    project_dir: Path
    function_name: str
    function_address: int
    candidate_object: Path
    reference_object: Path
    metadata_path: Path
    raw_report_path: Path
    backend_name: str
    backend_version: str | None
    objdump: str
    raw_score: int
    max_score: int
    similarity_percent: float
    matching_rows: int
    changed_rows: int
    added_rows: int
    removed_rows: int
    warnings: list[str] = field(default_factory=list)


def _functions_path(project: Path) -> Path:
    return project / "metadata" / "functions.json"


def _require_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise MatchingError(f"{label} must be an integer.")
    return value


def _load_functions(project: Path) -> list[MatchFunction]:
    path = _functions_path(project)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MatchingError(f"Phase 3 project metadata is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise MatchingError(f"Unable to read valid project function metadata from {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise MatchingError(f"Project metadata {path} must contain a JSON list of functions.")

    result: list[MatchFunction] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise MatchingError(f"Function entry {index} in {path} must be a JSON object.")
        try:
            name = item["name"]
            address = _require_int(item["address"], f"Function entry {index} address")
            size = _require_int(item["size"], f"Function entry {index} size")
            section = item["section"]
            instruction_count = _require_int(item["instruction_count"], f"Function entry {index} instruction_count")
            raw_instructions = item["instructions"]
        except KeyError as exc:
            raise MatchingError(f"Function entry {index} in {path} is missing {exc.args[0]!r}.") from exc
        if not isinstance(name, str) or not isinstance(section, str):
            raise MatchingError(f"Function entry {index} in {path} has invalid text fields.")
        if not isinstance(raw_instructions, list):
            raise MatchingError(f"Function entry {index} in {path} must contain an instruction list.")

        instructions: list[MatchInstruction] = []
        for instruction_index, raw in enumerate(raw_instructions):
            if not isinstance(raw, dict):
                raise MatchingError(f"Instruction {instruction_index} for {name} must be a JSON object.")
            try:
                inst_address = _require_int(raw["address"], f"Instruction {instruction_index} address")
                word = _require_int(raw["word"], f"Instruction {instruction_index} word")
                text = raw["text"]
                valid = raw["valid"]
                implemented = raw["implemented"]
            except KeyError as exc:
                raise MatchingError(f"Instruction {instruction_index} for {name} is missing {exc.args[0]!r}.") from exc
            if not isinstance(text, str) or not isinstance(valid, bool) or not isinstance(implemented, bool):
                raise MatchingError(f"Instruction {instruction_index} for {name} has invalid fields.")
            if not 0 <= word <= 0xFFFFFFFF:
                raise MatchingError(f"Instruction {instruction_index} for {name} has a word outside uint32 range.")
            instructions.append(MatchInstruction(inst_address, word, text, valid, implemented))

        if instruction_count != len(instructions):
            raise MatchingError(
                f"Function {name} declares {instruction_count} instructions but metadata contains {len(instructions)}."
            )
        result.append(MatchFunction(name, address, size, section, instruction_count, tuple(instructions)))
    return result


def resolve_match_function(project_dir: Path | str, selector: str) -> MatchFunction:
    project = Path(project_dir)
    functions = _load_functions(project)
    by_name = [function for function in functions if function.name == selector]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        raise MatchingError(f"Function selector {selector!r} is ambiguous in {_functions_path(project)}.")

    try:
        address = int(selector, 0)
    except ValueError:
        address = int(selector, 10) if selector.isdecimal() else None
    if address is not None:
        by_address = [function for function in functions if function.address == address]
        if len(by_address) == 1:
            return by_address[0]
        if len(by_address) > 1:
            raise MatchingError(f"Function address 0x{address:08X} is ambiguous in {_functions_path(project)}.")
    raise MatchingError(f"Function {selector!r} was not found in {_functions_path(project)}.")


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_reference_object(function: MatchFunction) -> bytes:
    if not function.instructions:
        raise MatchingError(f"Function {function.name} has no instruction words for reference-object generation.")
    expected_address = function.address
    for index, instruction in enumerate(function.instructions):
        if instruction.address != expected_address:
            raise MatchingError(
                f"Function {function.name} instruction {index} is not contiguous: expected 0x{expected_address:08X}, "
                f"got 0x{instruction.address:08X}."
            )
        expected_address += 4

    text = b"".join(struct.pack("<I", instruction.word) for instruction in function.instructions)
    symbol_name = function.name.encode("utf-8", "strict")
    if b"\0" in symbol_name:
        raise MatchingError("Function names containing NUL cannot be emitted into an ELF string table.")
    strtab = b"\0" + symbol_name + b"\0"
    shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    name_text = 1
    name_symtab = 7
    name_strtab = 15
    name_shstrtab = 23

    offset = 52
    text_offset = _align(offset, 4)
    offset = text_offset + len(text)
    symtab_offset = _align(offset, 4)
    null_symbol = bytes(16)
    function_symbol = struct.pack(
        "<IIIBBH",
        1,
        0,
        len(text),
        (1 << 4) | 2,
        0,
        1,
    )
    symtab = null_symbol + function_symbol
    offset = symtab_offset + len(symtab)
    strtab_offset = offset
    offset += len(strtab)
    shstrtab_offset = offset
    offset += len(shstrtab)
    section_header_offset = _align(offset, 4)

    ident = b"\x7fELF" + bytes((1, 1, 1)) + bytes(9)
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        1,
        8,
        1,
        0,
        0,
        section_header_offset,
        0,
        52,
        0,
        0,
        40,
        5,
        4,
    )
    section_headers = b"".join(
        [
            bytes(40),
            struct.pack("<IIIIIIIIII", name_text, 1, 0x6, 0, text_offset, len(text), 0, 0, 4, 0),
            struct.pack("<IIIIIIIIII", name_symtab, 2, 0, 0, symtab_offset, len(symtab), 3, 1, 4, 16),
            struct.pack("<IIIIIIIIII", name_strtab, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
            struct.pack("<IIIIIIIIII", name_shstrtab, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0),
        ]
    )
    data = bytearray(section_header_offset + len(section_headers))
    data[:52] = header
    data[text_offset : text_offset + len(text)] = text
    data[symtab_offset : symtab_offset + len(symtab)] = symtab
    data[strtab_offset : strtab_offset + len(strtab)] = strtab
    data[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    data[section_header_offset : section_header_offset + len(section_headers)] = section_headers
    return bytes(data)


def _command_for_path(path: Path, label: str) -> list[str]:
    if not path.exists():
        raise MatcherUnavailableError(f"{label} does not exist: {path}")
    if path.is_dir():
        raise MatcherUnavailableError(f"{label} path is a directory: {path}")
    if path.suffix.lower() == ".py":
        return [sys.executable, str(path.resolve())]
    return [str(path.resolve())]


def resolve_asm_differ_command(explicit_path: Path | str | None = None) -> list[str]:
    if explicit_path is not None:
        return _command_for_path(Path(explicit_path), "asm-differ backend")
    configured = os.environ.get("PSPDISASM_ASM_DIFFER")
    if configured:
        return _command_for_path(Path(configured), "asm-differ backend")
    executable = shutil.which("asm-differ")
    if executable:
        return [executable]
    raise MatcherUnavailableError(
        "asm-differ is required for matching. Pass --asm-differ PATH, set PSPDISASM_ASM_DIFFER, "
        "or install the asm-differ executable on PATH."
    )


def resolve_objdump(explicit_path: Path | str | None = None) -> str:
    if explicit_path is not None:
        path = Path(explicit_path)
        if not path.exists() or path.is_dir():
            raise MatcherUnavailableError(f"objdump executable does not exist: {path}")
        return str(path.resolve())
    configured = os.environ.get("PSPDISASM_OBJDUMP")
    if configured:
        path = Path(configured)
        if not path.exists() or path.is_dir():
            raise MatcherUnavailableError(f"configured objdump executable does not exist: {path}")
        return str(path.resolve())
    for name in ("psp-objdump", "mipsel-linux-gnu-objdump", "objdump"):
        executable = shutil.which(name)
        if executable:
            return executable
    raise MatcherUnavailableError(
        "A MIPS-capable objdump is required. Pass --objdump PATH, set PSPDISASM_OBJDUMP, "
        "or install psp-objdump/mipsel-linux-gnu-objdump on PATH."
    )


def _safe_stem(function: MatchFunction) -> str:
    cleaned = "".join(char if char in _SAFE_FILENAME else "_" for char in function.name).strip("._")
    return cleaned or f"func_{function.address:08X}"


def _resolve_project_path(project: Path, path: Path | str) -> Path:
    candidate = Path(path)
    return candidate.resolve() if candidate.is_absolute() else (project / candidate).resolve()


def _normalize_build_command(command: str | Sequence[str] | None) -> list[str] | None:
    if command is None:
        return None
    if isinstance(command, str):
        result = shlex.split(command)
    else:
        result = [str(part) for part in command]
    if not result:
        raise MatchingError("build command must not be empty.")
    return result


def _run_build(project: Path, command: Sequence[str], timeout: float) -> None:
    try:
        completed = subprocess.run(
            list(command),
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise MatchingError(f"build command timed out after {timeout:g} seconds.") from exc
    except OSError as exc:
        raise MatchingError(f"unable to execute build command {command[0]!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if len(detail) > 500:
            detail = detail[:500] + "..."
        suffix = f": {detail}" if detail else ""
        raise MatchingError(f"build command failed with exit code {completed.returncode}{suffix}")


def _detect_backend_version(command: Sequence[str]) -> str | None:
    if not command:
        return None
    path = Path(command[-1])
    candidates = [path.parent / "pyproject.toml", path.parent.parent / "pyproject.toml"]
    for pyproject in candidates:
        try:
            payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        project_version = payload.get("project", {}).get("version")
        if isinstance(project_version, str):
            return project_version
        poetry_version = payload.get("tool", {}).get("poetry", {}).get("version")
        if isinstance(poetry_version, str):
            return poetry_version
    return None


def _diff_settings(project: Path, objdump: str) -> str:
    return (
        "def apply(config, args):\n"
        "    config['arch'] = 'mipsel'\n"
        f"    config['objdump_executable'] = {objdump!r}\n"
        f"    config['source_directories'] = [{str(project)!r}]\n"
        "    config['show_line_numbers_default'] = False\n"
    )


def _run_asm_differ(
    command: Sequence[str],
    *,
    project: Path,
    function: MatchFunction,
    candidate: Path,
    reference: Path,
    objdump: str,
    section: str,
    ignore_large_imms: bool,
    timeout: float,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pspdisasm-match-") as temporary:
        temp = Path(temporary)
        (temp / "diff_settings.py").write_text(_diff_settings(project, objdump), encoding="utf-8")
        args = [
            *command,
            function.name,
            "-o",
            "-f",
            str(candidate),
            "-F",
            str(reference),
            "--format",
            "json",
            "--algorithm",
            "difflib",
            "--no-pager",
            "--no-line-numbers",
            "-j",
            section,
        ]
        if ignore_large_imms:
            args.append("-i")
        try:
            completed = subprocess.run(
                args,
                cwd=temp,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MatchingError(f"asm-differ timed out after {timeout:g} seconds.") from exc
        except OSError as exc:
            raise MatcherUnavailableError(f"unable to execute asm-differ backend {command[0]!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if len(detail) > 750:
            detail = detail[:750] + "..."
        suffix = f": {detail}" if detail else ""
        raise MatchingError(f"asm-differ failed with exit code {completed.returncode}{suffix}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        detail = completed.stdout.strip()
        if len(detail) > 300:
            detail = detail[:300] + "..."
        raise MatchingError(f"asm-differ did not return valid JSON: {detail or '<empty output>'}") from exc
    if not isinstance(payload, dict):
        raise MatchingError("asm-differ JSON output must be an object.")
    return payload


def _score(payload: dict[str, Any]) -> tuple[int, int, float]:
    raw_score = payload.get("current_score")
    max_score = payload.get("max_score")
    if not isinstance(raw_score, int) or isinstance(raw_score, bool):
        raise MatchingError("asm-differ JSON is missing integer current_score.")
    if not isinstance(max_score, int) or isinstance(max_score, bool) or max_score < 0:
        raise MatchingError("asm-differ JSON is missing non-negative integer max_score.")
    if max_score == 0:
        similarity = 100.0 if raw_score == 0 else 0.0
    else:
        similarity = 100.0 * (1.0 - (raw_score / max_score))
        similarity = min(100.0, max(0.0, similarity))
    return raw_score, max_score, round(similarity, 2)


def _cell_has_diff(cell: Any) -> bool:
    if not isinstance(cell, dict):
        return False
    text = cell.get("text")
    if not isinstance(text, list):
        return False
    for segment in text:
        if isinstance(segment, dict):
            format_name = segment.get("format")
            if isinstance(format_name, str) and format_name.startswith("diff_"):
                return True
    return False


def _classify_rows(payload: dict[str, Any]) -> tuple[int, int, int, int]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise MatchingError("asm-differ JSON is missing rows list.")
    matching = changed = added = removed = 0
    for row in rows:
        if not isinstance(row, dict):
            raise MatchingError("asm-differ rows must contain JSON objects.")
        base = row.get("base")
        current = row.get("current")
        if base is not None and current is not None:
            if _cell_has_diff(base) or _cell_has_diff(current):
                changed += 1
            else:
                matching += 1
        elif current is not None:
            added += 1
        elif base is not None:
            removed += 1
    return matching, changed, added, removed


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


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _reference_warning(project: Path, function: MatchFunction, auto_reference: bool) -> list[str]:
    if not auto_reference:
        return []
    path = project / "metadata" / "references.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, list) and any(
        isinstance(item, dict) and item.get("source_function") == function.name for item in payload
    ):
        return [
            "The synthesized reference object contains original instruction words but no MIPS relocation records; "
            "functions with calls/global references may receive a pessimistic asm-differ score."
        ]
    return []


def match_project_function(
    project_dir: Path | str,
    selector: str,
    *,
    candidate_object: Path | str,
    asm_differ_path: Path | str | None = None,
    objdump_path: Path | str | None = None,
    reference_object: Path | str | None = None,
    build_command: str | Sequence[str] | None = None,
    section: str = ".text",
    ignore_large_imms: bool = False,
    timeout: float = 120.0,
) -> MatchResult:
    if timeout <= 0:
        raise MatchingError("timeout must be greater than zero.")
    if not section:
        raise MatchingError("section must not be empty.")
    project = Path(project_dir).resolve()
    function = resolve_match_function(project, selector)
    candidate = _resolve_project_path(project, candidate_object)
    build = _normalize_build_command(build_command)
    if build is not None:
        _run_build(project, build, timeout)
    if not candidate.is_file():
        raise MatchingError(f"candidate object does not exist after build: {candidate}")

    backend_command = resolve_asm_differ_command(asm_differ_path)
    objdump = resolve_objdump(objdump_path)
    stem = _safe_stem(function)
    metadata_path = project / "metadata" / "matching" / f"{stem}.json"
    raw_report_path = project / "reports" / "matching" / f"{stem}.asm-differ.json"
    auto_reference = reference_object is None
    reference_bytes: bytes | None = None

    if reference_object is not None:
        reference = _resolve_project_path(project, reference_object)
        if not reference.is_file():
            raise MatchingError(f"reference object does not exist: {reference}")
        payload = _run_asm_differ(
            backend_command,
            project=project,
            function=function,
            candidate=candidate,
            reference=reference,
            objdump=objdump,
            section=section,
            ignore_large_imms=ignore_large_imms,
            timeout=timeout,
        )
    else:
        reference_bytes = build_reference_object(function)
        with tempfile.TemporaryDirectory(prefix="pspdisasm-reference-") as temporary:
            temporary_reference = Path(temporary) / f"{stem}.o"
            temporary_reference.write_bytes(reference_bytes)
            payload = _run_asm_differ(
                backend_command,
                project=project,
                function=function,
                candidate=candidate,
                reference=temporary_reference,
                objdump=objdump,
                section=section,
                ignore_large_imms=ignore_large_imms,
                timeout=timeout,
            )
        reference = project / "build" / "matching" / "reference" / f"{stem}.o"

    raw_score, max_score, similarity = _score(payload)
    matching, changed, added, removed = _classify_rows(payload)
    warnings = _reference_warning(project, function, auto_reference)
    backend_version = _detect_backend_version(backend_command)

    metadata = {
        "backend": {"name": "asm-differ", "version": backend_version, "objdump": objdump},
        "function": {"name": function.name, "address": function.address, "size": function.size, "section": function.section},
        "artifacts": {
            "candidate_object": _relative_or_string(candidate, project),
            "reference_object": _relative_or_string(reference, project),
            "raw_report": _relative_or_string(raw_report_path, project),
        },
        "build_command": build,
        "settings": {"section": section, "ignore_large_imms": ignore_large_imms, "algorithm": "difflib"},
        "score": {"raw": raw_score, "max": max_score, "similarity_percent": similarity},
        "rows": {"matching": matching, "changed": changed, "added": added, "removed": removed},
        "warnings": warnings,
    }

    if reference_bytes is not None:
        _atomic_write_bytes(reference, reference_bytes)
    _atomic_write_text(raw_report_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    _atomic_write_text(metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    return MatchResult(
        project_dir=project,
        function_name=function.name,
        function_address=function.address,
        candidate_object=candidate,
        reference_object=reference,
        metadata_path=metadata_path,
        raw_report_path=raw_report_path,
        backend_name="asm-differ",
        backend_version=backend_version,
        objdump=objdump,
        raw_score=raw_score,
        max_score=max_score,
        similarity_percent=similarity,
        matching_rows=matching,
        changed_rows=changed,
        added_rows=added,
        removed_rows=removed,
        warnings=warnings,
    )


__all__ = [
    "MatchFunction",
    "MatchInstruction",
    "MatchResult",
    "MatcherUnavailableError",
    "MatchingError",
    "build_reference_object",
    "match_project_function",
    "resolve_asm_differ_command",
    "resolve_match_function",
    "resolve_objdump",
]
