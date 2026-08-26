from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import sys

import pytest

from pspdisasm.matcher import (
    MatchingError,
    build_reference_object,
    match_project_function,
    resolve_match_function,
)


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "metadata").mkdir(parents=True)
    functions = [
        {
            "name": "func_08800000",
            "address": 0x08800000,
            "size": 12,
            "section": ".text",
            "assembly": "func_08800000:\n    li $v0, 1\n    jr $ra\n    nop\n",
            "instruction_count": 3,
            "instructions": [
                {"address": 0x08800000, "word": 0x24020001, "text": "addiu $v0, $zero, 1", "valid": True, "implemented": True},
                {"address": 0x08800004, "word": 0x03E00008, "text": "jr $ra", "valid": True, "implemented": True},
                {"address": 0x08800008, "word": 0x00000000, "text": "nop", "valid": True, "implemented": True},
            ],
        }
    ]
    (project / "metadata" / "functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (project / "metadata" / "references.json").write_text("[]\n", encoding="utf-8")
    return project


def _executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_objdump(tmp_path: Path) -> Path:
    return _executable(tmp_path / "objdump", "#!/bin/sh\nexit 0\n")


def _fake_asm_differ(tmp_path: Path, payload: dict, *, exit_code: int = 0) -> Path:
    script = tmp_path / "diff.py"
    script.write_text(
        "import json, sys\n"
        + f"payload = {payload!r}\n"
        + (f"print('backend failed', file=sys.stderr); sys.exit({exit_code})\n" if exit_code else "print(json.dumps(payload))\n"),
        encoding="utf-8",
    )
    return script


def test_resolve_match_function_by_name_and_address(tmp_path: Path) -> None:
    project = _project(tmp_path)

    by_name = resolve_match_function(project, "func_08800000")
    by_address = resolve_match_function(project, "0x08800000")

    assert by_name.name == "func_08800000"
    assert by_name.address == 0x08800000
    assert by_address == by_name
    assert [instruction.word for instruction in by_name.instructions] == [0x24020001, 0x03E00008, 0]


def test_build_reference_object_is_mips_elf_with_function_symbol(tmp_path: Path) -> None:
    function = resolve_match_function(_project(tmp_path), "func_08800000")

    data = build_reference_object(function)

    assert data[:4] == b"\x7fELF"
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    assert e_type == 1
    assert e_machine == 8
    assert b".text\x00" in data
    assert b".symtab\x00" in data
    assert b"func_08800000\x00" in data
    assert struct.pack("<III", 0x24020001, 0x03E00008, 0) in data


def test_match_exact_result_persists_normalized_and_raw_reports(tmp_path: Path) -> None:
    project = _project(tmp_path)
    candidate = tmp_path / "candidate.o"
    candidate.write_bytes(b"candidate")
    payload = {
        "arch_str": "mipsel",
        "header": {"base": [], "current": []},
        "current_score": 0,
        "max_score": 300,
        "rows": [
            {
                "key": "addiu",
                "is_data_ref": False,
                "base": {"text": [{"text": "addiu"}], "mnemonic": "addiu"},
                "current": {"text": [{"text": "addiu"}], "mnemonic": "addiu"},
            }
        ],
    }
    backend = _fake_asm_differ(tmp_path, payload)

    result = match_project_function(
        project,
        "func_08800000",
        candidate_object=candidate,
        asm_differ_path=backend,
        objdump_path=_fake_objdump(tmp_path),
    )

    assert result.raw_score == 0
    assert result.max_score == 300
    assert result.similarity_percent == 100.0
    assert result.matching_rows == 1
    assert result.changed_rows == 0
    assert result.added_rows == 0
    assert result.removed_rows == 0
    assert result.reference_object.is_file()
    assert result.metadata_path.is_file()
    assert result.raw_report_path.is_file()
    metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
    assert metadata["function"]["address"] == 0x08800000
    assert metadata["score"]["similarity_percent"] == 100.0
    assert json.loads(result.raw_report_path.read_text(encoding="utf-8")) == payload


def test_match_classifies_changed_added_and_removed_rows(tmp_path: Path) -> None:
    project = _project(tmp_path)
    candidate = tmp_path / "candidate.o"
    candidate.write_bytes(b"candidate")
    payload = {
        "arch_str": "mipsel",
        "header": {"base": [], "current": []},
        "current_score": 100,
        "max_score": 400,
        "rows": [
            {"key": "same", "is_data_ref": False, "base": {"text": [{"text": "same"}]}, "current": {"text": [{"text": "same"}]}},
            {"key": "changed", "is_data_ref": False, "base": {"text": [{"text": "a"}]}, "current": {"text": [{"text": "b", "format": "diff_change"}]}},
            {"key": "added", "is_data_ref": False, "current": {"text": [{"text": "c", "format": "diff_add"}]}},
            {"key": "removed", "is_data_ref": False, "base": {"text": [{"text": "d", "format": "diff_remove"}]}},
        ],
    }

    result = match_project_function(
        project,
        "func_08800000",
        candidate_object=candidate,
        asm_differ_path=_fake_asm_differ(tmp_path, payload),
        objdump_path=_fake_objdump(tmp_path),
    )

    assert result.similarity_percent == 75.0
    assert (result.matching_rows, result.changed_rows, result.added_rows, result.removed_rows) == (1, 1, 1, 1)


def test_failed_build_does_not_overwrite_previous_reports(tmp_path: Path) -> None:
    project = _project(tmp_path)
    metadata = project / "metadata" / "matching" / "func_08800000.json"
    raw = project / "reports" / "matching" / "func_08800000.asm-differ.json"
    metadata.parent.mkdir(parents=True)
    raw.parent.mkdir(parents=True)
    metadata.write_text("old metadata", encoding="utf-8")
    raw.write_text("old raw", encoding="utf-8")
    build = _executable(tmp_path / "build.py", "#!/usr/bin/env python3\nimport sys\nsys.exit(7)\n")

    with pytest.raises(MatchingError, match="build command failed"):
        match_project_function(
            project,
            "func_08800000",
            candidate_object=tmp_path / "missing.o",
            asm_differ_path=_fake_asm_differ(tmp_path, {"current_score": 0, "max_score": 1, "rows": []}),
            objdump_path=_fake_objdump(tmp_path),
            build_command=[sys.executable, str(build)],
        )

    assert metadata.read_text(encoding="utf-8") == "old metadata"
    assert raw.read_text(encoding="utf-8") == "old raw"


def test_backend_failure_does_not_overwrite_previous_reports(tmp_path: Path) -> None:
    project = _project(tmp_path)
    candidate = tmp_path / "candidate.o"
    candidate.write_bytes(b"candidate")
    metadata = project / "metadata" / "matching" / "func_08800000.json"
    raw = project / "reports" / "matching" / "func_08800000.asm-differ.json"
    metadata.parent.mkdir(parents=True)
    raw.parent.mkdir(parents=True)
    metadata.write_text("old metadata", encoding="utf-8")
    raw.write_text("old raw", encoding="utf-8")

    with pytest.raises(MatchingError, match="asm-differ failed"):
        match_project_function(
            project,
            "func_08800000",
            candidate_object=candidate,
            asm_differ_path=_fake_asm_differ(tmp_path, {}, exit_code=5),
            objdump_path=_fake_objdump(tmp_path),
        )

    assert metadata.read_text(encoding="utf-8") == "old metadata"
    assert raw.read_text(encoding="utf-8") == "old raw"


def test_invalid_backend_json_is_rejected(tmp_path: Path) -> None:
    project = _project(tmp_path)
    candidate = tmp_path / "candidate.o"
    candidate.write_bytes(b"candidate")
    backend = _executable(tmp_path / "diff.py", "#!/usr/bin/env python3\nprint('not-json')\n")

    with pytest.raises(MatchingError, match="valid JSON"):
        match_project_function(
            project,
            "func_08800000",
            candidate_object=candidate,
            asm_differ_path=backend,
            objdump_path=_fake_objdump(tmp_path),
        )


def test_explicit_reference_object_is_preserved(tmp_path: Path) -> None:
    project = _project(tmp_path)
    candidate = tmp_path / "candidate.o"
    candidate.write_bytes(b"candidate")
    reference = tmp_path / "reference.o"
    reference.write_bytes(b"reference")
    payload = {"current_score": 0, "max_score": 0, "rows": []}

    result = match_project_function(
        project,
        "func_08800000",
        candidate_object=candidate,
        reference_object=reference,
        asm_differ_path=_fake_asm_differ(tmp_path, payload),
        objdump_path=_fake_objdump(tmp_path),
    )

    assert result.reference_object == reference.resolve()
    assert reference.read_bytes() == b"reference"
    assert result.similarity_percent == 100.0

def test_build_command_string_is_split_without_shell_and_creates_candidate(tmp_path: Path) -> None:
    project = _project(tmp_path)
    builder = project / "builder.py"
    builder.write_text(
        "from pathlib import Path\nPath('build').mkdir(exist_ok=True)\nPath('build/candidate.o').write_bytes(b'candidate')\n",
        encoding="utf-8",
    )
    payload = {"current_score": 0, "max_score": 1, "rows": []}

    result = match_project_function(
        project,
        "func_08800000",
        candidate_object="build/candidate.o",
        asm_differ_path=_fake_asm_differ(tmp_path, payload),
        objdump_path=_fake_objdump(tmp_path),
        build_command=f"{sys.executable} {builder.name}",
    )

    assert result.candidate_object == (project / "build" / "candidate.o").resolve()


def test_auto_reference_warns_when_function_has_discovered_references(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "metadata" / "references.json").write_text(
        json.dumps([
            {
                "source_address": 0x08800000,
                "target_address": 0x08800100,
                "kind": "call",
                "source_function": "func_08800000",
                "target_section": ".text",
            }
        ]),
        encoding="utf-8",
    )
    candidate = tmp_path / "candidate.o"
    candidate.write_bytes(b"candidate")

    result = match_project_function(
        project,
        "func_08800000",
        candidate_object=candidate,
        asm_differ_path=_fake_asm_differ(tmp_path, {"current_score": 0, "max_score": 1, "rows": []}),
        objdump_path=_fake_objdump(tmp_path),
    )

    assert any("no MIPS relocation records" in warning for warning in result.warnings)
