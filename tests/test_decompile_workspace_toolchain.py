from __future__ import annotations

from pathlib import Path

import pytest

from pspdisasm.errors import BuildFailedError, BuildToolchainUnavailableError
from pspdisasm.decompile.toolchain import ExternalCompilerToolchain, ProjectBuildCommandToolchain


def _executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_compiler(tmp_path: Path, *, exit_code: int = 0, write_output: bool = True) -> Path:
    body = "#!/bin/sh\n"
    if write_output:
        body += 'for i in "$@"; do :; done\n'
        # Find the argument following -o and write to it.
        body += (
            "out=\"\"\n"
            "prev=\"\"\n"
            "for arg in \"$@\"; do\n"
            "  if [ \"$prev\" = \"-o\" ]; then out=\"$arg\"; fi\n"
            "  prev=\"$arg\"\n"
            "done\n"
            "if [ -n \"$out\" ]; then printf 'OBJECT' > \"$out\"; fi\n"
        )
    body += f"exit {exit_code}\n"
    return _executable(tmp_path / "fake-cc", body)


# ---------------------------------------------------------------------------
# ExternalCompilerToolchain
# ---------------------------------------------------------------------------


def test_external_compiler_toolchain_compiles_successfully(tmp_path):
    compiler = _fake_compiler(tmp_path)
    toolchain = ExternalCompilerToolchain(compiler, flags=["-O2"])
    source = tmp_path / "func.c"
    source.write_text("int func(void) { return 0; }\n", encoding="utf-8")
    output = tmp_path / "func.o"

    result = toolchain.compile_function(source, output=output, project=tmp_path, timeout=10)

    assert result.output_path == output
    assert output.read_bytes() == b"OBJECT"
    assert len(result.object_sha256) == 64


def test_external_compiler_toolchain_unavailable_when_not_configured():
    with pytest.raises(BuildToolchainUnavailableError):
        ExternalCompilerToolchain(None)


def test_external_compiler_toolchain_unavailable_when_path_missing(tmp_path):
    with pytest.raises(BuildToolchainUnavailableError, match="does not exist"):
        ExternalCompilerToolchain(tmp_path / "nonexistent-cc")


def test_external_compiler_toolchain_reports_nonzero_exit(tmp_path):
    compiler = _fake_compiler(tmp_path, exit_code=1, write_output=False)
    toolchain = ExternalCompilerToolchain(compiler)
    source = tmp_path / "func.c"
    source.write_text("bad C\n", encoding="utf-8")

    with pytest.raises(BuildFailedError, match="exited with code 1"):
        toolchain.compile_function(source, output=tmp_path / "func.o", project=tmp_path, timeout=10)


def test_external_compiler_toolchain_reports_missing_output(tmp_path):
    compiler = _fake_compiler(tmp_path, write_output=False)
    toolchain = ExternalCompilerToolchain(compiler)
    source = tmp_path / "func.c"
    source.write_text("int func(void) { return 0; }\n", encoding="utf-8")

    with pytest.raises(BuildFailedError, match="did not produce"):
        toolchain.compile_function(source, output=tmp_path / "func.o", project=tmp_path, timeout=10)


def test_external_compiler_toolchain_reports_timeout(tmp_path):
    compiler = _executable(tmp_path / "slow-cc", "#!/bin/sh\nsleep 5\n")
    toolchain = ExternalCompilerToolchain(compiler)
    source = tmp_path / "func.c"
    source.write_text("int func(void) { return 0; }\n", encoding="utf-8")

    with pytest.raises(BuildFailedError, match="timed out"):
        toolchain.compile_function(source, output=tmp_path / "func.o", project=tmp_path, timeout=0.2)


def test_external_compiler_toolchain_identity_reflects_compiler_and_flags(tmp_path):
    compiler = _fake_compiler(tmp_path)
    toolchain_a = ExternalCompilerToolchain(compiler, flags=["-O2"])
    toolchain_b = ExternalCompilerToolchain(compiler, flags=["-O0"])

    identity_a = toolchain_a.identity()
    identity_b = toolchain_b.identity()

    assert identity_a["compiler_sha256"] is not None
    assert identity_a != identity_b
    assert identity_a["flags"] == ["-O2"]


# ---------------------------------------------------------------------------
# ProjectBuildCommandToolchain
# ---------------------------------------------------------------------------


def test_project_build_command_toolchain_compiles_successfully(tmp_path):
    (tmp_path / "build.sh").write_text(
        "#!/bin/sh\nmkdir -p build\nprintf 'OBJECT' > \"build/$1.o\"\n", encoding="utf-8"
    )
    (tmp_path / "build.sh").chmod(0o755)
    toolchain = ProjectBuildCommandToolchain(
        command_template=f"{tmp_path / 'build.sh'} {{function}}",
        output_template="build/{function}.o",
    )
    source = tmp_path / "func_08812340.c"
    source.write_text("int func(void) { return 0; }\n", encoding="utf-8")

    result = toolchain.compile_function(source, output=tmp_path / "ignored.o", project=tmp_path, timeout=10)

    assert result.output_path == tmp_path / "build/func_08812340.o"
    assert result.output_path.read_bytes() == b"OBJECT"


def test_project_build_command_toolchain_reports_nonzero_exit(tmp_path):
    toolchain = ProjectBuildCommandToolchain(command_template="false", output_template="build/{function}.o")
    source = tmp_path / "func.c"
    source.write_text("x", encoding="utf-8")

    with pytest.raises(BuildFailedError, match="exited with code"):
        toolchain.compile_function(source, output=tmp_path / "ignored.o", project=tmp_path, timeout=10)


def test_project_build_command_toolchain_reports_missing_output(tmp_path):
    toolchain = ProjectBuildCommandToolchain(command_template="true", output_template="build/{function}.o")
    source = tmp_path / "func.c"
    source.write_text("x", encoding="utf-8")

    with pytest.raises(BuildFailedError, match="did not produce"):
        toolchain.compile_function(source, output=tmp_path / "ignored.o", project=tmp_path, timeout=10)


def test_project_build_command_toolchain_rejects_empty_template():
    with pytest.raises(BuildToolchainUnavailableError):
        ProjectBuildCommandToolchain(command_template="   ", output_template="build/{function}.o")


def test_project_build_command_toolchain_identity_includes_command_hash_when_resolvable(tmp_path):
    script = tmp_path / "build.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    toolchain = ProjectBuildCommandToolchain(command_template=f"{script} {{function}}", output_template="{function}.o")

    identity = toolchain.identity()
    assert "command_sha256" in identity


def test_project_build_command_toolchain_never_uses_shell_features(tmp_path):
    """A shell-metacharacter-laden function name must not be interpreted by a
    shell; shlex.split + argv execution means it's just a literal argument."""
    (tmp_path / "record.sh").write_text(
        "#!/bin/sh\nmkdir -p build\nprintf '%s' \"$1\" > build/seen.txt\ntouch \"build/$2\"\n",
        encoding="utf-8",
    )
    (tmp_path / "record.sh").chmod(0o755)
    toolchain = ProjectBuildCommandToolchain(
        command_template=f"{tmp_path / 'record.sh'} 'literal;arg' {{function}}.o",
        output_template="build/{function}.o",
    )
    source = tmp_path / "func.c"
    source.write_text("x", encoding="utf-8")

    result = toolchain.compile_function(source, output=tmp_path / "ignored.o", project=tmp_path, timeout=10)

    assert (tmp_path / "build/seen.txt").read_text(encoding="utf-8") == "literal;arg"
    assert result.output_path.is_file()
