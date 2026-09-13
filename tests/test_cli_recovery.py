from __future__ import annotations

import hashlib
import json

from pspdisasm.cli import main
from tests.fixtures import build_allegrex_elf32, build_psp_container_header
from tests.test_game_project import _build_game_iso


def _write_fake_backend_script(path, *, exit_code: int = 0, output: bytes | None = None):
    output_bytes = output if output is not None else build_allegrex_elf32()
    path.write_text(
        "import sys\n"
        "args = sys.argv[1:]\n"
        "output_path = args[args.index('--output') + 1]\n"
        f"with open(output_path, 'wb') as handle:\n"
        f"    handle.write({output_bytes!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return path


def test_cli_recover_writes_output_and_json_provenance(tmp_path, capsys):
    backend = _write_fake_backend_script(tmp_path / "backend.py")
    source = tmp_path / "LOCKED.PRX"
    source.write_bytes(build_psp_container_header())
    output = tmp_path / "recovered.elf"

    code = main(
        [
            "recover",
            str(source),
            str(output),
            "--recovery-backend",
            str(backend),
            "--json",
            "-",
        ]
    )

    assert code == 0
    assert output.read_bytes() == build_allegrex_elf32()
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "verified"
    assert payload["verification"] == "valid_elf32_psp"
    assert payload["original_sha256"] == hashlib.sha256(build_psp_container_header()).hexdigest()
    assert payload["recovered_sha256"] == hashlib.sha256(build_allegrex_elf32()).hexdigest()


def test_cli_recover_prints_human_summary_without_json_flag(tmp_path, capsys):
    backend = _write_fake_backend_script(tmp_path / "backend.py")
    source = tmp_path / "LOCKED.PRX"
    source.write_bytes(build_psp_container_header())
    output = tmp_path / "recovered.elf"

    code = main(["recover", str(source), str(output), "--recovery-backend", str(backend)])

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Recovered:" in stdout
    assert "Verification: valid_elf32_psp" in stdout


def test_cli_recover_reports_no_backend_configured(tmp_path, capsys):
    source = tmp_path / "LOCKED.PRX"
    source.write_bytes(build_psp_container_header())
    output = tmp_path / "recovered.elf"

    code = main(["recover", str(source), str(output)])

    assert code == 2
    assert "recovery backend" in capsys.readouterr().err.lower()


def test_cli_recover_reports_backend_failure(tmp_path, capsys):
    backend = _write_fake_backend_script(tmp_path / "backend.py", exit_code=1)
    source = tmp_path / "LOCKED.PRX"
    source.write_bytes(build_psp_container_header())
    output = tmp_path / "recovered.elf"

    code = main(["recover", str(source), str(output), "--recovery-backend", str(backend)])

    assert code == 2
    assert "exit" in capsys.readouterr().err.lower()


def test_cli_recover_with_manifest_backend(tmp_path, capsys):
    recovered_bytes = build_allegrex_elf32()
    recovered_file = tmp_path / "dump.elf"
    recovered_file.write_bytes(recovered_bytes)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "original_sha256": hashlib.sha256(build_psp_container_header()).hexdigest(),
                    "recovered_sha256": hashlib.sha256(recovered_bytes).hexdigest(),
                    "path": "dump.elf",
                }
            ]
        ),
        encoding="utf-8",
    )
    source = tmp_path / "LOCKED.PRX"
    source.write_bytes(build_psp_container_header())
    output = tmp_path / "recovered.elf"

    code = main(["recover", str(source), str(output), "--recovery-manifest", str(manifest)])

    assert code == 0
    assert output.read_bytes() == recovered_bytes


def test_cli_game_project_reports_recovered_modules(tmp_path, capsys):
    backend = _write_fake_backend_script(tmp_path / "backend.py")
    image = tmp_path / "game.iso"
    output = tmp_path / "game_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        modules={"PSP_GAME/USRDIR/LOCKED.PRX": build_psp_container_header()},
    )

    code = main(
        ["game-project", str(image), str(output), "--recovery-backend", str(backend)]
    )

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Analyzed modules: 1" in stdout
    assert "Recovered modules: 1" in stdout
    assert "Needs decryption: 0" in stdout


def test_cli_game_project_defaults_to_zero_recovered_modules(tmp_path, capsys):
    image = tmp_path / "game.iso"
    output = tmp_path / "game_decomp"
    _build_game_iso(
        image,
        eboot=build_allegrex_elf32(),
        modules={"PSP_GAME/USRDIR/LOCKED.PRX": build_psp_container_header()},
    )

    code = main(["game-project", str(image), str(output)])

    assert code == 0
    stdout = capsys.readouterr().out
    assert "Recovered modules: 0" in stdout
    assert "Needs decryption: 1" in stdout
