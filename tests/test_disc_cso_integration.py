from tests.test_disc import build_psp_iso
from tests.test_disc_image import build_cso

from pspdisasm.disc import scan_game_disc


def test_scan_game_disc_reads_cso_without_expanding_to_iso(tmp_path):
    iso_path = tmp_path / "game.iso"
    cso_path = tmp_path / "game.cso"
    output = tmp_path / "project"
    build_psp_iso(iso_path, eboot=b"\x7fELF" + b"E" * 60)

    iso_bytes = iso_path.read_bytes()
    blocks = [iso_bytes[offset : offset + 2048] for offset in range(0, len(iso_bytes), 2048)]
    compressed = {index for index in range(len(blocks)) if index % 2 == 1}
    cso_path.write_bytes(build_cso(blocks, compressed=compressed))
    iso_path.unlink()

    manifest = scan_game_disc(cso_path, output)

    assert manifest.image_format == "cso"
    assert manifest.disc_id == "ULUS12345"
    assert manifest.boot_path == "PSP_GAME/SYSDIR/EBOOT.BIN"
    assert (output / "modules" / "PSP_GAME" / "SYSDIR" / "EBOOT.BIN").read_bytes().startswith(b"\x7fELF")
