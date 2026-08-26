from pspdisasm.analyzer import analyze_bytes
from tests.fixtures import build_prx_elf32, build_psp_container_header, build_simple_elf32


def test_analyzes_prx_into_normalized_model():
    model = analyze_bytes(build_prx_elf32(), "sample.prx")
    assert model.source_name == "sample.prx"
    assert model.input_kind == "elf32"
    assert model.executable_kind == "prx"
    assert model.needs_decryption is False
    assert model.elf_header is not None
    assert model.elf_header.file_type == 0xFFA0
    assert model.module_info is not None
    assert model.module_info.name == "TESTPRX"
    assert len(model.imports) == 1
    assert len(model.exports) == 1
    assert len(model.relocations) == 2
    assert [reloc.source for reloc in model.relocations] == ["section", "program_header_rel2"]


def test_analyzes_standard_mips_elf_without_prx_metadata():
    model = analyze_bytes(build_simple_elf32(), "main.elf")
    assert model.executable_kind == "elf"
    assert model.needs_decryption is False
    assert model.module_info is None
    assert len(model.sections) == 5


def test_analyzes_psp_container_without_claiming_body_is_decrypted():
    model = analyze_bytes(build_psp_container_header(), "EBOOT.BIN")
    assert model.input_kind == "psp_container"
    assert model.executable_kind == "encrypted_psp_container"
    assert model.needs_decryption is True
    assert model.container_header is not None
    assert model.container_header.module_name == "GAMEBOOT"
    assert model.elf_header is None
    assert any("decryption" in warning.lower() for warning in model.warnings)
