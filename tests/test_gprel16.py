from pspdisasm.model import Relocation
from pspdisasm.prxreloc2 import apply_psp_relocation_word


def test_psp_gprel16_is_identity_in_explicit_load_view_application() -> None:
    relocation = Relocation(
        section=".rel.text",
        offset=0,
        info=7,
        type=7,
        type_name="R_MIPS_GPREL16",
        symbol_index=0,
        target_section_index=None,
    )

    assert apply_psp_relocation_word(0x24840020, relocation, 0x08804000) == 0x24840020
