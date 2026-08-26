import pspdisasm


def test_phase7e_relocation_helpers_are_public_api():
    assert pspdisasm.decode_prxreloc2 is not None
    assert pspdisasm.apply_psp_relocation_word is not None
    assert "decode_prxreloc2" in pspdisasm.__all__
    assert "apply_psp_relocation_word" in pspdisasm.__all__
