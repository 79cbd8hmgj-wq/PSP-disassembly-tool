from __future__ import annotations

import pspdisasm


def test_phase7a_game_image_api_is_public() -> None:
    assert pspdisasm.__version__ == "0.10.0"
    assert callable(pspdisasm.analyze_game_image)
    assert callable(pspdisasm.extract_game_executables)
    assert callable(pspdisasm.parse_param_sfo)
    assert callable(pspdisasm.read_game_file)
