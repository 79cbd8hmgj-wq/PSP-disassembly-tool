from __future__ import annotations


def test_phase7g_placement_api_is_public():
    import pspdisasm

    assert pspdisasm.ModulePlacement.__name__ == "ModulePlacement"
    assert pspdisasm.ModulePlacementInput.__name__ == "ModulePlacementInput"
    assert callable(pspdisasm.plan_module_placements)
