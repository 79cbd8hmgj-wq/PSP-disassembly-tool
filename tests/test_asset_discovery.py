from __future__ import annotations

from dataclasses import asdict

import pspdisasm.model as model


def test_asset_models_are_normalized_dataclasses():
    assert hasattr(model, "AssetRecord")
    assert hasattr(model, "AssetReferenceRecord")
    assert hasattr(model, "AssetDiscoveryResult")

    asset = model.AssetRecord(
        address=0x08802000,
        file_offset=0x200,
        section=".rodata",
        format="png",
        kind="image",
        size=20,
        confidence=1.0,
        evidence=["png_signature", "png_iend"],
        extractable=True,
        suggested_extension="png",
        metadata={"chunk_count": 1},
    )
    reference = model.AssetReferenceRecord(
        source_address=0x08800100,
        asset_address=asset.address,
        source_function="func_08800100",
        reference_kind="direct",
        asset_format="png",
        confidence=1.0,
        evidence=["reference_record", "asset_exact_start"],
    )
    result = model.AssetDiscoveryResult(
        source_name="fixture.elf",
        assets=[asset],
        references=[reference],
        warnings=[],
    )

    normalized = asdict(result)
    assert normalized["assets"][0]["format"] == "png"
    assert normalized["assets"][0]["metadata"] == {"chunk_count": 1}
    assert normalized["references"][0]["asset_address"] == 0x08802000
