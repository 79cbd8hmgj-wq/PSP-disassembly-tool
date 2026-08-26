from __future__ import annotations

from dataclasses import asdict
import importlib.util

import pspdisasm.model as model


BASE = 0x08802000
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"
JPEG = b"\xff\xd8\xff\xe0\x00\x04AB\xff\xd9"
RIFF_WAVE = b"RIFF" + (16).to_bytes(4, "little") + b"WAVEfmt " + (4).to_bytes(4, "little") + b"\x01\x00\x01\x00"
RIFF_ATRAC = b"RIFF" + (16).to_bytes(4, "little") + b"WAVEfmt " + (4).to_bytes(4, "little") + b"\x70\x02\x02\x00"
GIM = b"MIG.00.1PSP\x00" + b"\x00" * 20
PSMF = b"PSMF" + b"\x00" * 28


def _vag(payload_size: int = 16, sample_rate: int = 44100) -> bytes:
    header = bytearray(0x30)
    header[0:4] = b"VAGp"
    header[4:8] = (0x20).to_bytes(4, "big")
    header[12:16] = payload_size.to_bytes(4, "big")
    header[16:20] = sample_rate.to_bytes(4, "big")
    return bytes(header) + b"\x00" * payload_size


def _context(payload: bytes, *, flags: int = 0x2, section_type: int = 1):
    section = model.Section(
        index=1,
        name=".rodata" if not flags & 0x4 else ".text",
        type=section_type,
        flags=flags,
        addr=BASE,
        offset=0,
        size=len(payload),
        link=0,
        info=0,
        addralign=1,
        entsize=0,
        kind="executable" if flags & 0x4 else "readonly",
    )
    header = model.ElfHeader(2, 8, 1, BASE, 0, 0, 0, 0x34, 0x20, 0, 0x28, 2, 0)
    elf = model.ElfImage(header, "little", [], [section], payload)
    executable = model.ExecutableModel("fixture.elf", "elf", "elf", False, endianness="little", elf_header=header, sections=[section])
    disassembly = model.DisassemblyResult("fixture.elf")
    typing = model.DataTypingResult("fixture.elf")
    return executable, disassembly, typing, elf


def _analyze(payload: bytes, *, flags: int = 0x2, section_type: int = 1, disassembly=None, typing=None):
    assert importlib.util.find_spec("pspdisasm.asset_discovery") is not None
    from pspdisasm.asset_discovery import analyze_assets

    executable, default_disassembly, default_typing, elf = _context(payload, flags=flags, section_type=section_type)
    return analyze_assets(executable, disassembly or default_disassembly, typing or default_typing, elf)


def test_asset_models_are_normalized_dataclasses():
    assert hasattr(model, "AssetRecord")
    assert hasattr(model, "AssetReferenceRecord")
    assert hasattr(model, "AssetDiscoveryResult")

    asset = model.AssetRecord(
        address=BASE,
        file_offset=0,
        section=".rodata",
        format="png",
        kind="image",
        size=len(PNG),
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
    result = model.AssetDiscoveryResult("fixture.elf", [asset], [reference], [])

    normalized = asdict(result)
    assert normalized["assets"][0]["format"] == "png"
    assert normalized["assets"][0]["metadata"] == {"chunk_count": 1}
    assert normalized["references"][0]["asset_address"] == BASE


def test_detects_bounded_png_and_never_overreads_truncated_png():
    result = _analyze(PNG)
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert (asset.format, asset.kind, asset.size, asset.extractable, asset.confidence) == ("png", "image", len(PNG), True, 1.0)

    truncated = _analyze(PNG[:-4])
    assert truncated.assets == []


def test_detects_bounded_jpeg_and_rejects_soi_only_prefix():
    result = _analyze(JPEG)
    assert [(item.format, item.size, item.extractable) for item in result.assets] == [("jpeg", len(JPEG), True)]
    assert _analyze(b"\xff\xd8garbage without eoi").assets == []


def test_detects_wave_and_atrac_specialization_with_bounded_riff_extent():
    wave = _analyze(RIFF_WAVE).assets[0]
    assert (wave.format, wave.kind, wave.size, wave.extractable) == ("wav", "audio", len(RIFF_WAVE), True)
    assert wave.metadata["codec_tag"] == 0x0001

    atrac = _analyze(RIFF_ATRAC).assets[0]
    assert atrac.format == "at3"
    assert atrac.metadata["codec_tag"] == 0x0270
    assert "atrac_codec" in atrac.evidence

    invalid = b"RIFF" + (0x1000).to_bytes(4, "little") + b"WAVEfmt " + b"\x00" * 8
    assert _analyze(invalid).assets == []


def test_detects_bounded_vag_and_rejects_bad_header_fields():
    valid_bytes = _vag()
    valid = _analyze(valid_bytes).assets[0]
    assert (valid.format, valid.kind, valid.size, valid.extractable) == ("vag", "audio", len(valid_bytes), True)
    assert valid.metadata["sample_rate"] == 44100

    assert _analyze(_vag(sample_rate=0)).assets == []
    assert _analyze(_vag(payload_size=64)[:-32]).assets == []


def test_gim_and_psmf_are_conservative_non_extractable_records():
    gim = _analyze(GIM).assets[0]
    assert (gim.format, gim.kind, gim.size, gim.extractable, gim.confidence) == ("gim", "image", None, False, 0.9)

    psmf = _analyze(PSMF).assets[0]
    assert (psmf.format, psmf.kind, psmf.size, psmf.extractable, psmf.confidence) == ("pmf", "video", None, False, 0.9)


def test_scans_unaligned_signatures_but_not_executable_or_nobits_sections():
    result = _analyze(b"XYZ" + PNG)
    assert len(result.assets) == 1
    assert result.assets[0].address == BASE + 3
    assert result.assets[0].file_offset == 3

    assert _analyze(PNG, flags=0x6).assets == []
    assert _analyze(PNG, section_type=8).assets == []


def test_validated_outer_asset_suppresses_overlapping_nested_signature():
    junk = b"JUNK" + len(PNG).to_bytes(4, "little") + PNG
    body = b"WAVE" + junk
    riff = b"RIFF" + len(body).to_bytes(4, "little") + body
    result = _analyze(riff)
    assert len(result.assets) == 1
    assert result.assets[0].format == "wav"
