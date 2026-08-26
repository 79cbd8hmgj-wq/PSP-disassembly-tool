from __future__ import annotations

from pspdisasm.resource_formats import detect_resource_at, scan_resource_bytes


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"
JPEG = b"\xff\xd8\xff\xe0\x00\x04AB\xff\xd9"
RIFF_WAVE = b"RIFF" + (16).to_bytes(4, "little") + b"WAVEfmt " + (4).to_bytes(4, "little") + b"\x01\x00\x01\x00"
RIFF_ATRAC = b"RIFF" + (16).to_bytes(4, "little") + b"WAVEfmt " + (4).to_bytes(4, "little") + b"\x70\x02\x02\x00"
GIM = b"MIG.00.1PSP\x00" + b"\x00" * 20


def _psmf(stream_offset: int = 0x800, stream_size: int = 0x1000, version: bytes = b"0015") -> bytes:
    return b"PSMF" + version + stream_offset.to_bytes(4, "big") + stream_size.to_bytes(4, "big") + b"\x00" * 16


def _vag(payload_size: int = 16, sample_rate: int = 44100) -> bytes:
    header = bytearray(0x30)
    header[0:4] = b"VAGp"
    header[4:8] = (0x20).to_bytes(4, "big")
    header[12:16] = payload_size.to_bytes(4, "big")
    header[16:20] = sample_rate.to_bytes(4, "big")
    return bytes(header) + b"\x00" * payload_size


def test_detect_resource_at_preserves_phase6d_known_format_metadata():
    png = detect_resource_at(PNG)
    assert png is not None
    assert (png.offset, png.format, png.kind, png.size, png.extractable, png.confidence) == (
        0,
        "png",
        "image",
        len(PNG),
        True,
        1.0,
    )
    assert png.suggested_extension == "png"
    assert png.metadata == {"chunk_count": 1}

    jpeg = detect_resource_at(JPEG)
    assert jpeg is not None
    assert (jpeg.format, jpeg.kind, jpeg.size, jpeg.extractable) == ("jpeg", "image", len(JPEG), True)

    wave = detect_resource_at(RIFF_WAVE)
    assert wave is not None
    assert (wave.format, wave.kind, wave.size, wave.extractable) == ("wav", "audio", len(RIFF_WAVE), True)
    assert wave.metadata["codec_tag"] == 0x0001

    atrac = detect_resource_at(RIFF_ATRAC)
    assert atrac is not None
    assert atrac.format == "at3"
    assert atrac.metadata["codec_tag"] == 0x0270
    assert "atrac_codec" in atrac.evidence

    vag_bytes = _vag()
    vag = detect_resource_at(vag_bytes)
    assert vag is not None
    assert (vag.format, vag.kind, vag.size, vag.extractable) == ("vag", "audio", len(vag_bytes), True)
    assert vag.metadata["sample_rate"] == 44100

    gim = detect_resource_at(GIM)
    assert gim is not None
    assert (gim.format, gim.kind, gim.size, gim.extractable, gim.confidence) == (
        "gim",
        "image",
        None,
        False,
        0.90,
    )

    psmf = detect_resource_at(_psmf())
    assert psmf is not None
    assert (psmf.format, psmf.kind, psmf.size, psmf.extractable, psmf.confidence) == (
        "pmf",
        "video",
        None,
        False,
        0.95,
    )
    assert psmf.metadata == {"version": "0015", "stream_offset": 0x800, "stream_size": 0x1000}


def test_detect_resource_at_rejects_malformed_or_truncated_candidates():
    assert detect_resource_at(PNG[:-4]) is None
    assert detect_resource_at(b"\xff\xd8garbage without eoi") is None
    assert detect_resource_at(b"RIFF" + (0x1000).to_bytes(4, "little") + b"WAVEfmt " + b"\x00" * 8) is None
    assert detect_resource_at(_vag(sample_rate=0)) is None
    assert detect_resource_at(_vag(payload_size=64)[:-32]) is None
    assert detect_resource_at(_psmf(version=b"9999")) is None
    assert detect_resource_at(_psmf(stream_offset=0x801)) is None
    assert detect_resource_at(_psmf(stream_size=0)) is None


def test_scan_resource_bytes_finds_unaligned_resources_and_suppresses_nested_overlap():
    matches = scan_resource_bytes(b"XYZ" + PNG)
    assert [(item.offset, item.format, item.size) for item in matches] == [(3, "png", len(PNG))]

    junk = b"JUNK" + len(PNG).to_bytes(4, "little") + PNG
    body = b"WAVE" + junk
    riff = b"RIFF" + len(body).to_bytes(4, "little") + body
    matches = scan_resource_bytes(riff)
    assert len(matches) == 1
    assert matches[0].format == "wav"
