from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from pspdisasm.resource_containers import (
    ContainerCandidateProfile,
    ContainerInspection,
    ResourceContainerParser,
    group_container_families,
    profile_container_candidate,
    select_container_parser,
)


def test_profile_container_candidate_records_bounded_fingerprint_and_entropy(tmp_path):
    payload = b"PACK" + bytes(range(32)) + b"A" * 70000
    path = tmp_path / "DATA.DAT"
    path.write_bytes(payload)

    profile = profile_container_candidate(
        path,
        "PSP_GAME/USRDIR/DATA.DAT",
        embedded_count=2,
        bounded_embedded_bytes=24,
    )

    assert isinstance(profile, ContainerCandidateProfile)
    assert profile.path == "PSP_GAME/USRDIR/DATA.DAT"
    assert profile.size == len(payload)
    assert profile.suffix == ".dat"
    assert profile.prefix_hex == payload[:16].hex()
    assert profile.prefix_ascii == "PACK" + "." * 12
    assert 0.0 <= profile.sample_entropy <= 8.0
    assert profile.embedded_count == 2
    assert profile.bounded_embedded_bytes == 24
    assert profile.family_key == ".dat:5041434b"


def test_group_container_families_is_deterministic(tmp_path):
    first = tmp_path / "A.DAT"
    second = tmp_path / "B.DAT"
    third = tmp_path / "C.BIN"
    first.write_bytes(b"PACKaaaa")
    second.write_bytes(b"PACKbbbb")
    third.write_bytes(b"PACKcccc")

    profiles = [
        profile_container_candidate(second, "PSP_GAME/B.DAT"),
        profile_container_candidate(third, "PSP_GAME/C.BIN"),
        profile_container_candidate(first, "PSP_GAME/A.DAT"),
    ]

    families = group_container_families(profiles)

    assert [family.family_key for family in families] == [
        ".bin:5041434b",
        ".dat:5041434b",
    ]
    dat_family = families[1]
    assert dat_family.member_count == 2
    assert dat_family.member_paths == ["PSP_GAME/A.DAT", "PSP_GAME/B.DAT"]
    assert dat_family.total_size == 16


@dataclass
class _Parser:
    name: str
    confidence: float
    fail: bool = False

    def probe(self, prefix: bytes, path: str) -> float:
        if self.fail:
            raise RuntimeError(f"{self.name} probe failed")
        return self.confidence

    def inspect(self, path: Path) -> ContainerInspection:
        return ContainerInspection(
            parser_name=self.name,
            format_name=self.name,
            confidence=self.confidence,
        )


def test_resource_container_parser_protocol_is_runtime_usable():
    parser = _Parser("synthetic", 0.99)
    assert isinstance(parser, ResourceContainerParser)


def test_select_container_parser_uses_threshold_and_highest_confidence():
    selected, confidence, warnings = select_container_parser(
        b"PACKpayload",
        "PSP_GAME/USRDIR/DATA.DAT",
        [_Parser("low", 0.89), _Parser("best", 0.98), _Parser("middle", 0.95)],
    )

    assert selected is not None
    assert selected.name == "best"
    assert confidence == pytest.approx(0.98)
    assert warnings == []


def test_select_container_parser_ties_by_name_and_ignores_invalid_probes():
    selected, confidence, warnings = select_container_parser(
        b"PACKpayload",
        "PSP_GAME/USRDIR/DATA.DAT",
        [
            _Parser("zeta", 0.95),
            _Parser("alpha", 0.95),
            _Parser("nan", float("nan")),
            _Parser("too-high", 1.5),
            _Parser("broken", 1.0, fail=True),
        ],
    )

    assert selected is not None
    assert selected.name == "alpha"
    assert confidence == pytest.approx(0.95)
    assert len(warnings) == 3
    assert any("nan" in warning for warning in warnings)
    assert any("too-high" in warning for warning in warnings)
    assert any("broken" in warning for warning in warnings)
