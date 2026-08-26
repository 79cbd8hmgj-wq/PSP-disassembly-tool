from __future__ import annotations

from pspdisasm.model import Relocation


def test_relocation_keeps_legacy_constructor_and_adds_optional_prxreloc2_provenance():
    legacy = Relocation(
        section=".rel.text",
        offset=4,
        info=2,
        type=2,
        type_name="R_MIPS_32",
        symbol_index=0,
        target_section_index=1,
    )

    assert legacy.source_segment_index is None
    assert legacy.target_segment_index is None
    assert legacy.stream_offset is None
    assert legacy.addend is None
    assert legacy.encoding_flags is None
