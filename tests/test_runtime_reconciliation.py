from __future__ import annotations

from dataclasses import asdict

from pspdisasm.model import RuntimeAddress, RuntimeBreakpointObservation, RuntimeModule
from pspdisasm.runtime.reconciliation import (
    ObservationGroup,
    RuntimeEvidenceStatus,
    StaticCandidate,
    reconcile_observation,
    reconcile_workspace,
)

MODULE_PATH = "PSP_GAME/USRDIR/LOCKED.PRX"


def _runtime_addr(value: int) -> RuntimeAddress:
    return RuntimeAddress(domain="runtime", value=value)


def _observation(address_value: int, sequence: int = 1) -> RuntimeBreakpointObservation:
    return RuntimeBreakpointObservation(
        session_id="s1",
        sequence=sequence,
        breakpoint_address=_runtime_addr(address_value),
        hit_count=1,
    )


def _module(base: int, size: int | None = None, path: str | None = MODULE_PATH) -> RuntimeModule:
    return RuntimeModule(
        name=path,
        runtime_base=_runtime_addr(base),
        runtime_size=size,
        static_module_path=path,
        resolution_status="user_provided",
    )


def test_reconcile_observation_maps_runtime_address_to_static_function():
    module = _module(base=0x09A00000)
    placements = {MODULE_PATH: {"load_address": 0x08804000, "image_size": 0x20000}}
    candidates = {MODULE_PATH: [StaticCandidate(kind="function", address=0x0881B420, evidence=["sub_0881B420"])]}

    observation = _observation(0x09A17420)
    result = reconcile_observation(
        observation, modules=[module], module_placements=placements, static_candidates=candidates
    )

    assert result.status == RuntimeEvidenceStatus.CORROBORATED.value
    assert result.resolved_module_offset.value == 0x17420
    assert result.static_address.value == 0x0881B420
    assert result.static_evidence == ["sub_0881B420"]
    assert result.observation_count == 1


def test_reconcile_observation_uses_real_runtime_base_even_when_it_differs_from_analysis_placement():
    """The synthetic Phase 7G analysis placement (0x08804000) is deliberately
    not the real observed runtime base (0x09A00000) — reconciliation must
    still land on the correct static function via the offset alone, never by
    assuming the analysis placement was the true load address."""
    module = _module(base=0x09A00000)
    placements = {MODULE_PATH: {"load_address": 0x08804000, "image_size": 0x20000}}
    candidates = {MODULE_PATH: [StaticCandidate(kind="function", address=0x0881B420, evidence=["sub_0881B420"])]}

    result = reconcile_observation(
        _observation(0x09A17420), modules=[module], module_placements=placements, static_candidates=candidates
    )

    assert result.static_address.value == 0x0881B420
    assert result.status == RuntimeEvidenceStatus.CORROBORATED.value


def test_reconcile_observation_no_matching_module_is_unresolved():
    result = reconcile_observation(
        _observation(0x0A000000), modules=[_module(base=0x09A00000, size=0x1000)], module_placements={}, static_candidates={}
    )
    assert result.status == RuntimeEvidenceStatus.UNRESOLVED.value
    assert result.resolved_module_offset is None
    assert result.static_address is None


def test_reconcile_observation_outside_known_runtime_module_range_is_unresolved():
    module = _module(base=0x09A00000, size=0x100)
    result = reconcile_observation(
        _observation(0x09A00200), modules=[module], module_placements={}, static_candidates={}
    )
    assert result.status == RuntimeEvidenceStatus.UNRESOLVED.value


def test_reconcile_observation_offset_beyond_static_image_size_is_conflicting():
    # The runtime module's own size is unknown/unbounded (as an HLE report
    # without a size, or a user-provided mapping, might be), but the offset
    # exceeds what static analysis declared for this module's image size.
    module = _module(base=0x09A00000, size=None)
    placements = {MODULE_PATH: {"load_address": 0x08804000, "image_size": 0x100}}
    result = reconcile_observation(
        _observation(0x09A00200), modules=[module], module_placements=placements, static_candidates={}
    )
    assert result.status == RuntimeEvidenceStatus.CONFLICTING.value
    assert "exceeds" in result.conflicts[0]


def test_reconcile_observation_without_static_module_path_is_runtime_observed():
    module = _module(base=0x09A00000, path=None)
    result = reconcile_observation(
        _observation(0x09A00010), modules=[module], module_placements={}, static_candidates={}
    )
    assert result.status == RuntimeEvidenceStatus.RUNTIME_OBSERVED.value
    assert result.resolved_module_offset.value == 0x10


def test_reconcile_observation_without_placement_is_runtime_observed_not_fabricated():
    module = _module(base=0x09A00000)
    result = reconcile_observation(
        _observation(0x09A00010), modules=[module], module_placements={}, static_candidates={}
    )
    assert result.status == RuntimeEvidenceStatus.RUNTIME_OBSERVED.value
    assert result.static_address is None


def test_reconcile_observation_no_static_candidate_at_address_is_runtime_observed():
    module = _module(base=0x09A00000)
    placements = {MODULE_PATH: {"load_address": 0x08804000}}
    result = reconcile_observation(
        _observation(0x09A00010), modules=[module], module_placements=placements, static_candidates={}
    )
    assert result.status == RuntimeEvidenceStatus.RUNTIME_OBSERVED.value
    assert result.static_address.value == 0x08804010


def test_reconcile_workspace_escalates_to_runtime_verified_on_repeat_observations():
    module = _module(base=0x09A00000)
    placements = {MODULE_PATH: {"load_address": 0x08804000}}
    candidates = {MODULE_PATH: [StaticCandidate(kind="call_edge_target", address=0x0881B420, evidence=["sub_0881B420"])]}
    groups = [ObservationGroup(call_site_key="call@0x08801000", observation=_observation(0x09A17420, seq)) for seq in range(1, 28)]

    results = reconcile_workspace(groups, modules=[module], module_placements=placements, static_candidates=candidates)

    assert results[0].status == RuntimeEvidenceStatus.CORROBORATED.value
    assert results[-1].status == RuntimeEvidenceStatus.RUNTIME_VERIFIED.value
    assert results[-1].observation_count == 27
    assert results[-1].static_address.value == 0x0881B420


def test_reconcile_workspace_flags_conflicting_targets_at_same_call_site_without_erasing_either():
    module = _module(base=0x09A00000)
    placements = {MODULE_PATH: {"load_address": 0x08804000}}
    candidates = {
        MODULE_PATH: [
            StaticCandidate(kind="function", address=0x0881B420, evidence=["sub_0881B420"]),
            StaticCandidate(kind="function", address=0x0881C000, evidence=["sub_0881C000"]),
        ]
    }
    groups = [
        ObservationGroup(call_site_key="call@0x08801000", observation=_observation(0x09A17420, 1)),
        ObservationGroup(call_site_key="call@0x08801000", observation=_observation(0x09A18000, 2)),
    ]

    results = reconcile_workspace(groups, modules=[module], module_placements=placements, static_candidates=candidates)

    assert all(r.status == RuntimeEvidenceStatus.CONFLICTING.value for r in results)
    assert results[0].static_address.value == 0x0881B420
    assert results[1].static_address.value == 0x0881C000
    assert "multiple distinct runtime" in results[0].conflicts[-1]
    assert "multiple distinct runtime" in results[1].conflicts[-1]


def test_reconcile_workspace_isolates_an_unresolvable_observation_from_the_rest_of_the_batch():
    module = _module(base=0x09A00000, size=0x1000)
    # This observation's address matches no runtime module range; it must not
    # prevent the well-formed observation alongside it from reconciling.
    unresolvable = ObservationGroup(call_site_key="bad", observation=_observation(0x0BADC0DE))
    good = ObservationGroup(call_site_key="ok", observation=_observation(0x09A00010))

    results = reconcile_workspace([unresolvable, good], modules=[module], module_placements={}, static_candidates={})

    assert results[0].status == RuntimeEvidenceStatus.UNRESOLVED.value
    assert results[1].status == RuntimeEvidenceStatus.RUNTIME_OBSERVED.value


def test_reconciliation_serializes_deterministically_without_timestamps():
    module = _module(base=0x09A00000)
    placements = {MODULE_PATH: {"load_address": 0x08804000}}
    candidates = {MODULE_PATH: [StaticCandidate(kind="function", address=0x08804010, evidence=["sub_08804010"])]}

    result = reconcile_observation(
        _observation(0x09A00010), modules=[module], module_placements=placements, static_candidates=candidates
    )
    payload = asdict(result)

    assert payload == asdict(
        reconcile_observation(
            _observation(0x09A00010), modules=[module], module_placements=placements, static_candidates=candidates
        )
    )
    assert "timestamp" not in payload
