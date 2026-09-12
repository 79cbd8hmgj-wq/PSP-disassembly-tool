from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum

from ..model import (
    RuntimeAddress,
    RuntimeAddressDomain,
    RuntimeBreakpointObservation,
    RuntimeModule,
    RuntimeReconciliation,
)


class RuntimeEvidenceStatus(str, Enum):
    UNRESOLVED = "unresolved"
    INFERRED = "inferred"
    CORROBORATED = "corroborated"
    RUNTIME_OBSERVED = "runtime_observed"
    RUNTIME_VERIFIED = "runtime_verified"
    CONFLICTING = "conflicting"


@dataclass(frozen=True, slots=True)
class StaticCandidate:
    """One static fact a caller wants runtime evidence reconciled against.

    `address` is in the ANALYSIS domain — the same address space
    FunctionRecord/CallGraphEdge/JumpTableRecord already use for this module
    (i.e. placement.load_address-relative), not the module's raw ELF vaddr.
    """

    kind: str
    address: int
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ObservationGroup:
    """Binds one runtime observation to the static call site it's evidence for.

    `call_site_key` is caller-chosen (typically the static call site's own
    analysis address as a string) and is what lets reconcile_workspace detect
    that two different observations at the *same* call site resolved to two
    different runtime targets.
    """

    call_site_key: str
    observation: RuntimeBreakpointObservation


def _find_module(runtime_value: int, modules: Sequence[RuntimeModule]) -> RuntimeModule | None:
    """Find the module whose runtime range contains this address.

    A module with an unknown size (`runtime_size is None`, e.g. an
    unsized user-provided mapping) matches any address at or after its
    base — the best that can be said without a known upper bound. Prefer
    a module with a known, bounding size when one is available.
    """
    unbounded_match: RuntimeModule | None = None
    for module in modules:
        base = module.runtime_base.value
        if runtime_value < base:
            continue
        if module.runtime_size is None:
            if unbounded_match is None:
                unbounded_match = module
            continue
        if runtime_value < base + module.runtime_size:
            return module
    return unbounded_match


def reconcile_observation(
    observation: RuntimeBreakpointObservation,
    *,
    modules: Sequence[RuntimeModule],
    module_placements: Mapping[str, Mapping[str, object]],
    static_candidates: Mapping[str, Sequence[StaticCandidate]],
) -> RuntimeReconciliation:
    """Map one runtime observation back to a static module/address, never guessing a load address.

    runtime address -> runtime module range (from an already-built
    RuntimeModuleMap) -> module-relative offset -> that module's own
    Phase 7G placement.load_address -> analysis address -> match against
    caller-supplied static candidates at that exact analysis address.
    Any step that cannot be proven leaves the observation UNRESOLVED rather
    than guessing forward.
    """
    runtime_address = observation.breakpoint_address
    module = _find_module(runtime_address.value, modules)
    if module is None:
        return RuntimeReconciliation(
            static_kind="unresolved",
            static_address=None,
            static_evidence=[],
            runtime_address=runtime_address,
            resolved_module_offset=None,
            observation_count=1,
            status=RuntimeEvidenceStatus.UNRESOLVED.value,
            conflicts=["no runtime module range contains this address"],
        )

    offset = runtime_address.value - module.runtime_base.value
    module_offset = RuntimeAddress(
        domain=RuntimeAddressDomain.MODULE_RELATIVE.value, value=offset, module_path=module.static_module_path
    )

    if module.static_module_path is None:
        return RuntimeReconciliation(
            static_kind="unresolved",
            static_address=None,
            static_evidence=[],
            runtime_address=runtime_address,
            resolved_module_offset=module_offset,
            observation_count=1,
            status=RuntimeEvidenceStatus.RUNTIME_OBSERVED.value,
            conflicts=[],
        )

    placement = module_placements.get(module.static_module_path)
    load_address = placement.get("load_address") if isinstance(placement, Mapping) else None
    if not isinstance(load_address, int):
        return RuntimeReconciliation(
            static_kind="unresolved",
            static_address=None,
            static_evidence=[],
            runtime_address=runtime_address,
            resolved_module_offset=module_offset,
            observation_count=1,
            status=RuntimeEvidenceStatus.RUNTIME_OBSERVED.value,
            conflicts=[],
        )

    # `_find_module` already proved this address is within the module's own
    # *observed* runtime range (when that range is known). Here we instead
    # check the offset against the *static* placement's declared image_size:
    # a real runtime module bigger than what static analysis captured is a
    # genuine discrepancy worth surfacing, not a silent RUNTIME_OBSERVED.
    static_image_size = placement.get("image_size") if isinstance(placement, Mapping) else None
    if isinstance(static_image_size, int) and offset >= static_image_size:
        return RuntimeReconciliation(
            static_kind="unresolved",
            static_address=None,
            static_evidence=[],
            runtime_address=runtime_address,
            resolved_module_offset=module_offset,
            observation_count=1,
            status=RuntimeEvidenceStatus.CONFLICTING.value,
            conflicts=[
                f"offset 0x{offset:X} exceeds this module's static image_size 0x{static_image_size:X}; "
                "the observed runtime module is larger than static analysis captured"
            ],
        )

    analysis_value = load_address + offset
    analysis_address = RuntimeAddress(
        domain=RuntimeAddressDomain.ANALYSIS.value, value=analysis_value, module_path=module.static_module_path
    )

    candidates = [
        candidate
        for candidate in static_candidates.get(module.static_module_path, ())
        if candidate.address == analysis_value
    ]
    if not candidates:
        return RuntimeReconciliation(
            static_kind="unresolved",
            static_address=analysis_address,
            static_evidence=[],
            runtime_address=runtime_address,
            resolved_module_offset=module_offset,
            observation_count=1,
            status=RuntimeEvidenceStatus.RUNTIME_OBSERVED.value,
            conflicts=[],
        )

    kinds = sorted({candidate.kind for candidate in candidates})
    evidence = [note for candidate in candidates for note in candidate.evidence]
    return RuntimeReconciliation(
        static_kind="/".join(kinds),
        static_address=analysis_address,
        static_evidence=evidence,
        runtime_address=runtime_address,
        resolved_module_offset=module_offset,
        observation_count=1,
        status=RuntimeEvidenceStatus.CORROBORATED.value,
        conflicts=[],
    )


def reconcile_workspace(
    groups: Sequence[ObservationGroup],
    *,
    modules: Sequence[RuntimeModule],
    module_placements: Mapping[str, Mapping[str, object]],
    static_candidates: Mapping[str, Sequence[StaticCandidate]],
) -> list[RuntimeReconciliation]:
    """Reconcile a batch of observations, accumulating counts and detecting conflicts.

    Each observation is isolated: one malformed/unresolvable observation
    never prevents the rest of the batch from being reconciled. Repeated
    observations resolving to the same (call site, target) pair accumulate
    `observation_count` and escalate CORROBORATED -> RUNTIME_VERIFIED; two
    observations at the *same* call_site_key resolving to *different*
    targets are both kept, both flagged CONFLICTING, and neither is erased.
    """
    per_group: list[RuntimeReconciliation] = []
    counts: dict[tuple[str, int | None], int] = {}
    targets_by_site: dict[str, set[int]] = {}

    for group in groups:
        try:
            base = reconcile_observation(
                group.observation,
                modules=modules,
                module_placements=module_placements,
                static_candidates=static_candidates,
            )
        except Exception as exc:  # noqa: BLE001 - one bad observation must not abort the batch
            per_group.append(
                RuntimeReconciliation(
                    static_kind="unresolved",
                    static_address=None,
                    static_evidence=[],
                    runtime_address=group.observation.breakpoint_address,
                    resolved_module_offset=None,
                    observation_count=1,
                    status=RuntimeEvidenceStatus.UNRESOLVED.value,
                    conflicts=[f"reconciliation failed: {exc}"],
                )
            )
            continue

        target_value = base.static_address.value if base.static_address is not None else None
        key = (group.call_site_key, target_value)
        counts[key] = counts.get(key, 0) + 1
        reconciled = replace(base, observation_count=counts[key])
        if target_value is not None:
            escalated = (
                RuntimeEvidenceStatus.RUNTIME_VERIFIED.value
                if reconciled.status == RuntimeEvidenceStatus.CORROBORATED.value and counts[key] > 1
                else reconciled.status
            )
            reconciled = replace(reconciled, status=escalated)
            targets_by_site.setdefault(group.call_site_key, set()).add(target_value)
        per_group.append(reconciled)

    finalized: list[RuntimeReconciliation] = []
    for group, reconciled in zip(groups, per_group):
        targets = targets_by_site.get(group.call_site_key, set())
        if len(targets) > 1 and reconciled.status != RuntimeEvidenceStatus.UNRESOLVED.value:
            finalized.append(
                replace(
                    reconciled,
                    status=RuntimeEvidenceStatus.CONFLICTING.value,
                    conflicts=[
                        *reconciled.conflicts,
                        f"call site {group.call_site_key!r} resolved to multiple distinct runtime "
                        "targets: " + ", ".join(f"0x{value:08X}" for value in sorted(targets)),
                    ],
                )
            )
        else:
            finalized.append(reconciled)
    return finalized
