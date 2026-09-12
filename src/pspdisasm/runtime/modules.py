from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..model import RuntimeAddress, RuntimeAddressDomain, RuntimeModule
from .transport import PpssppDebuggerTransport

DEFAULT_MODULE_PROBE_TIMEOUT = 2.0


class RuntimeModuleResolution(str, Enum):
    HLE_REPORTED = "hle_reported"
    USER_PROVIDED = "user_provided"
    UNRESOLVED = "unresolved"


@runtime_checkable
class RuntimeModuleSource(Protocol):
    name: str

    def discover(self, transport: PpssppDebuggerTransport) -> list[RuntimeModule]: ...


class HleModuleListSource:
    """Tier 1: ask PPSSPP directly, if it actually supports it.

    Whether PPSSPP's debugger protocol exposes an HLE module-list event (and
    under what name/schema) is *not* verified against real PPSSPP by this
    toolkit's own test suite — only against the request vocabulary a
    project-owned reference client has proven (which does not include this
    event). This source therefore probes rather than assumes: an "error"
    response, a timeout, or a response that doesn't parse as expected all
    fall through to `[]` so callers move on to the next tier instead of
    fabricating a mapping.
    """

    name = "hle_module_list"

    def __init__(self, *, event: str = "hle.module.list", probe_timeout: float = DEFAULT_MODULE_PROBE_TIMEOUT) -> None:
        self._event = event
        self._probe_timeout = probe_timeout

    def discover(self, transport: PpssppDebuggerTransport) -> list[RuntimeModule]:
        result = transport.try_request(self._event, timeout=self._probe_timeout)
        if result is None:
            return []
        entries = result.payload.get("modules")
        if not isinstance(entries, list):
            return []

        modules: list[RuntimeModule] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            base = entry.get("address", entry.get("base"))
            if not isinstance(base, int):
                continue
            name = entry.get("name")
            size = entry.get("size")
            modules.append(
                RuntimeModule(
                    name=name if isinstance(name, str) else None,
                    runtime_base=RuntimeAddress(domain=RuntimeAddressDomain.RUNTIME.value, value=base),
                    runtime_size=size if isinstance(size, int) else None,
                    static_module_path=None,
                    resolution_status=RuntimeModuleResolution.HLE_REPORTED.value,
                    evidence=[f"PPSSPP {self._event} reported this module directly."],
                )
            )
        return modules


class UserProvidedModuleSource:
    """Tier 4 (the Phase 8C baseline): an explicit, caller-supplied mapping.

    Never claims toolkit-proven accuracy — every produced RuntimeModule says
    plainly that its runtime base came from the caller, not from observed
    PPSSPP state. When a static placement for the same path is available
    (from this workspace's own Phase 7G module_placements.json), the module
    is sized from that real static fact rather than left unsized.
    """

    name = "user_provided"

    def __init__(
        self,
        mapping: Mapping[str, int],
        *,
        static_placements: Mapping[str, Mapping[str, object]] | None = None,
    ) -> None:
        self._mapping = dict(mapping)
        self._static_placements = static_placements or {}

    def discover(self, transport: PpssppDebuggerTransport) -> list[RuntimeModule]:
        del transport
        modules: list[RuntimeModule] = []
        for path in sorted(self._mapping):
            base = self._mapping[path]
            evidence = [f"User-provided runtime base for {path} (0x{base:08X}); not toolkit-proven."]
            size: int | None = None
            placement = self._static_placements.get(path)
            if isinstance(placement, Mapping):
                candidate_size = placement.get("image_size")
                if isinstance(candidate_size, int):
                    size = candidate_size
                    evidence.append("Sized from this workspace's own module_placements.json.")
            modules.append(
                RuntimeModule(
                    name=path,
                    runtime_base=RuntimeAddress(domain=RuntimeAddressDomain.RUNTIME.value, value=base),
                    runtime_size=size,
                    static_module_path=path,
                    resolution_status=RuntimeModuleResolution.USER_PROVIDED.value,
                    evidence=evidence,
                )
            )
        return modules


def build_runtime_module_map(
    transport: PpssppDebuggerTransport,
    sources: Sequence[RuntimeModuleSource],
) -> list[RuntimeModule]:
    """Try each source in the given (preferred) order; the first non-empty result wins.

    Tiers are never merged: mixing a partially-successful HLE-reported list
    with a user-provided fallback would blur which modules are actually
    toolkit-proven, so exactly one source's output is used.
    """
    for source in sources:
        modules = source.discover(transport)
        if modules:
            return modules
    return []


def load_static_placements(workspace_dir: Path | str) -> dict[str, dict[str, object]]:
    """Read this workspace's own module_placements.json, keyed by module path.

    Returns {} if static analysis has not produced a placement file yet;
    that is a normal state (e.g. before `analyze-workspace` has run), not an
    error a module-mapping caller needs to handle specially.
    """
    path = Path(workspace_dir) / "analysis" / "game_project" / "metadata" / "module_placements.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, list):
        return {}
    result: dict[str, dict[str, object]] = {}
    for entry in payload:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            result[entry["path"]] = entry
    return result
