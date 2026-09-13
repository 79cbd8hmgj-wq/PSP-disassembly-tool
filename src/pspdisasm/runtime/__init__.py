"""Phase 8C: general PSP runtime intelligence (PPSSPP debugger transport, sessions, and evidence).

Not imported from the top-level `pspdisasm` package: static analysis has no
runtime dependency, so `import pspdisasm` alone never pulls in this
subpackage's socket/subprocess-facing code. Use `from pspdisasm.runtime
import ...` directly.
"""

from ..model import (
    RuntimeAddress,
    RuntimeAddressDomain,
    RuntimeBacktrace,
    RuntimeBreakpointObservation,
    RuntimeEvidenceSet,
    RuntimeMemoryObservation,
    RuntimeModule,
    RuntimeReconciliation,
    RuntimeRegisterSnapshot,
    RuntimeSessionInfo,
)
from .bundle import DebuggerBundleIdentity, DebuggerBundleProfile, verify_ppsspp_bundle
from .modules import (
    HleModuleListSource,
    RuntimeModuleResolution,
    RuntimeModuleSource,
    UserProvidedModuleSource,
    build_runtime_module_map,
    load_static_placements,
)
from .reconciliation import (
    ObservationGroup,
    RuntimeEvidenceStatus,
    StaticCandidate,
    reconcile_observation,
    reconcile_workspace,
)
from .session import LaunchSpec, RuntimeSession
from .transport import DebuggerEvent, PpssppDebuggerTransport
from .workspace import (
    RUNTIME_SCHEMA_VERSION,
    list_sessions,
    load_module_map,
    load_observations,
    load_reconciliation,
    load_session_info,
    save_evidence_set,
    save_module_map,
    save_observations,
    save_reconciliation,
    save_session_info,
)

__all__ = [
    "RUNTIME_SCHEMA_VERSION",
    "DebuggerBundleIdentity",
    "DebuggerBundleProfile",
    "DebuggerEvent",
    "HleModuleListSource",
    "LaunchSpec",
    "ObservationGroup",
    "PpssppDebuggerTransport",
    "RuntimeAddress",
    "RuntimeAddressDomain",
    "RuntimeBacktrace",
    "RuntimeBreakpointObservation",
    "RuntimeEvidenceSet",
    "RuntimeEvidenceStatus",
    "RuntimeMemoryObservation",
    "RuntimeModule",
    "RuntimeModuleResolution",
    "RuntimeModuleSource",
    "RuntimeReconciliation",
    "RuntimeRegisterSnapshot",
    "RuntimeSession",
    "RuntimeSessionInfo",
    "StaticCandidate",
    "UserProvidedModuleSource",
    "build_runtime_module_map",
    "list_sessions",
    "load_module_map",
    "load_observations",
    "load_reconciliation",
    "load_session_info",
    "load_static_placements",
    "reconcile_observation",
    "reconcile_workspace",
    "save_evidence_set",
    "save_module_map",
    "save_observations",
    "save_reconciliation",
    "save_session_info",
    "verify_ppsspp_bundle",
]
