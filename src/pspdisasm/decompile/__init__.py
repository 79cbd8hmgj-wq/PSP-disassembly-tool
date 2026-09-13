"""Phase 8D: automated decompile -> build -> match orchestration over the existing toolchain.

Not imported from the top-level `pspdisasm` package: like `runtime`, this
subpackage drives subprocess-heavy tools (compilers, build commands) on top
of the existing decompiler/matcher modules, so plain `import pspdisasm` never
pulls it in. Use `from pspdisasm.decompile import ...` directly.
"""

from ..model import DecompilationAttempt, FunctionDecompilationState
from .orchestrator import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TIMEOUT_SECONDS,
    AttemptOutcome,
    RetryVariant,
    compute_attempt_id,
    default_variants,
    run_and_persist,
    run_function,
    select_best_attempt,
)
from .queue import (
    DecompilationStatus,
    QueueFilters,
    QueuedFunction,
    discover_functions,
    enrich_with_runtime_evidence,
    enrich_with_static_confidence,
    select_functions,
)
from .reporting import write_match_status_report
from .toolchain import (
    BuildResult,
    BuildToolchain,
    ExternalCompilerToolchain,
    ProjectBuildCommandToolchain,
)
from .workspace import (
    DECOMPILATION_SCHEMA_VERSION,
    decompilation_root,
    list_function_states,
    load_function_state,
    save_function_state,
)

__all__ = [
    "DECOMPILATION_SCHEMA_VERSION",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_SECONDS",
    "AttemptOutcome",
    "BuildResult",
    "BuildToolchain",
    "DecompilationAttempt",
    "DecompilationStatus",
    "ExternalCompilerToolchain",
    "FunctionDecompilationState",
    "ProjectBuildCommandToolchain",
    "QueueFilters",
    "QueuedFunction",
    "RetryVariant",
    "compute_attempt_id",
    "decompilation_root",
    "default_variants",
    "discover_functions",
    "enrich_with_runtime_evidence",
    "enrich_with_static_confidence",
    "list_function_states",
    "load_function_state",
    "run_and_persist",
    "run_function",
    "save_function_state",
    "select_best_attempt",
    "select_functions",
    "write_match_status_report",
]
