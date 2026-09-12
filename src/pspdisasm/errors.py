class ParseError(ValueError):
    """Raised when an input cannot be safely parsed."""


class EngineUnavailableError(RuntimeError):
    """Raised when an optional disassembly engine cannot be loaded."""


class DisassemblyError(RuntimeError):
    """Raised when instruction analysis cannot be completed safely."""


class DecompilerUnavailableError(RuntimeError):
    """Raised when the external assisted-decompilation backend cannot be located."""


class DecompilationError(RuntimeError):
    """Raised when assisted C decompilation cannot be completed safely."""


class MatcherUnavailableError(RuntimeError):
    """Raised when an external matching backend or objdump cannot be located."""


class MatchingError(RuntimeError):
    """Raised when original-vs-recompiled matching cannot be completed safely."""


class WorkspaceError(RuntimeError):
    """Raised when a local PSP workspace cannot be prepared or used safely."""


class AnalysisPackError(WorkspaceError):
    """Raised when a portable analysis pack cannot be produced safely."""


class RecoveryBackendUnavailableError(RuntimeError):
    """Raised when no recovery backend is configured, resolvable, or accepts a module."""

    def __init__(self, message: str, *, provenance: object | None = None) -> None:
        super().__init__(message)
        self.provenance = provenance


class RecoveryError(RuntimeError):
    """Raised when a recovery backend ran but produced unusable output."""

    def __init__(self, message: str, *, provenance: object | None = None) -> None:
        super().__init__(message)
        self.provenance = provenance


class RecoveryVerificationError(RecoveryError):
    """Raised when recovered output failed the post-recovery verification gate."""


class RecoveryOutputTooLargeError(RecoveryError):
    """Raised when a recovery backend's output exceeds the configured size bound."""
