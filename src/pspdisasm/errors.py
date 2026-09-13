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


class RuntimeBackendUnavailableError(RuntimeError):
    """Raised when no PPSSPP debugger backend can be reached or launched."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class RuntimeConnectionError(RuntimeError):
    """Raised when a PPSSPP debugger connection/handshake fails after a backend was resolved."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class RuntimeProtocolError(RuntimeError):
    """Raised on a malformed/oversized frame, malformed JSON, or unexpected debugger protocol state."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class RuntimeTimeoutError(RuntimeError):
    """Raised when a connect/request/event-wait operation exceeds its explicit timeout."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class RuntimeCaptureError(RuntimeError):
    """Raised when a bounded runtime observation (e.g. observe_breakpoint) fails safely."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class RuntimeMappingError(RuntimeError):
    """Raised when a runtime address cannot be proven to map to a module/static address."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class BuildToolchainUnavailableError(RuntimeError):
    """Raised when a Phase 8D build toolchain (compiler/build command) cannot be resolved."""

    def __init__(self, message: str, *, attempt: object | None = None) -> None:
        super().__init__(message)
        self.attempt = attempt


class BuildFailedError(RuntimeError):
    """Raised when a resolved build toolchain ran but did not produce a usable object."""

    def __init__(self, message: str, *, attempt: object | None = None) -> None:
        super().__init__(message)
        self.attempt = attempt


class UnsupportedFunctionError(RuntimeError):
    """Raised when a function is structurally unsuitable for decompilation (e.g. no instructions)."""

    def __init__(self, message: str, *, attempt: object | None = None) -> None:
        super().__init__(message)
        self.attempt = attempt


class ContextGenerationFailedError(RuntimeError):
    """Raised when assembling m2c context/symbol inputs for a function fails safely."""

    def __init__(self, message: str, *, attempt: object | None = None) -> None:
        super().__init__(message)
        self.attempt = attempt
