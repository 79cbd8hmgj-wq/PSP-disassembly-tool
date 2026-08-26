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
