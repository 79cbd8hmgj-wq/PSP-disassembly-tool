class ParseError(ValueError):
    """Raised when an input cannot be safely parsed."""


class EngineUnavailableError(RuntimeError):
    """Raised when an optional disassembly engine cannot be loaded."""


class DisassemblyError(RuntimeError):
    """Raised when instruction analysis cannot be completed safely."""
