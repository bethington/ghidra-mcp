"""Bridge exception types."""


class GhidraConnectionError(Exception):
    """Raised when connection to Ghidra server fails."""


class GhidraAnalysisError(Exception):
    """Raised when Ghidra analysis operation fails."""


class GhidraValidationError(Exception):
    """Raised when input validation fails."""
