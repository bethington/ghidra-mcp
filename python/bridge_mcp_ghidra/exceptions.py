"""Custom exception types for the GhidraMCP bridge."""


class GhidraConnectionError(Exception):
    """Raised when connection to Ghidra server fails"""

    pass


class GhidraAnalysisError(Exception):
    """Raised when Ghidra analysis operation fails"""

    pass


class GhidraValidationError(Exception):
    """Raised when input validation fails"""

    pass
