class ApplicationError(Exception):
    """Base error safe to map at an entrypoint."""


class ConfigurationError(ApplicationError):
    """Configuration could not be loaded or validated."""


class DiagnosticError(ApplicationError):
    """One or more required diagnostics failed."""
