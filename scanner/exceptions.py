"""Custom exception hierarchy for the vulnerability scanner.

This module defines specific exception types to enable better error handling
and recovery strategies throughout the scanner codebase.
"""


class ScannerException(Exception):
    """Base exception for all scanner-related errors."""
    pass


class NetworkError(ScannerException):
    """Raised when network-related transient failures occur.

    These errors are typically retryable (timeouts, connection errors, etc.).
    """
    pass


class ValidationError(ScannerException):
    """Raised when configuration or input validation fails.

    These errors indicate problems with user input or configuration
    that should be fixed before retrying.
    """
    pass


class TimeoutError(ScannerException):
    """Raised when a plugin or request operation times out.

    This can indicate slow targets or plugins that need optimization.
    """
    pass


class PluginError(ScannerException):
    """Raised when a plugin fails during execution.

    This wrapper provides context about which plugin failed and why.
    """
    def __init__(self, plugin_name: str, message: str, original_error: Exception = None):
        self.plugin_name = plugin_name
        self.original_error = original_error
        super().__init__(f"Plugin '{plugin_name}' failed: {message}")


class AuthenticationError(ScannerException):
    """Raised when authentication fails.

    This indicates problems with login credentials or authentication flow.
    """
    pass


class ConfigurationError(ValidationError):
    """Raised when configuration is invalid or incomplete.

    Subclass of ValidationError for configuration-specific issues.
    """
    pass
