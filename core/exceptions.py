# core/exceptions.py

"""
Custom Exception Classes
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Defines all custom exception classes for the WOLFSTRIKE toolkit
to provide clear and specific error handling throughout the application.
"""

from typing import Optional


class WolfStrikeException(Exception):
    """Base exception class for all WOLFSTRIKE errors."""
    
    def __init__(self, message: str = "An error occurred in WOLFSTRIKE"):
        self.message = message
        super().__init__(self.message)
    
    def __str__(self) -> str:
        return f"[WOLFSTRIKE] {self.message}"


class ConfigurationError(WolfStrikeException):
    """Raised when configuration is invalid or missing."""
    
    def __init__(self, message: str = "Configuration error"):
        super().__init__(f"Configuration Error: {message}")


class ScanError(WolfStrikeException):
    """Raised when scan execution fails."""
    
    def __init__(self, message: str = "Scan execution failed"):
        super().__init__(f"Scan Error: {message}")


class ModuleError(WolfStrikeException):
    """Raised when a module fails to execute."""
    
    def __init__(self, message: str = "Module execution failed"):
        super().__init__(f"Module Error: {message}")


class NetworkError(WolfStrikeException):
    """Raised when network operations fail."""
    
    def __init__(self, message: str = "Network operation failed", status_code: Optional[int] = None):
        self.status_code = status_code
        detail = f" (Status: {status_code})" if status_code else ""
        super().__init__(f"Network Error: {message}{detail}")


class AuthenticationError(WolfStrikeException):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(f"Authentication Error: {message}")


class PayloadError(WolfStrikeException):
    """Raised when payload generation or execution fails."""
    
    def __init__(self, message: str = "Payload error"):
        super().__init__(f"Payload Error: {message}")


class DatabaseError(WolfStrikeException):
    """Raised when database operations fail."""
    
    def __init__(self, message: str = "Database operation failed"):
        super().__init__(f"Database Error: {message}")


class CacheError(WolfStrikeException):
    """Raised when cache operations fail."""
    
    def __init__(self, message: str = "Cache operation failed"):
        super().__init__(f"Cache Error: {message}")


class ValidationError(WolfStrikeException):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Validation failed"):
        super().__init__(f"Validation Error: {message}")


class TargetError(WolfStrikeException):
    """Raised when target is invalid or unreachable."""
    
    def __init__(self, target: str = "unknown", message: str = "Target error"):
        self.target = target
        super().__init__(f"Target Error ({target}): {message}")


class RateLimitError(WolfStrikeException):
    """Raised when rate limiting is detected."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        self.retry_after = retry_after
        detail = f" Retry after {retry_after}s" if retry_after else ""
        super().__init__(f"Rate Limit Error: {message}{detail}")


class WAFDetectionError(WolfStrikeException):
    """Raised when WAF blocks requests."""
    
    def __init__(self, waf_name: str = "Unknown", message: str = "Request blocked by WAF"):
        self.waf_name = waf_name
        super().__init__(f"WAF Blocked ({waf_name}): {message}")


class ReportGenerationError(WolfStrikeException):
    """Raised when report generation fails."""
    
    def __init__(self, message: str = "Report generation failed"):
        super().__init__(f"Report Error: {message}")


class PlatformError(WolfStrikeException):
    """Raised when platform compatibility issues occur."""
    
    def __init__(self, message: str = "Platform compatibility error"):
        super().__init__(f"Platform Error: {message}")


class DependencyError(WolfStrikeException):
    """Raised when required dependencies are missing."""
    
    def __init__(self, dependency: str = "unknown", message: str = "Missing dependency"):
        self.dependency = dependency
        super().__init__(f"Dependency Error ({dependency}): {message}")


class TimeoutError(WolfStrikeException):
    """Raised when operations timeout."""
    
    def __init__(self, message: str = "Operation timed out", timeout_seconds: Optional[float] = None):
        self.timeout_seconds = timeout_seconds
        detail = f" after {timeout_seconds}s" if timeout_seconds else ""
        super().__init__(f"Timeout Error: {message}{detail}")