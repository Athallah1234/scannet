class NetScanException(Exception):
    """Base exception for NetScan library."""
    pass

class TargetValidationError(NetScanException):
    """Raised when target validation fails."""
    pass

class UnauthorizedScanError(NetScanException):
    """Raised when scan is not authorized."""
    pass

class ScanTimeoutError(NetScanException):
    """Raised when scan timeout is exceeded."""
    pass
