from prowler.exceptions.exceptions import ProwlerException


class ScanBaseException(ProwlerException):
    """Base class for Scan errors."""

    SCAN_ERROR_CODES = {
        (2000, "ScanInvalidSeverityError"): {
            "message": "Invalid severity level provided.",
            "remediation": "Please provide a valid severity level. Valid severities are: critical, high, medium, low, informational.",
        }
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        module = "Scan"
        error_info = self.SCAN_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=module,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class ScanInvalidSeverityError(ScanBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2000, file=file, original_exception=original_exception, message=message
        )
