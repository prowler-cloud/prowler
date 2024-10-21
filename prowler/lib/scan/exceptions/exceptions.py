from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 5000 to 5999 are reserved for Scan exceptions
class ScanBaseException(ProwlerException):
    """Base class for Scan errors."""

    SCAN_ERROR_CODES = {
        (5000, "ScanInvalidSeverityError"): {
            "message": "Invalid severity level provided.",
            "remediation": "Please provide a valid severity level. Valid severities are: critical, high, medium, low, informational.",
        },
        (5001, "ScanInvalidCheckError"): {
            "message": "Invalid check provided.",
            "remediation": "Please provide a valid check name.",
        },
        (5002, "ScanInvalidServiceError"): {
            "message": "Invalid service provided.",
            "remediation": "Please provide a valid service name.",
        },
        (5003, "ScanInvalidComplianceFrameworkError"): {
            "message": "Invalid compliance framework provided.",
            "remediation": "Please provide a valid compliance framework name for the chosen provider.",
        },
        (5004, "ScanInvalidCategoryError"): {
            "message": "Invalid category provided.",
            "remediation": "Please provide a valid category name.",
        },
        (5005, "ScanInvalidStatusError"): {
            "message": "Invalid status provided.",
            "remediation": "Please provide a valid status: FAIL, PASS, MANUAL.",
        },
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
            5000, file=file, original_exception=original_exception, message=message
        )


class ScanInvalidCheckError(ScanBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5001, file=file, original_exception=original_exception, message=message
        )


class ScanInvalidServiceError(ScanBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5002, file=file, original_exception=original_exception, message=message
        )


class ScanInvalidComplianceFrameworkError(ScanBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5003, file=file, original_exception=original_exception, message=message
        )


class ScanInvalidCategoryError(ScanBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5004, file=file, original_exception=original_exception, message=message
        )


class ScanInvalidStatusError(ScanBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5005, file=file, original_exception=original_exception, message=message
        )
