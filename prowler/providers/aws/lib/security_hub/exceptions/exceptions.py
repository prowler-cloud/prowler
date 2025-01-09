from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 7000 to 7999 are reserved for Security Hub exceptions
class SecurityHubBaseException(ProwlerException):
    """Base class for Security Hub exceptions."""

    SECURITYHUB_ERROR_CODES = {
        (7000, "SecurityHubNoEnabledRegionsError"): {
            "message": "No regions were found to with the Security Hub integration enabled.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (7001, "SecurityHubInvalidRegionError"): {
            "message": "Given region has not Security Hub enabled.",
            "remediation": "Please provide a valid region.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        module = "SecurityHub"
        error_info = self.SECURITYHUB_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=module,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class SecurityHubNoEnabledRegionsError(SecurityHubBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7000, file=file, original_exception=original_exception, message=message
        )


class SecurityHubInvalidRegionError(SecurityHubBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7001, file=file, original_exception=original_exception, message=message
        )
