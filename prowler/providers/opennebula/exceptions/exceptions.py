from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 9000 to 9999 are reserved for OpenNebula exceptions
class OpenNebulaBaseException(ProwlerException):
    """Base class for OpenNebula errors."""

    OpenNebula_ERROR_CODES = {
        (4004, "OpenNebulaError"): {
            "message": "An error occurred in the OpenNebula provider.",
            "remediation": "Check the provider code and configuration to identify the issue. For more information on troubleshooting OpenNebula providers, refer to the OpenNebula documentation",
        },
    }

    def __init__(
        self,
        code,
        file=None,
        original_exception=None,
        message=None,
    ):
        provider = "OpenNebula"
        error_info = self.OpenNebula_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class OpenNebulaError(OpenNebulaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4004, file, original_exception, message)