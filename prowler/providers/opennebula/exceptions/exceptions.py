from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 9000 to 9999 are reserved for Opennebula exceptions
class OpennebulaBaseException(ProwlerException):
    """Base class for Opennebula errors."""

    Opennebula_ERROR_CODES = {
        (4004, "OpennebulaError"): {
            "message": "An error occurred in the Opennebula provider.",
            "remediation": "Check the provider code and configuration to identify the issue. For more information on troubleshooting Opennebula providers, refer to the Opennebula documentation",
        },
    }

    def __init__(
        self,
        code,
        file=None,
        original_exception=None,
        message=None,
    ):
        provider = "Opennebula"
        error_info = self.Opennebula_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class OpennebulaError(OpennebulaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4004, file, original_exception, message)