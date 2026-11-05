from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 21000 to 21999 are reserved for IaC exceptions
class IacBaseException(ProwlerException):
    """Base class for IaC provider errors."""

    IAC_ERROR_CODES = {
        (21000, "IacRepositoryCloneError"): {
            "message": "Unable to clone the repository to scan",
            "remediation": "Check that the repository URL is correct, that it is reachable, and that the provided credentials can read it.",
        },
        (21001, "IacTrivyNotFoundError"): {
            "message": "Trivy binary not found",
            "remediation": "Install Trivy from https://trivy.dev/latest/getting-started/installation/ or use your system package manager (e.g., 'brew install trivy' on macOS, 'apt-get install trivy' on Ubuntu).",
        },
        (21002, "IacScanError"): {
            "message": "Error running the IaC scan",
            "remediation": "Check the Trivy output and the scanned path, then try again.",
        },
        (21003, "IacOutputProcessingError"): {
            "message": "Error processing the IaC scan output",
            "remediation": "Check the Trivy output format and try again.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "IaC"
        error_info = self.IAC_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown IaC error",
                "remediation": "Check the error message and try again.",
            }
        elif message:
            error_info = error_info.copy()
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class IacRepositoryCloneError(IacBaseException):
    """Exception raised when the repository to scan cannot be cloned."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21000, file=file, original_exception=original_exception, message=message
        )


class IacTrivyNotFoundError(IacBaseException):
    """Exception raised when the Trivy binary is not available."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21001, file=file, original_exception=original_exception, message=message
        )


class IacScanError(IacBaseException):
    """Exception raised when the Trivy scan fails."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21002, file=file, original_exception=original_exception, message=message
        )


class IacOutputProcessingError(IacBaseException):
    """Exception raised when a Trivy finding cannot be processed."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21003, file=file, original_exception=original_exception, message=message
        )
