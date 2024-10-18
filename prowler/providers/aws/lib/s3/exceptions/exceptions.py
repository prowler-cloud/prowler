from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 6000 to 6999 are reserved for S3 exceptions
class S3BaseException(ProwlerException):
    """Base class for S3 exceptions."""

    S3_ERROR_CODES = {
        (6000, "S3TestConnectionError"): {
            "message": "Failed to test connection to S3 bucket.",
            "remediation": "Check the S3 bucket name and permissions.",
        }
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        module = "S3"
        error_info = self.S3_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=module,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class S3TestConnectionError(S3BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6000, file=file, original_exception=original_exception, message=message
        )
