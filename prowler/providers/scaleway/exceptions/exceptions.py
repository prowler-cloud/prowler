# Exceptions codes from 15000 to 15999 are reserved for Scaleway exceptions
from prowler.exceptions.exceptions import ProwlerException


class ScalewayBaseException(ProwlerException):
    """Base exception for Scaleway provider errors."""

    SCALEWAY_ERROR_CODES = {
        (15000, "ScalewayCredentialsError"): {
            "message": "Scaleway credentials not found or invalid.",
            "remediation": (
                "Set the SCW_ACCESS_KEY and SCW_SECRET_KEY environment variables "
                "with a valid Scaleway API key. Generate one at "
                "https://console.scaleway.com/iam/api-keys."
            ),
        },
        (15001, "ScalewayAuthenticationError"): {
            "message": "Authentication to the Scaleway API failed.",
            "remediation": (
                "Verify your Scaleway API key is valid, has not expired, and that "
                "the bearer has IAM read permissions on the target organization."
            ),
        },
        (15002, "ScalewaySessionError"): {
            "message": "Failed to create a Scaleway API session.",
            "remediation": (
                "Check network connectivity and ensure the Scaleway API is "
                "reachable at https://api.scaleway.com."
            ),
        },
        (15003, "ScalewayIdentityError"): {
            "message": "Failed to retrieve Scaleway identity information.",
            "remediation": (
                "Ensure the API key has permissions to read IAM users and the "
                "owning organization metadata."
            ),
        },
        (15004, "ScalewayAPIError"): {
            "message": "An error occurred while calling the Scaleway API.",
            "remediation": (
                "Check the Scaleway API status at https://status.scaleway.com "
                "and retry. Run with --log-level DEBUG for the full traceback."
            ),
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Scaleway"
        error_info = self.SCALEWAY_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Scaleway error.",
                "remediation": "Check the Scaleway API documentation for more details.",
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


class ScalewayCredentialsError(ScalewayBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            15000, file=file, original_exception=original_exception, message=message
        )


class ScalewayAuthenticationError(ScalewayBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            15001, file=file, original_exception=original_exception, message=message
        )


class ScalewaySessionError(ScalewayBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            15002, file=file, original_exception=original_exception, message=message
        )


class ScalewayIdentityError(ScalewayBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            15003, file=file, original_exception=original_exception, message=message
        )


class ScalewayAPIError(ScalewayBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            15004, file=file, original_exception=original_exception, message=message
        )
