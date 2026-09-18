# Exceptions codes from 22000 to 22999 are reserved for Fly.io exceptions
from prowler.exceptions.exceptions import ProwlerException


class FlyBaseException(ProwlerException):
    """Base exception for Fly.io provider errors."""

    FLY_ERROR_CODES = {
        (22000, "FlyCredentialsError"): {
            "message": "Fly.io credentials not found or invalid.",
            "remediation": "Set the FLY_API_TOKEN environment variable with a valid Fly.io token. Create an org-scoped read-only token with `fly tokens create readonly --org <org>`.",
        },
        (22001, "FlyAuthenticationError"): {
            "message": "Authentication to the Fly.io API failed.",
            "remediation": "Verify the token has not expired or been revoked and that it grants read access to the organization being scanned.",
        },
        (22002, "FlySessionError"): {
            "message": "Failed to create a Fly.io API session.",
            "remediation": "Check network connectivity and ensure https://api.machines.dev and https://api.fly.io are reachable.",
        },
        (22003, "FlyIdentityError"): {
            "message": "Failed to retrieve Fly.io identity information.",
            "remediation": "Ensure the token can read organizations through the Fly.io GraphQL API.",
        },
        (22004, "FlyInvalidOrganizationError"): {
            "message": "The specified Fly.io organization was not found or is not accessible.",
            "remediation": "Verify the organization slug and that the token is scoped to that organization.",
        },
        (22005, "FlyAPIError"): {
            "message": "An error occurred while calling the Fly.io API.",
            "remediation": "Check the Fly.io status page at https://status.flyio.net and retry.",
        },
        (22006, "FlyRateLimitError"): {
            "message": "Rate limited by the Fly.io API.",
            "remediation": "Wait for the Retry-After window and run the scan again. See https://fly.io/docs/machines/api/working-with-machines-api/.",
        },
        (22007, "FlyInvalidArgumentError"): {
            "message": "Invalid Fly.io provider argument.",
            "remediation": "Provide at least one non-empty app name, or omit the app filter to scan all apps in the selected organization.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Fly"
        error_info = self.FLY_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Fly.io error.",
                "remediation": "Check the Fly.io API documentation for more details.",
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


class FlyCredentialsError(FlyBaseException):
    """Fly.io credentials are missing or invalid."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22000, file=file, original_exception=original_exception, message=message
        )


class FlyAuthenticationError(FlyBaseException):
    """The Fly.io API rejected the token or its access permissions."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22001, file=file, original_exception=original_exception, message=message
        )


class FlySessionError(FlyBaseException):
    """The Fly.io HTTP session could not be initialized."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22002, file=file, original_exception=original_exception, message=message
        )


class FlyIdentityError(FlyBaseException):
    """The Fly.io organization lookup could not be completed."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22003, file=file, original_exception=original_exception, message=message
        )


class FlyInvalidOrganizationError(FlyBaseException):
    """A single readable Fly.io organization could not be selected."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22004, file=file, original_exception=original_exception, message=message
        )


class FlyAPIError(FlyBaseException):
    """A Fly.io API request failed for a non-authentication reason."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22005, file=file, original_exception=original_exception, message=message
        )


class FlyRateLimitError(FlyBaseException):
    """The Fly.io API rate limit could not be recovered within the retry budget."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22006, file=file, original_exception=original_exception, message=message
        )


class FlyInvalidArgumentError(FlyBaseException):
    """A Fly.io provider argument would produce an invalid scan scope."""

    def __init__(
        self,
        file: str | None = None,
        original_exception: Exception | None = None,
        message: str | None = None,
    ) -> None:
        """Initialize the invalid-argument error with its remediation.

        Args:
            file: Source file reporting the error.
            original_exception: Underlying error, when available.
            message: Optional explanation overriding the default error message.
        """
        super().__init__(
            22007, file=file, original_exception=original_exception, message=message
        )
