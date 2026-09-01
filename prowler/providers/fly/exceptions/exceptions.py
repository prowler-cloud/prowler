# Exceptions codes from 22000 to 22999 are reserved for Fly.io exceptions
from prowler.exceptions.exceptions import ProwlerException


class FlyBaseException(ProwlerException):
    """Base exception for Fly.io provider errors."""

    FLY_ERROR_CODES = {
        (22000, "FlyCredentialsError"): {
            "message": "Fly.io credentials not found or invalid.",
            "remediation": "Set the FLY_API_TOKEN environment variable with a valid Fly.io token. Create an org-scoped read-only token with `fly tokens create readonly <org>`.",
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
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22000, file=file, original_exception=original_exception, message=message
        )


class FlyAuthenticationError(FlyBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22001, file=file, original_exception=original_exception, message=message
        )


class FlySessionError(FlyBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22002, file=file, original_exception=original_exception, message=message
        )


class FlyIdentityError(FlyBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22003, file=file, original_exception=original_exception, message=message
        )


class FlyInvalidOrganizationError(FlyBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22004, file=file, original_exception=original_exception, message=message
        )


class FlyAPIError(FlyBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22005, file=file, original_exception=original_exception, message=message
        )


class FlyRateLimitError(FlyBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22006, file=file, original_exception=original_exception, message=message
        )
