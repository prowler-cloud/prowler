# Exceptions codes from 13000 to 13999 are reserved for Vercel exceptions
from prowler.exceptions.exceptions import ProwlerException


class VercelBaseException(ProwlerException):
    """Base exception for Vercel provider errors."""

    VERCEL_ERROR_CODES = {
        (13000, "VercelCredentialsError"): {
            "message": "Vercel credentials not found or invalid.",
            "remediation": "Set the VERCEL_TOKEN environment variable with a valid Vercel API token. Generate one at https://vercel.com/account/tokens.",
        },
        (13001, "VercelAuthenticationError"): {
            "message": "Authentication to Vercel API failed.",
            "remediation": "Verify your Vercel API token is valid and has not expired. Check at https://vercel.com/account/tokens.",
        },
        (13002, "VercelSessionError"): {
            "message": "Failed to create a Vercel API session.",
            "remediation": "Check network connectivity and ensure the Vercel API is reachable at https://api.vercel.com.",
        },
        (13003, "VercelIdentityError"): {
            "message": "Failed to retrieve Vercel identity information.",
            "remediation": "Ensure the API token has permissions to read user and team information.",
        },
        (13004, "VercelInvalidTeamError"): {
            "message": "The specified Vercel team was not found or is not accessible.",
            "remediation": "Verify the team ID or slug is correct and that your token has access to the team.",
        },
        (13005, "VercelInvalidProviderIdError"): {
            "message": "The provided Vercel provider ID is invalid.",
            "remediation": "Ensure the provider UID matches a valid Vercel team ID or user ID format.",
        },
        (13006, "VercelAPIError"): {
            "message": "An error occurred while calling the Vercel API.",
            "remediation": "Check the Vercel API status at https://www.vercel-status.com/ and retry the request.",
        },
        (13007, "VercelRateLimitError"): {
            "message": "Rate limited by the Vercel API.",
            "remediation": "Wait and retry. Vercel API rate limits vary by endpoint. See https://vercel.com/docs/rest-api#rate-limits.",
        },
        (13008, "VercelPlanLimitationError"): {
            "message": "This feature requires a higher Vercel plan.",
            "remediation": "Some security features (e.g., WAF managed rulesets) require Vercel Enterprise. Upgrade your plan or skip these checks.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Vercel"
        error_info = self.VERCEL_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Vercel error.",
                "remediation": "Check the Vercel API documentation for more details.",
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


class VercelCredentialsError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13000, file=file, original_exception=original_exception, message=message
        )


class VercelAuthenticationError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13001, file=file, original_exception=original_exception, message=message
        )


class VercelSessionError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13002, file=file, original_exception=original_exception, message=message
        )


class VercelIdentityError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13003, file=file, original_exception=original_exception, message=message
        )


class VercelInvalidTeamError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13004, file=file, original_exception=original_exception, message=message
        )


class VercelInvalidProviderIdError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13005, file=file, original_exception=original_exception, message=message
        )


class VercelAPIError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13006, file=file, original_exception=original_exception, message=message
        )


class VercelRateLimitError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13007, file=file, original_exception=original_exception, message=message
        )


class VercelPlanLimitationError(VercelBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13008, file=file, original_exception=original_exception, message=message
        )
