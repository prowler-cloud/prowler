from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 21000 to 21999 are reserved for Supabase exceptions
class SupabaseBaseException(ProwlerException):
    """Base exception for Supabase provider errors."""

    SUPABASE_ERROR_CODES = {
        (21000, "SupabaseCredentialsError"): {
            "message": "Supabase credentials were not found.",
            "remediation": "Set SUPABASE_ACCESS_TOKEN to a valid Supabase Personal Access Token.",
        },
        (21001, "SupabaseAuthenticationError"): {
            "message": "Supabase Management API authentication failed.",
            "remediation": "Verify that SUPABASE_ACCESS_TOKEN is valid and has not expired or been revoked.",
        },
        (21002, "SupabaseInsufficientPermissionsError"): {
            "message": "Supabase Management API permissions are insufficient.",
            "remediation": "Use a Personal Access Token from an account that can read the target organizations and their members.",
        },
        (21003, "SupabaseRateLimitError"): {
            "message": "The Supabase Management API rate limit was exceeded.",
            "remediation": "Wait for the rate-limit window to reset before retrying the scan.",
        },
        (21004, "SupabaseSessionError"): {
            "message": "Failed to create a Supabase Management API session.",
            "remediation": "Check the local HTTP client configuration and retry.",
        },
        (21005, "SupabaseIdentityError"): {
            "message": "Failed to retrieve Supabase organization identity information.",
            "remediation": "Ensure the token can call GET /v1/organizations.",
        },
        (21006, "SupabaseAPIError"): {
            "message": "A Supabase Management API request failed.",
            "remediation": "Check Supabase service status, network connectivity, and the API response before retrying.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.SUPABASE_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Supabase error.",
                "remediation": "Review the Supabase Management API documentation.",
            }
        elif message:
            error_info = error_info.copy()
            error_info["message"] = message
        super().__init__(
            code=code,
            source="Supabase",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class SupabaseCredentialsError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21000, file=file, original_exception=original_exception, message=message
        )


class SupabaseAuthenticationError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21001, file=file, original_exception=original_exception, message=message
        )


class SupabaseInsufficientPermissionsError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21002, file=file, original_exception=original_exception, message=message
        )


class SupabaseRateLimitError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21003, file=file, original_exception=original_exception, message=message
        )


class SupabaseSessionError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21004, file=file, original_exception=original_exception, message=message
        )


class SupabaseIdentityError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21005, file=file, original_exception=original_exception, message=message
        )


class SupabaseAPIError(SupabaseBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            21006, file=file, original_exception=original_exception, message=message
        )
