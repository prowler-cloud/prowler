import re

from prowler.exceptions.exceptions import ProwlerException


def parse_cloudflare_api_error(error: Exception) -> str:
    """Parse a Cloudflare API error and return a user-friendly message.

    Cloudflare API errors typically look like:
    Error code: 400 - {'success': False, 'errors': [{'code': 6003, 'message': 'Invalid request headers',
    'error_chain': [{'code': 6111, 'message': 'Invalid format for Authorization header'}]}], ...}

    Args:
        error: The exception from the Cloudflare SDK.

    Returns:
        A formatted, user-friendly error message.
    """
    error_str = str(error)

    # Try to extract messages from the Cloudflare API response format
    messages = []

    # Pattern to find 'message': 'some message' in the error string
    message_pattern = r"'message':\s*'([^']+)'"
    matches = re.findall(message_pattern, error_str)
    if matches:
        # Deduplicate while preserving order
        seen = set()
        for msg in matches:
            if msg not in seen:
                seen.add(msg)
                messages.append(msg)

    if messages:
        return " - ".join(messages)

    # If we couldn't parse specific messages, check for common HTTP status codes
    if "401" in error_str or "Unauthorized" in error_str:
        return "Invalid API token or credentials"
    if "403" in error_str or "Forbidden" in error_str:
        return "API token lacks required permissions"
    if "400" in error_str:
        return "Invalid request - please check your API token format"

    # Fallback to a generic message if we can't parse the error
    return "Authentication failed - please verify your credentials"


# Exceptions codes from 9000 to 9999 are reserved for Cloudflare exceptions
class CloudflareBaseException(ProwlerException):
    """Base class for Cloudflare errors."""

    CLOUDFLARE_ERROR_CODES = {
        (9000, "CloudflareCredentialsError"): {
            "message": "Cloudflare credentials not found or invalid",
            "remediation": "Provide a valid API token or API key and email for Cloudflare.",
        },
        (9001, "CloudflareAuthenticationError"): {
            "message": "Cloudflare authentication failed",
            "remediation": "Verify the Cloudflare credentials and ensure the token has the required permissions.",
        },
        (9002, "CloudflareSessionError"): {
            "message": "Cloudflare session setup failed",
            "remediation": "Review the Cloudflare SDK initialization parameters and credentials.",
        },
        (9003, "CloudflareIdentityError"): {
            "message": "Unable to retrieve Cloudflare identity or account information",
            "remediation": "Ensure the credentials allow access to the Cloudflare user and account APIs.",
        },
        (9004, "CloudflareInvalidAccountError"): {
            "message": "The provided Cloudflare account is not accessible with these credentials",
            "remediation": "Check the account identifier and token scopes to confirm access.",
        },
        (9005, "CloudflareInvalidProviderIdError"): {
            "message": "The requested Cloudflare provider identifier is not valid",
            "remediation": "Verify the supplied account or zone identifiers and retry.",
        },
        (9006, "CloudflareAPIError"): {
            "message": "Cloudflare API call failed",
            "remediation": "Inspect the API response details and permissions for the failing request.",
        },
        (9007, "CloudflareCredentialsConflictError"): {
            "message": "Conflicting Cloudflare credentials provided",
            "remediation": "Use either API Token or API Key + Email, not both. Unset CLOUDFLARE_API_TOKEN or unset both CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL.",
        },
        (9008, "CloudflareUserAuthenticationRequiredError"): {
            "message": "Cloudflare user-level authentication required",
            "remediation": "Create a User API Token under My Profile (not an Account-owned token), or use API Key + Email.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Cloudflare"
        error_info = self.CLOUDFLARE_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class CloudflareCredentialsError(CloudflareBaseException):
    """Exception for Cloudflare credential errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9000, file=file, original_exception=original_exception, message=message
        )


class CloudflareAuthenticationError(CloudflareBaseException):
    """Exception for Cloudflare authentication errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9001, file=file, original_exception=original_exception, message=message
        )


class CloudflareSessionError(CloudflareBaseException):
    """Exception for Cloudflare session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9002, file=file, original_exception=original_exception, message=message
        )


class CloudflareIdentityError(CloudflareBaseException):
    """Exception for Cloudflare identity setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9003, file=file, original_exception=original_exception, message=message
        )


class CloudflareInvalidAccountError(CloudflareBaseException):
    """Exception for inaccessible Cloudflare account identifiers."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9004, file=file, original_exception=original_exception, message=message
        )


class CloudflareInvalidProviderIdError(CloudflareBaseException):
    """Exception for invalid Cloudflare provider identifiers."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9005, file=file, original_exception=original_exception, message=message
        )


class CloudflareAPIError(CloudflareBaseException):
    """Exception for Cloudflare API errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9006, file=file, original_exception=original_exception, message=message
        )


class CloudflareCredentialsConflictError(CloudflareBaseException):
    """Exception for conflicting Cloudflare credentials."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9007, file=file, original_exception=original_exception, message=message
        )


class CloudflareUserAuthenticationRequiredError(CloudflareBaseException):
    """Exception for missing user-level Cloudflare authentication."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9008, file=file, original_exception=original_exception, message=message
        )
