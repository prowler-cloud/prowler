from prowler.exceptions.exceptions import ProwlerException


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
        (9007, "CloudflareNoAccountsError"): {
            "message": "No Cloudflare accounts found",
            "remediation": "Verify your API token has the required permissions to list accounts.",
        },
        (9008, "CloudflareUserTokenRequiredError"): {
            "message": "User-level API token required",
            "remediation": "Create a User API Token under My Profile (not an Account-owned token), or use API Key + Email authentication.",
        },
        (9009, "CloudflareInvalidAPIKeyError"): {
            "message": "Invalid API Key or Email",
            "remediation": "Verify your API Key and Email are correct. The API Key can be found in your Cloudflare profile.",
        },
        (9010, "CloudflareInvalidAPITokenError"): {
            "message": "Invalid API Token format",
            "remediation": "Check that your API Token is correctly formatted. Tokens should be alphanumeric strings.",
        },
        (9011, "CloudflareRateLimitError"): {
            "message": "Cloudflare API rate limit exceeded",
            "remediation": "Wait before retrying. Consider reducing the frequency of API calls.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Cloudflare"
        error_info = self.CLOUDFLARE_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Cloudflare error",
                "remediation": "Check the Cloudflare API documentation for more details.",
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


class CloudflareNoAccountsError(CloudflareBaseException):
    """Exception for no Cloudflare accounts found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9007, file=file, original_exception=original_exception, message=message
        )


class CloudflareUserTokenRequiredError(CloudflareBaseException):
    """Exception for missing user-level Cloudflare authentication."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9008, file=file, original_exception=original_exception, message=message
        )


class CloudflareInvalidAPIKeyError(CloudflareBaseException):
    """Exception for invalid Cloudflare API Key or Email."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9009, file=file, original_exception=original_exception, message=message
        )


class CloudflareInvalidAPITokenError(CloudflareBaseException):
    """Exception for invalid Cloudflare API Token format."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9010, file=file, original_exception=original_exception, message=message
        )


class CloudflareRateLimitError(CloudflareBaseException):
    """Exception for Cloudflare API rate limit exceeded."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9011, file=file, original_exception=original_exception, message=message
        )
