from prowler.exceptions.exceptions import ProwlerException


class CloudflareException(ProwlerException):
    """Base class for Cloudflare Provider exceptions"""

    CLOUDFLARE_ERROR_CODES = {
        (1000, "CloudflareEnvironmentVariableError"): {
            "message": "Cloudflare environment variables are not set correctly",
            "remediation": "Ensure that CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL environment variables are set correctly.",
        },
        (1001, "CloudflareInvalidCredentialsError"): {
            "message": "Cloudflare credentials are invalid",
            "remediation": "Ensure that the provided Cloudflare API credentials are valid and have the necessary permissions.",
        },
        (1002, "CloudflareSetUpSessionError"): {
            "message": "Error setting up Cloudflare session",
            "remediation": "Check your Cloudflare API credentials and network connectivity.",
        },
        (1003, "CloudflareSetUpIdentityError"): {
            "message": "Error setting up Cloudflare identity",
            "remediation": "Ensure that your Cloudflare API credentials have the necessary permissions to retrieve account information.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Cloudflare"
        error_info = self.CLOUDFLARE_ERROR_CODES.get((code, self.__class__.__name__))
        if not error_info:
            error_info = {
                "message": "Unknown Cloudflare error",
                "remediation": "Please check your configuration.",
            }
        if message:
            error_info = error_info.copy()
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class CloudflareEnvironmentVariableError(CloudflareException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1000, file=file, original_exception=original_exception, message=message
        )


class CloudflareInvalidCredentialsError(CloudflareException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1001, file=file, original_exception=original_exception, message=message
        )


class CloudflareSetUpSessionError(CloudflareException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1002, file=file, original_exception=original_exception, message=message
        )


class CloudflareSetUpIdentityError(CloudflareException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1003, file=file, original_exception=original_exception, message=message
        )
