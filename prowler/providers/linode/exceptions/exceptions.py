from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 18000 to 18099 are reserved for Linode exceptions
class LinodeBaseException(ProwlerException):
    """Base class for Linode errors."""

    LINODE_ERROR_CODES = {
        (18000, "LinodeCredentialsError"): {
            "message": "Linode credentials not found or invalid",
            "remediation": "Provide a valid Personal Access Token for Linode via the LINODE_TOKEN environment variable.",
        },
        (18001, "LinodeAuthenticationError"): {
            "message": "Linode authentication failed",
            "remediation": "Verify the Linode Personal Access Token and ensure it has the required scopes (linodes:read_only, firewalls:read_only, account:read_only).",
        },
        (18002, "LinodeSessionError"): {
            "message": "Linode session setup failed",
            "remediation": "Review the Linode SDK initialization parameters and credentials.",
        },
        (18003, "LinodeIdentityError"): {
            "message": "Unable to retrieve Linode identity or account information",
            "remediation": "Ensure the Personal Access Token allows access to the Linode account and profile APIs.",
        },
        (18004, "LinodeMissingPermissionError"): {
            "message": "Linode token is missing a required permission scope",
            "remediation": "Grant the Personal Access Token the read-only scope required for the affected service (account:read_only, linodes:read_only, firewall:read_only).",
        },
        (18005, "LinodeInvalidRegionError"): {
            "message": "One or more requested Linode regions are invalid",
            "remediation": "Pass a valid Linode region id to --region. See https://www.linode.com/global-infrastructure/ or the API /v4/regions endpoint for the current list.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Linode"
        error_info = self.LINODE_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Linode error",
                "remediation": "Check the Linode API documentation for more details.",
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


class LinodeCredentialsError(LinodeBaseException):
    """Exception for Linode credential errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            18000, file=file, original_exception=original_exception, message=message
        )


class LinodeAuthenticationError(LinodeBaseException):
    """Exception for Linode authentication errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            18001, file=file, original_exception=original_exception, message=message
        )


class LinodeSessionError(LinodeBaseException):
    """Exception for Linode session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            18002, file=file, original_exception=original_exception, message=message
        )


class LinodeIdentityError(LinodeBaseException):
    """Exception for Linode identity errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            18003, file=file, original_exception=original_exception, message=message
        )


class LinodeMissingPermissionError(LinodeBaseException):
    """Exception for Linode missing permission scope errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            18004, file=file, original_exception=original_exception, message=message
        )


class LinodeInvalidRegionError(LinodeBaseException):
    """Exception for invalid Linode region filters."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            18005, file=file, original_exception=original_exception, message=message
        )
