from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 16000 to 16099 are reserved for Linode exceptions
class LinodeBaseException(ProwlerException):
    """Base class for Linode errors."""

    LINODE_ERROR_CODES = {
        (16000, "LinodeCredentialsError"): {
            "message": "Linode credentials not found or invalid",
            "remediation": "Provide a valid Personal Access Token for Linode via LINODE_TOKEN environment variable or --linode-token argument.",
        },
        (16001, "LinodeAuthenticationError"): {
            "message": "Linode authentication failed",
            "remediation": "Verify the Linode Personal Access Token and ensure it has the required scopes (linodes:read_only, firewalls:read_only, account:read_only).",
        },
        (16002, "LinodeSessionError"): {
            "message": "Linode session setup failed",
            "remediation": "Review the Linode SDK initialization parameters and credentials.",
        },
        (16003, "LinodeIdentityError"): {
            "message": "Unable to retrieve Linode identity or account information",
            "remediation": "Ensure the Personal Access Token allows access to the Linode account and profile APIs.",
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
            16000, file=file, original_exception=original_exception, message=message
        )


class LinodeAuthenticationError(LinodeBaseException):
    """Exception for Linode authentication errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16001, file=file, original_exception=original_exception, message=message
        )


class LinodeSessionError(LinodeBaseException):
    """Exception for Linode session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16002, file=file, original_exception=original_exception, message=message
        )


class LinodeIdentityError(LinodeBaseException):
    """Exception for Linode identity errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16003, file=file, original_exception=original_exception, message=message
        )
