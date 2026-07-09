from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 19000 to 19999 are reserved for E2E Networks exceptions
class E2eNetworksBaseException(ProwlerException):
    """Base class for E2E Networks errors."""

    E2E_NETWORKS_ERROR_CODES = {
        (19000, "E2eNetworksCredentialsError"): {
            "message": "E2E Networks credentials not found or invalid",
            "remediation": "Provide a valid API key, auth token and project id via the E2E_NETWORKS_API_KEY, E2E_NETWORKS_AUTH_TOKEN and E2E_NETWORKS_PROJECT_ID environment variables.",
        },
        (19001, "E2eNetworksAuthenticationError"): {
            "message": "E2E Networks authentication failed",
            "remediation": "Verify the E2E Networks API key and auth token and ensure the project id is correct and accessible.",
        },
        (19002, "E2eNetworksSessionError"): {
            "message": "E2E Networks session setup failed",
            "remediation": "Review the E2E Networks credentials and network connectivity to the MyAccount API.",
        },
        (19003, "E2eNetworksAPIError"): {
            "message": "E2E Networks API request failed",
            "remediation": "Check the E2E Networks MyAccount API status and that the credentials grant access to the requested resource.",
        },
        (19004, "E2eNetworksIdentityError"): {
            "message": "Unable to retrieve E2E Networks identity or project information",
            "remediation": "Ensure the credentials allow access to the E2E Networks project and account APIs.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "E2E"
        error_info = self.E2E_NETWORKS_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown E2E Networks error",
                "remediation": "Check the E2E Networks MyAccount API documentation for more details.",
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


class E2eNetworksCredentialsError(E2eNetworksBaseException):
    """Exception for E2E Networks credential errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19000, file=file, original_exception=original_exception, message=message
        )


class E2eNetworksAuthenticationError(E2eNetworksBaseException):
    """Exception for E2E Networks authentication errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19001, file=file, original_exception=original_exception, message=message
        )


class E2eNetworksSessionError(E2eNetworksBaseException):
    """Exception for E2E Networks session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19002, file=file, original_exception=original_exception, message=message
        )


class E2eNetworksAPIError(E2eNetworksBaseException):
    """Exception for E2E Networks API request errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19003, file=file, original_exception=original_exception, message=message
        )


class E2eNetworksIdentityError(E2eNetworksBaseException):
    """Exception for E2E Networks identity errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19004, file=file, original_exception=original_exception, message=message
        )
