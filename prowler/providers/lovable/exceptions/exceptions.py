# Exception codes 14000 to 14999 are reserved for the Lovable provider.
from prowler.exceptions.exceptions import ProwlerException


class LovableBaseException(ProwlerException):
    """Base exception for Lovable provider errors."""

    LOVABLE_ERROR_CODES = {
        (14000, "LovableCredentialsError"): {
            "message": "Lovable credentials not found or invalid.",
            "remediation": (
                "Set the LOVABLE_API_TOKEN environment variable with a valid "
                "Lovable Cloud API token. Generate one from your Lovable "
                "workspace settings."
            ),
        },
        (14001, "LovableAuthenticationError"): {
            "message": "Authentication to the Lovable Cloud API failed.",
            "remediation": (
                "Verify the LOVABLE_API_TOKEN is valid, has not been revoked, "
                "and grants access to the target workspace."
            ),
        },
        (14002, "LovableSessionError"): {
            "message": "Failed to create a Lovable API session.",
            "remediation": (
                "Check network connectivity to https://api.lovable.dev and "
                "retry the request."
            ),
        },
        (14003, "LovableIdentityError"): {
            "message": "Failed to retrieve Lovable identity information.",
            "remediation": (
                "Ensure the API token has read access to the workspace and "
                "user profile."
            ),
        },
        (14004, "LovableInvalidWorkspaceError"): {
            "message": "The specified Lovable workspace was not found or is not accessible.",
            "remediation": (
                "Verify the workspace ID/slug is correct and that the API "
                "token has access to it."
            ),
        },
        (14005, "LovableInvalidProviderIdError"): {
            "message": "The provided Lovable provider ID is invalid.",
            "remediation": (
                "Ensure the provider UID matches a valid Lovable workspace ID "
                "(format: ws_<24+ hex chars>)."
            ),
        },
        (14006, "LovableAPIError"): {
            "message": "An error occurred while calling the Lovable Cloud API.",
            "remediation": (
                "Check the Lovable status page and retry. If the error "
                "persists, run with --log-level DEBUG and inspect logs."
            ),
        },
        (14007, "LovableRateLimitError"): {
            "message": "Rate limited by the Lovable Cloud API.",
            "remediation": (
                "Wait and retry. Reduce concurrent project scans by passing "
                "--project to scope the assessment."
            ),
        },
        (14008, "LovablePublishedAppFetchError"): {
            "message": "Could not fetch the published Lovable app over HTTP.",
            "remediation": (
                "Verify the app is published, publicly reachable, and that "
                "Prowler can resolve its hostname."
            ),
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Lovable"
        error_info = self.LOVABLE_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Lovable error.",
                "remediation": "Check the Lovable documentation for more details.",
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


class LovableCredentialsError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14000, file=file, original_exception=original_exception, message=message
        )


class LovableAuthenticationError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14001, file=file, original_exception=original_exception, message=message
        )


class LovableSessionError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14002, file=file, original_exception=original_exception, message=message
        )


class LovableIdentityError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14003, file=file, original_exception=original_exception, message=message
        )


class LovableInvalidWorkspaceError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14004, file=file, original_exception=original_exception, message=message
        )


class LovableInvalidProviderIdError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14005, file=file, original_exception=original_exception, message=message
        )


class LovableAPIError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14006, file=file, original_exception=original_exception, message=message
        )


class LovableRateLimitError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14007, file=file, original_exception=original_exception, message=message
        )


class LovablePublishedAppFetchError(LovableBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14008, file=file, original_exception=original_exception, message=message
        )
