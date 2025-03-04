from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 3000 to 3999 are reserved for GCP exceptions
class GCPBaseException(ProwlerException):
    """Base class for GCP Errors."""

    GCP_ERROR_CODES = {
        (3002, "GCPNoAccesibleProjectsError"): {
            "message": "No Project IDs are active or can be accessed via Google Credentials",
            "remediation": "Ensure the project is active and accessible.",
        },
        (3003, "GCPSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (3005, "GCPTestConnectionError"): {
            "message": "Error testing connection to GCP",
            "remediation": "Check the connection and ensure it is properly set up.",
        },
        (3006, "GCPLoadADCFromDictError"): {
            "message": "Error loading Application Default Credentials from dictionary",
            "remediation": "Check the dictionary and ensure a valid Application Default Credentials are present with client_id, client_secret and refresh_token keys.",
        },
        (3007, "GCPStaticCredentialsError"): {
            "message": "Error loading static credentials",
            "remediation": "Check the credentials and ensure they are properly set up. client_id, client_secret and refresh_token are required.",
        },
        (3008, "GCPInvalidProviderIdError"): {
            "message": "Provider does not match with the expected project_id",
            "remediation": "Check the provider and ensure it matches the expected project_id.",
        },
        (3010, "GCPLoadServiceAccountKeyFromDictError"): {
            "message": "Error loading Service Account Private Key credentials from dictionary",
            "remediation": "Check the dictionary and ensure it contains a Service Account Private Key.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "GCP"
        error_info = self.GCP_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class GCPCredentialsError(GCPBaseException):
    """Base class for GCP credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class GCPNoAccesibleProjectsError(GCPCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3002, file=file, original_exception=original_exception, message=message
        )


class GCPSetUpSessionError(GCPCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3003, file=file, original_exception=original_exception, message=message
        )


class GCPTestConnectionError(GCPBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3005, file=file, original_exception=original_exception, message=message
        )


class GCPLoadADCFromDictError(GCPCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3006, file=file, original_exception=original_exception, message=message
        )


class GCPStaticCredentialsError(GCPCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3007, file=file, original_exception=original_exception, message=message
        )


class GCPInvalidProviderIdError(GCPBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3008, file=file, original_exception=original_exception, message=message
        )


class GCPLoadServiceAccountKeyFromDictError(GCPCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3010, file=file, original_exception=original_exception, message=message
        )
