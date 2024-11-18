from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 3000 to 3999 are reserved for GCP exceptions
class GCPBaseException(ProwlerException):
    """Base class for GCP Errors."""

    GCP_ERROR_CODES = {
        (3000, "GCPCloudResourceManagerAPINotUsedError"): {
            "message": "Cloud Resource Manager API not used",
            "remediation": "Enable the Cloud Resource Manager API for the project.",
        },
        (3001, "GCPHTTPError"): {
            "message": "HTTP error",
            "remediation": "Check the HTTP error and ensure the request is properly formatted.",
        },
        (3002, "GCPNoAccesibleProjectsError"): {
            "message": "No Project IDs are active or can be accessed via Google Credentials",
            "remediation": "Ensure the project is active and accessible.",
        },
        (3003, "GCPSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (3004, "GCPGetProjectError"): {
            "message": "Error getting project",
            "remediation": "Check the project and ensure it is properly set up.",
        },
        (3005, "GCPTestConnectionError"): {
            "message": "Error testing connection to GCP",
            "remediation": "Check the connection and ensure it is properly set up.",
        },
        (3006, "GCPLoadCredentialsFromDictError"): {
            "message": "Error loading credentials from dictionary",
            "remediation": "Check the credentials and ensure they are properly set up. client_id, client_secret and refresh_token are required.",
        },
        (3007, "GCPStaticCredentialsError"): {
            "message": "Error loading static credentials",
            "remediation": "Check the credentials and ensure they are properly set up. client_id, client_secret and refresh_token are required.",
        },
        (3008, "GCPInvalidProviderIdError"): {
            "message": "Provider does not match with the expected project_id",
            "remediation": "Check the provider and ensure it matches the expected project_id.",
        },
        (3009, "GCPCloudAssetAPINotUsedError"): {
            "message": "Cloud Asset API not used",
            "remediation": "Enable the Cloud Asset API for the project.",
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


class GCPCloudResourceManagerAPINotUsedError(GCPBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3000, file=file, original_exception=original_exception, message=message
        )


class GCPHTTPError(GCPBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3001, file=file, original_exception=original_exception, message=message
        )


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


class GCPGetProjectError(GCPCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3004, file=file, original_exception=original_exception, message=message
        )


class GCPTestConnectionError(GCPBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3005, file=file, original_exception=original_exception, message=message
        )


class GCPLoadCredentialsFromDictError(GCPCredentialsError):
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


class GCPCloudAssetAPINotUsedError(GCPBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            3009, file=file, original_exception=original_exception, message=message
        )
