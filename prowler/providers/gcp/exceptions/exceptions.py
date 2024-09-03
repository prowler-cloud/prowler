from prowler.exceptions.exceptions import ProwlerException


class GCPBaseException(ProwlerException):
    """Base class for GCP Errors."""

    GCP_ERROR_CODES = {
        (1925, "GCPCloudResourceManagerAPINotUsedError"): {
            "message": "Cloud Resource Manager API not used",
            "remediation": "Enable the Cloud Resource Manager API for the project.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1926, "GCPHTTPError"): {
            "message": "HTTP error",
            "remediation": "Check the HTTP error and ensure the request is properly formatted.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1927, "GCPNoAccesibleProjectsError"): {
            "message": "No Project IDs can be accessed via Google Credentials",
            "remediation": "Ensure the project is accessible and properly set up.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1928, "GCPSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1929, "GCPGetProjectError"): {
            "message": "Error getting project",
            "remediation": "Check the project and ensure it is properly set up.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1930, "GCPTestConnectionError"): {
            "message": "Error testing connection to GCP",
            "remediation": "Check the connection and ensure it is properly set up.",
            "file": "{file}",
            "provider": "{provider}",
        },
    }

    def __init__(self, code, provider="GCP", file=None, original_exception=None):
        error_info = self.GCP_ERROR_CODES.get((code, self.__class__.__name__))
        super().__init__(code, provider, file, original_exception, error_info)


class GCPCloudResourceManagerAPINotUsedError(GCPBaseException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(1925, file=file, original_exception=original_exception)


class GCPHTTPError(GCPBaseException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(1926, file=file, original_exception=original_exception)


class GCPNoAccesibleProjectsError(GCPBaseException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(1927, file=file, original_exception=original_exception)


class GCPSetUpSessionError(GCPBaseException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(1928, file=file, original_exception=original_exception)


class GCPGetProjectError(GCPBaseException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(1929, file=file, original_exception=original_exception)


class GCPTestConnectionError(GCPBaseException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(1930, file=file, original_exception=original_exception)
