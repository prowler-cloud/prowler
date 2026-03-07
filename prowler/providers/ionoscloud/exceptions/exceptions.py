from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 13000 to 13999 are reserved for IONOS Cloud exceptions
class IonosCloudBaseException(ProwlerException):
    """Base class for IONOS Cloud Provider exceptions."""

    IONOSCLOUD_ERROR_CODES = {
        (13000, "IonosCloudClientError"): {
            "message": "IONOS Cloud client error occurred",
            "remediation": "Check your IONOS Cloud client configuration and permissions.",
        },
        (13001, "IonosCloudNoCredentialsError"): {
            "message": "No credentials found for IONOS Cloud provider",
            "remediation": "Provide credentials via --username/--password, --token, or the "
            "IONOS_USERNAME/IONOS_PASSWORD/IONOS_TOKEN environment variables.",
        },
        (13002, "IonosCloudInvalidCredentialsError"): {
            "message": "Invalid credentials provided for IONOS Cloud provider",
            "remediation": "Check your IONOS Cloud credentials and ensure they are valid and have proper permissions.",
        },
        (13003, "IonosCloudSetUpSessionError"): {
            "message": "Failed to set up session for IONOS Cloud provider",
            "remediation": "Check the IONOS Cloud session setup and ensure it is properly configured.",
        },
        (13004, "IonosCloudInvalidRegionError"): {
            "message": "Invalid location specified for IONOS Cloud provider",
            "remediation": "Check the location and ensure it is a valid IONOS Cloud location (e.g., de/fra, us/las).",
        },
        (13005, "IonosCloudArgumentTypeValidationError"): {
            "message": "IONOS Cloud argument type validation error",
            "remediation": "Check the provided argument types specific to IONOS Cloud and ensure they meet the required format.",
        },
        (13006, "IonosCloudHTTPError"): {
            "message": "IONOS Cloud HTTP/API error",
            "remediation": "Check the IONOS Cloud API request and response, and ensure the service is accessible.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.IONOSCLOUD_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="IonosCloud",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class IonosCloudCredentialsError(IonosCloudBaseException):
    """Base class for IONOS Cloud credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class IonosCloudClientError(IonosCloudCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13000, file=file, original_exception=original_exception, message=message
        )


class IonosCloudNoCredentialsError(IonosCloudCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13001, file=file, original_exception=original_exception, message=message
        )


class IonosCloudInvalidCredentialsError(IonosCloudCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13002, file=file, original_exception=original_exception, message=message
        )


class IonosCloudSetUpSessionError(IonosCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13003, file=file, original_exception=original_exception, message=message
        )


class IonosCloudInvalidRegionError(IonosCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13004, file=file, original_exception=original_exception, message=message
        )


class IonosCloudArgumentTypeValidationError(IonosCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13005, file=file, original_exception=original_exception, message=message
        )


class IonosCloudHTTPError(IonosCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            13006, file=file, original_exception=original_exception, message=message
        )
