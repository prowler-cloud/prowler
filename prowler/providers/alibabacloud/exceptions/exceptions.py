from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 10000 to 10999 are reserved for AlibabaCloud exceptions
class AlibabaCloudBaseException(ProwlerException):
    """Base class for Alibaba Cloud Provider exceptions"""

    ALIBABACLOUD_ERROR_CODES = {
        (10000, "AlibabaCloudClientError"): {
            "message": "Alibaba Cloud ClientError occurred",
            "remediation": "Check your Alibaba Cloud client configuration and permissions.",
        },
        (10001, "AlibabaCloudNoCredentialsError"): {
            "message": "No credentials found for Alibaba Cloud provider",
            "remediation": "Verify that Alibaba Cloud credentials are properly set up. Access Key ID and Access Key Secret are required.",
        },
        (10002, "AlibabaCloudInvalidCredentialsError"): {
            "message": "Invalid credentials provided for Alibaba Cloud provider",
            "remediation": "Check your Alibaba Cloud credentials and ensure they are valid and have proper permissions.",
        },
        (10003, "AlibabaCloudSetUpSessionError"): {
            "message": "Failed to set up session for Alibaba Cloud provider",
            "remediation": "Check the Alibaba Cloud session setup and ensure it is properly configured.",
        },
        (10004, "AlibabaCloudAssumeRoleError"): {
            "message": "Failed to assume role for Alibaba Cloud provider",
            "remediation": "Check the Alibaba Cloud assume role configuration and ensure it is properly set up.",
        },
        (10005, "AlibabaCloudInvalidRegionError"): {
            "message": "Invalid region specified for Alibaba Cloud provider",
            "remediation": "Check the region and ensure it is a valid region for Alibaba Cloud.",
        },
        (10006, "AlibabaCloudArgumentTypeValidationError"): {
            "message": "Alibaba Cloud argument type validation error",
            "remediation": "Check the provided argument types specific to Alibaba Cloud and ensure they meet the required format.",
        },
        (10007, "AlibabaCloudHTTPError"): {
            "message": "Alibaba Cloud HTTP/API error",
            "remediation": "Check the Alibaba Cloud API request and response, and ensure the service is accessible.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.ALIBABACLOUD_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="AlibabaCloud",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class AlibabaCloudCredentialsError(AlibabaCloudBaseException):
    """Base class for Alibaba Cloud credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class AlibabaCloudClientError(AlibabaCloudCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10000, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudNoCredentialsError(AlibabaCloudCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10001, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudInvalidCredentialsError(AlibabaCloudCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10002, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudSetUpSessionError(AlibabaCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10003, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudAssumeRoleError(AlibabaCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10004, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudInvalidRegionError(AlibabaCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10005, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudArgumentTypeValidationError(AlibabaCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10006, file=file, original_exception=original_exception, message=message
        )


class AlibabaCloudHTTPError(AlibabaCloudBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10007, file=file, original_exception=original_exception, message=message
        )
