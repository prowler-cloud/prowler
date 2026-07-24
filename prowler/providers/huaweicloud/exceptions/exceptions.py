from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 19000 to 19099 are reserved for Huawei Cloud exceptions
class HuaweiCloudBaseException(ProwlerException):
    """Base class for Huawei Cloud errors."""

    HUAWEICLOUD_ERROR_CODES = {
        (19000, "HuaweiCloudCredentialsError"): {
            "message": "Huawei Cloud credentials not found or invalid",
            "remediation": "Provide valid Huawei Cloud credentials via the HUAWEICLOUD_ACCESS_KEY_ID and HUAWEICLOUD_SECRET_ACCESS_KEY environment variables.",
        },
        (19001, "HuaweiCloudAuthenticationError"): {
            "message": "Huawei Cloud authentication failed",
            "remediation": "Verify the Access Key ID, Secret Access Key and Project/Domain ID, and ensure the credentials have the required IAM read permissions.",
        },
        (19002, "HuaweiCloudSetUpSessionError"): {
            "message": "Huawei Cloud session setup failed",
            "remediation": "Review the Huawei Cloud SDK initialization parameters and credentials.",
        },
        (19003, "HuaweiCloudIdentityError"): {
            "message": "Unable to retrieve Huawei Cloud identity or account information",
            "remediation": "Ensure the credentials allow access to the IAM Keystone APIs (list auth domains/projects and show user).",
        },
        (19004, "HuaweiCloudInvalidRegionError"): {
            "message": "One or more requested Huawei Cloud regions are invalid",
            "remediation": "Pass a valid Huawei Cloud region id to --region. See https://developer.huaweicloud.com/intl/en-us/endpoint for the current list.",
        },
        (19005, "HuaweiCloudInvalidProviderIdError"): {
            "message": "The provided Huawei Cloud account id does not match the authenticated account",
            "remediation": "Ensure the credentials belong to the expected Huawei Cloud account id.",
        },
        (19006, "HuaweiCloudServiceError"): {
            "message": "Huawei Cloud service error",
            "remediation": "Review the requested service and region, and check the Huawei Cloud API documentation for more details.",
        },
        (19007, "HuaweiCloudAssumeRoleError"): {
            "message": "Failed to assume the Huawei Cloud agency",
            "remediation": "Verify HUAWEICLOUD_AGENCY_NAME and the target account (HUAWEICLOUD_ASSUME_DOMAIN_ID or HUAWEICLOUD_ASSUME_DOMAIN_NAME), and ensure the agency delegates the required permissions to the authenticated account.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "HuaweiCloud"
        error_info = self.HUAWEICLOUD_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Huawei Cloud error",
                "remediation": "Check the Huawei Cloud API documentation for more details.",
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


class HuaweiCloudCredentialsError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud credential errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19000, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudAuthenticationError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud authentication errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19001, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudSetUpSessionError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19002, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudIdentityError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud identity errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19003, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudInvalidRegionError(HuaweiCloudBaseException):
    """Exception for invalid Huawei Cloud region filters."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19004, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudInvalidProviderIdError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud account/provider id mismatch."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19005, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudServiceError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud service errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19006, file=file, original_exception=original_exception, message=message
        )


class HuaweiCloudAssumeRoleError(HuaweiCloudBaseException):
    """Exception for Huawei Cloud agency (assume-role) errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            19007, file=file, original_exception=original_exception, message=message
        )
