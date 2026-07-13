"""Huawei Cloud Provider Exceptions"""

from prowler.lib.logger import logger


class HuaweiCloudException(Exception):
    """Base exception for Huawei Cloud provider."""

    error_code = 7000
    message = "Huawei Cloud provider error"

    def __init__(self, message=None, error_code=None, **kwargs):
        self.message = message or self.message
        self.error_code = error_code or self.error_code
        self.kwargs = kwargs
        super().__init__(self.message)

    def __str__(self):
        error_msg = f"[{self.error_code}] {self.message}"
        if self.kwargs:
            error_msg += f" - {self.kwargs}"
        return error_msg


class HuaweiCloudNoCredentialsError(HuaweiCloudException):
    """Raised when no credentials are found."""

    error_code = 7001
    message = "No Huawei Cloud credentials found"


class HuaweiCloudInvalidCredentialsError(HuaweiCloudException):
    """Raised when credentials are invalid."""

    error_code = 7002
    message = "Invalid Huawei Cloud credentials"


class HuaweiCloudSetUpSessionError(HuaweiCloudException):
    """Raised when session setup fails."""

    error_code = 7003
    message = "Failed to set up Huawei Cloud session"


class HuaweiCloudRegionValidationError(HuaweiCloudException):
    """Raised when region validation fails."""

    error_code = 7004
    message = "Invalid Huawei Cloud region"


class HuaweiCloudServiceError(HuaweiCloudException):
    """Raised when a Huawei Cloud service error occurs."""

    error_code = 7005
    message = "Huawei Cloud service error"


class HuaweiCloudClientError(HuaweiCloudException):
    """Raised when a Huawei Cloud client error occurs."""

    error_code = 7006
    message = "Huawei Cloud client error"


class HuaweiCloudNoActiveSessionError(HuaweiCloudException):
    """Raised when no active session is found."""

    error_code = 7007
    message = "No active Huawei Cloud session"


class HuaweiCloudAssumeRoleError(HuaweiCloudException):
    """Raised when assuming a role fails."""

    error_code = 7008
    message = "Failed to assume Huawei Cloud role"


class HuaweiCloudIdentityError(HuaweiCloudException):
    """Raised when identity validation fails."""

    error_code = 7009
    message = "Failed to validate Huawei Cloud identity"


class HuaweiCloudConfigError(HuaweiCloudException):
    """Raised when configuration is invalid."""

    error_code = 7010
    message = "Invalid Huawei Cloud configuration"


# Huawei Cloud SDK specific exceptions
class HuaweiCloudSDKError(HuaweiCloudException):
    """Base exception for Huawei Cloud SDK errors."""

    error_code = 7100
    message = "Huawei Cloud SDK error"


class HuaweiCloudSDKClientError(HuaweiCloudSDKError):
    """Raised when Huawei Cloud SDK client error occurs."""

    error_code = 7101
    message = "Huawei Cloud SDK client error"


class HuaweiCloudSDKServerError(HuaweiCloudSDKError):
    """Raised when Huawei Cloud SDK server error occurs."""

    error_code = 7102
    message = "Huawei Cloud SDK server error"


class HuaweiCloudSDKRequestTimeoutError(HuaweiCloudSDKError):
    """Raised when Huawei Cloud SDK request times out."""

    error_code = 7103
    message = "Huawei Cloud SDK request timeout"


class HuaweiCloudSDKConnectionError(HuaweiCloudSDKError):
    """Raised when Huawei Cloud SDK connection fails."""

    error_code = 7104
    message = "Huawei Cloud SDK connection error"


# Service-specific exceptions
class HuaweiCloudOBSError(HuaweiCloudServiceError):
    """Raised when OBS service error occurs."""

    error_code = 7200
    message = "Huawei Cloud OBS service error"


class HuaweiCloudECSError(HuaweiCloudServiceError):
    """Raised when ECS service error occurs."""

    error_code = 7300
    message = "Huawei Cloud ECS service error"


class HuaweiCloudVPCError(HuaweiCloudServiceError):
    """Raised when VPC service error occurs."""

    error_code = 7400
    message = "Huawei Cloud VPC service error"


class HuaweiCloudIAMError(HuaweiCloudServiceError):
    """Raised when IAM service error occurs."""

    error_code = 7500
    message = "Huawei Cloud IAM service error"


class HuaweiCloudRDSError(HuaweiCloudServiceError):
    """Raised when RDS service error occurs."""

    error_code = 7600
    message = "Huawei Cloud RDS service error"


class HuaweiCloudCTSError(HuaweiCloudServiceError):
    """Raised when CTS service error occurs."""

    error_code = 7700
    message = "Huawei Cloud CTS service error"


class HuaweiCloudKMSError(HuaweiCloudServiceError):
    """Raised when KMS service error occurs."""

    error_code = 7800
    message = "Huawei Cloud KMS service error"


class HuaweiCloudWAFError(HuaweiCloudServiceError):
    """Raised when WAF service error occurs."""

    error_code = 7900
    message = "Huawei Cloud WAF service error"


def handle_huaweicloud_exception(error: Exception, service: str = None) -> HuaweiCloudException:
    """
    Handle Huawei Cloud SDK exceptions and convert them to HuaweiCloudException.
    
    Args:
        error: The original exception
        service: The service name (optional)
    
    Returns:
        HuaweiCloudException: The converted exception
    """
    error_message = str(error)
    
    # Check if it's already a HuaweiCloudException
    if isinstance(error, HuaweiCloudException):
        return error
    
    # Check for Huawei Cloud SDK exceptions
    try:
        # Huawei Cloud SDK exceptions have specific attributes
        # We'll check the error message for common patterns
        if "ClientRequestException" in error_message or "connection" in error_message.lower():
            return HuaweiCloudSDKClientError(
                message=f"Huawei Cloud SDK client error: {error_message}",
                service=service
            )
        elif "ServerResponseException" in error_message or "server" in error_message.lower():
            return HuaweiCloudSDKServerError(
                message=f"Huawei Cloud SDK server error: {error_message}",
                service=service
            )
        elif "timeout" in error_message.lower() or "timed out" in error_message.lower():
            return HuaweiCloudSDKRequestTimeoutError(
                message=f"Huawei Cloud SDK request timeout: {error_message}",
                service=service
            )
        elif "credentials" in error_message.lower() or "authentication" in error_message.lower():
            return HuaweiCloudInvalidCredentialsError(
                message=f"Huawei Cloud credentials error: {error_message}",
                service=service
            )
        elif "region" in error_message.lower() or "endpoint" in error_message.lower():
            return HuaweiCloudRegionValidationError(
                message=f"Huawei Cloud region error: {error_message}",
                service=service
            )
    except Exception as e:
        logger.error(f"Error handling Huawei Cloud exception: {e}")
    
    # Default to generic Huawei Cloud exception
    return HuaweiCloudException(
        message=f"Huawei Cloud error: {error_message}",
        service=service
    )
