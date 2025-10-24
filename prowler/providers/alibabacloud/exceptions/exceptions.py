"""
Alibaba Cloud Provider Exceptions

This module contains exception classes for the Alibaba Cloud provider.
"""


class AlibabaCloudException(Exception):
    """Base exception for Alibaba Cloud provider errors"""
    pass


class AlibabaCloudAuthenticationError(AlibabaCloudException):
    """
    AlibabaCloudAuthenticationError is raised when authentication fails

    This can occur due to:
    - Invalid AccessKey credentials
    - Expired STS tokens
    - Insufficient permissions
    """
    def __init__(self, message="Authentication to Alibaba Cloud failed"):
        super().__init__(message)


class AlibabaCloudSetUpSessionError(AlibabaCloudException):
    """
    AlibabaCloudSetUpSessionError is raised when session setup fails
    """
    def __init__(self, message="Failed to set up Alibaba Cloud session"):
        super().__init__(message)


class AlibabaCloudAPIError(AlibabaCloudException):
    """
    AlibabaCloudAPIError is raised when an API call fails
    """
    def __init__(self, service: str, operation: str, error: str):
        message = f"Alibaba Cloud API Error - Service: {service}, Operation: {operation}, Error: {error}"
        super().__init__(message)


class AlibabaCloudNoCredentialsError(AlibabaCloudException):
    """
    AlibabaCloudNoCredentialsError is raised when no credentials are found
    """
    def __init__(self, message="No Alibaba Cloud credentials found"):
        super().__init__(message)


class AlibabaCloudInvalidRegionError(AlibabaCloudException):
    """
    AlibabaCloudInvalidRegionError is raised when an invalid region is specified
    """
    def __init__(self, region: str):
        message = f"Invalid Alibaba Cloud region: {region}"
        super().__init__(message)


class AlibabaCloudAssumeRoleError(AlibabaCloudException):
    """
    AlibabaCloudAssumeRoleError is raised when assuming a RAM role fails
    """
    def __init__(self, role_arn: str, error: str):
        message = f"Failed to assume RAM role {role_arn}: {error}"
        super().__init__(message)


class AlibabaCloudInvalidAccessKeyError(AlibabaCloudException):
    """
    AlibabaCloudInvalidAccessKeyError is raised when AccessKey credentials are invalid
    """
    def __init__(self, message="Invalid Alibaba Cloud AccessKey credentials"):
        super().__init__(message)


class AlibabaCloudAccountNotFoundError(AlibabaCloudException):
    """
    AlibabaCloudAccountNotFoundError is raised when account information cannot be retrieved
    """
    def __init__(self, message="Unable to retrieve Alibaba Cloud account information"):
        super().__init__(message)


class AlibabaCloudConfigValidationError(AlibabaCloudException):
    """
    AlibabaCloudConfigValidationError is raised when configuration validation fails
    """
    def __init__(self, message="Alibaba Cloud configuration validation failed"):
        super().__init__(message)
