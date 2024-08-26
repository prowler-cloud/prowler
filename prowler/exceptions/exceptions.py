class ProwlerException(Exception):
    """Base exception for all Prowler SDK errors."""

    ERROR_CODES = {
        (1901, "ProviderConnectionError"): {
            "message": "Provider connection error",
            "remediation": "Check your network connection and ensure the service is reachable.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1902, "ProviderAuthenticationError"): {
            "message": "Provider authentication failed",
            "remediation": "Verify your credentials and ensure they have the necessary permissions.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1903, "ProviderTimeoutError"): {
            "message": "Request to provider timed out",
            "remediation": "Consider increasing the timeout setting or check the service status.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1905, "FileExistsError"): {
            "message": "File could not be updated, it already exists",
            "remediation": "Provide a different file or set overwrite=True to overwrite the existing file.",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1906, "AWSClientError"): {
            "message": "AWS ClientError occurred",
            "remediation": "Check your AWS client configuration and permissions.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1907, "AWSProfileNotFoundError"): {
            "message": "AWS Profile not found",
            "remediation": "Ensure the AWS profile is correctly configured.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1908, "AWSNoCredentialsError"): {
            "message": "No AWS credentials found",
            "remediation": "Verify that AWS credentials are properly set up.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1909, "AWSArgumentTypeValidationError"): {
            "message": "AWS argument type validation error",
            "remediation": "Check the provided argument types specific to AWS and ensure they meet the required format.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1910, "AWSSetUpSessionError"): {
            "message": "AWS session setup error",
            "remediation": "Check the AWS session setup and ensure it is properly configured.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1911, "AWSIAMRoleARNRegionNotEmtpy"): {
            "message": "AWS IAM Role ARN region is not empty",
            "remediation": "Check the AWS IAM Role ARN region and ensure it is empty.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1912, "AWSIAMRoleARNPartitionEmpty"): {
            "message": "AWS IAM Role ARN partition is empty",
            "remediation": "Check the AWS IAM Role ARN partition and ensure it is not empty.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1913, "AWSIAMRoleARNMissingFields"): {
            "message": "AWS IAM Role ARN missing fields",
            "remediation": "Check the AWS IAM Role ARN and ensure all required fields are present.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1914, "AWSIAMRoleARNServiceNotIAMnorSTS"): {
            "message": "AWS IAM Role ARN service is not IAM nor STS",
            "remediation": "Check the AWS IAM Role ARN service and ensure it is either IAM or STS.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1915, "AWSIAMRoleARNInvalidAccountID"): {
            "message": "AWS IAM Role ARN account ID is invalid",
            "remediation": "Check the AWS IAM Role ARN account ID and ensure it is a valid 12-digit number.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1916, "AWSIAMRoleARNInvalidResourceType"): {
            "message": "AWS IAM Role ARN resource type is invalid",
            "remediation": "Check the AWS IAM Role ARN resource type and ensure it is valid.",
            "file": "{file}",
            "provider": "AWS",
        },
        (1917, "AWSIAMRoleARNEmptyResource"): {
            "message": "AWS IAM Role ARN resource is empty",
            "remediation": "Check the AWS IAM Role ARN resource and ensure it is not empty.",
            "file": "{file}",
            "provider": "AWS",
        },
    }

    def __init__(self, code, provider=None, file=None, original_exception=None):
        self.code = code
        self.provider = provider
        self.file = file
        # Use class name as the second key in the tuple
        error_info = self.ERROR_CODES.get((code, self.__class__.__name__))
        self.message = error_info["message"]
        self.remediation = error_info["remediation"]
        self.original_exception = original_exception
        super().__init__(
            f"[{self.code}] {self.message} - {self.remediation} - {self.file} - {self.original_exception} - {self.provider}"
        )


# Specific exception classes remain the same
class ProviderConnectionError(ProwlerException):
    def __init__(self, provider, file, original_exception=None):
        super().__init__(1901, provider, file, original_exception)


class ProviderAuthenticationError(ProwlerException):
    def __init__(self, provider, file, original_exception=None):
        super().__init__(1902, provider, file, original_exception)


class ProviderTimeoutError(ProwlerException):
    def __init__(self, provider, file, original_exception=None):
        super().__init__(1903, provider, file, original_exception)


class FileExistsError(ProwlerException):
    def __init__(self, file, original_exception=None):
        super().__init__(
            1905, provider=None, file=file, original_exception=original_exception
        )
