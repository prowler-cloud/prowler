# Updated ERROR_CODES dictionary
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
}


# Updated ProwlerException class
class ProwlerException(Exception):
    """Base exception for all Prowler SDK errors."""

    def __init__(self, code, provider=None, file=None, original_exception=None):
        self.code = code
        self.provider = provider
        self.file = file
        # Use class name as the second key in the tuple
        error_info = ERROR_CODES.get((code, self.__class__.__name__))
        self.message = error_info["message"]
        self.remediation = error_info["remediation"]
        self.original_exception = original_exception
        super().__init__(f"[{self.code}] {self.message}")


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
