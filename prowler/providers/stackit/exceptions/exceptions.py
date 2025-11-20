from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 10000 to 10999 are reserved for StackIT exceptions
class StackITBaseException(ProwlerException):
    """Base class for StackIT Errors."""

    STACKIT_ERROR_CODES = {
        (10000, "StackITEnvironmentVariableError"): {
            "message": "StackIT environment variable error",
            "remediation": "Check the StackIT environment variables and ensure they are properly set.",
        },
        (10001, "StackITNonExistentTokenError"): {
            "message": "A StackIT API token is required to authenticate against StackIT",
            "remediation": "Check the StackIT API token and ensure it is properly set up. Use --stackit-api-token or set STACKIT_API_TOKEN environment variable.",
        },
        (10002, "StackITInvalidTokenError"): {
            "message": "StackIT API token provided is not valid",
            "remediation": "Check the StackIT API token and ensure it is valid. Verify that the token has not expired.",
        },
        (10003, "StackITSetUpSessionError"): {
            "message": "Error setting up StackIT session",
            "remediation": "Check the session setup and ensure the StackIT SDK is properly configured.",
        },
        (10004, "StackITSetUpIdentityError"): {
            "message": "StackIT identity setup error due to bad credentials",
            "remediation": "Check credentials and ensure they are properly set up for StackIT.",
        },
        (10005, "StackITInvalidProjectIdError"): {
            "message": "The provided project ID is not valid or not accessible",
            "remediation": "Check the project ID and ensure you have access to it with the provided credentials.",
        },
        (10006, "StackITAPIError"): {
            "message": "Error calling StackIT API",
            "remediation": "Check the API endpoint and ensure the service is accessible. Verify network connectivity.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "StackIT"
        error_info = self.STACKIT_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class StackITCredentialsError(StackITBaseException):
    """Base class for StackIT credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class StackITEnvironmentVariableError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10000, file=file, original_exception=original_exception, message=message
        )


class StackITNonExistentTokenError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10001, file=file, original_exception=original_exception, message=message
        )


class StackITInvalidTokenError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10002, file=file, original_exception=original_exception, message=message
        )


class StackITSetUpSessionError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10003, file=file, original_exception=original_exception, message=message
        )


class StackITSetUpIdentityError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10004, file=file, original_exception=original_exception, message=message
        )


class StackITInvalidProjectIdError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10005, file=file, original_exception=original_exception, message=message
        )


class StackITAPIError(StackITBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            10006, file=file, original_exception=original_exception, message=message
        )
