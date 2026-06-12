from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 16000 to 16999 are reserved for StackIT exceptions
class StackITBaseException(ProwlerException):
    """Base class for StackIT Errors."""

    STACKIT_ERROR_CODES = {
        (16001, "StackITNonExistentTokenError"): {
            "message": "A StackIT service account key file is required to authenticate against StackIT",
            "remediation": "Set --stackit-service-account-key-path or the STACKIT_SERVICE_ACCOUNT_KEY_PATH environment variable to a valid service account key JSON file.",
        },
        (16002, "StackITInvalidTokenError"): {
            "message": "StackIT service account key was rejected or lacks permissions",
            "remediation": "Verify the service account key file is current, has not been revoked, and that the service account has the required roles on the project.",
        },
        (16003, "StackITSetUpSessionError"): {
            "message": "Error setting up StackIT session",
            "remediation": "Check the session setup and ensure the StackIT SDK is properly configured.",
        },
        (16004, "StackITSetUpIdentityError"): {
            "message": "StackIT identity setup error due to bad credentials",
            "remediation": "Check credentials and ensure they are properly set up for StackIT.",
        },
        (16005, "StackITInvalidProjectIdError"): {
            "message": "The provided project ID is not valid or not accessible",
            "remediation": "Check the project ID and ensure you have access to it with the provided credentials.",
        },
        (16006, "StackITAPIError"): {
            "message": "Error calling StackIT API",
            "remediation": "Check the API endpoint and ensure the service is accessible. Verify network connectivity.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "StackIT"
        # Clone the catalog entry so per-instance message overrides do not
        # mutate the class-level dict and bleed into later exceptions raised
        # in the same process.
        base_info = self.STACKIT_ERROR_CODES.get((code, self.__class__.__name__))
        error_info = dict(base_info) if base_info else None
        if message and error_info is not None:
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


class StackITNonExistentTokenError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16001, file=file, original_exception=original_exception, message=message
        )


class StackITInvalidTokenError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16002, file=file, original_exception=original_exception, message=message
        )


class StackITSetUpSessionError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16003, file=file, original_exception=original_exception, message=message
        )


class StackITSetUpIdentityError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16004, file=file, original_exception=original_exception, message=message
        )


class StackITInvalidProjectIdError(StackITCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16005, file=file, original_exception=original_exception, message=message
        )


class StackITAPIError(StackITBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            16006, file=file, original_exception=original_exception, message=message
        )
