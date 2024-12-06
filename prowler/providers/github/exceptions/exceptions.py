from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 5000 to 5999 are reserved for Github exceptions
class GithubBaseException(ProwlerException):
    """Base class for Github Errors."""

    GITHUB_ERROR_CODES = {
        (5000, "GithubEnvironmentVariableError"): {
            "message": "Github environment variable error",
            "remediation": "Check the Github environment variables and ensure they are properly set.",
        },
        (5001, "GithubNonExistentTokenError"): {
            "message": "A Github token is required to authenticate against Github",
            "remediation": "Check the Github token and ensure it is properly set up.",
        },
        (5002, "GithubInvalidTokenError"): {
            "message": "Github token provided is not valid",
            "remediation": "Check the Github token and ensure it is valid.",
        },
        (5003, "GithubSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (5004, "GithubSetUpIdentityError"): {
            "message": "Github identity setup error due to bad credentials",
            "remediation": "Check credentials and ensure they are properly set up for Github and the identity provider.",
        },
        (5005, "GithubInvalidCredentialsError"): {
            "message": "Github invalid App Key or App ID for GitHub APP login",
            "remediation": "Check user and password and ensure they are properly set up as in your Github account.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Github"
        error_info = self.GITHUB_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class GithubCredentialsError(GithubBaseException):
    """Base class for Github credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class GithubEnvironmentVariableError(GithubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5000, file=file, original_exception=original_exception, message=message
        )


class GithubNonExistentTokenError(GithubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5001, file=file, original_exception=original_exception, message=message
        )


class GithubInvalidTokenError(GithubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5002, file=file, original_exception=original_exception, message=message
        )


class GithubSetUpSessionError(GithubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5003, file=file, original_exception=original_exception, message=message
        )


class GithubSetUpIdentityError(GithubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5004, file=file, original_exception=original_exception, message=message
        )


class GithubInvalidCredentialsError(GithubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            5005, file=file, original_exception=original_exception, message=message
        )
