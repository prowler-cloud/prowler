from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 5000 to 5999 are reserved for GitHub exceptions
class GitHubBaseException(ProwlerException):
    """Base class for GitHub Errors."""

    GITHUB_ERROR_CODES = {
        (2000, "GitHubEnvironmentVariableError"): {
            "message": "GitHub environment variable error",
            "remediation": "Check the GitHub environment variables and ensure they are properly set.",
        },
        (2001, "GitHubInvalidTokenError"): {
            "message": "GitHub token provided is not valid",
            "remediation": "Check the GitHub token and ensure it is valid.",
        },
        (2002, "GitHubSetUpIdentityError"): {
            "message": "GitHub identity setup error related with credentials",
            "remediation": "Check credentials and ensure they are properly set up for GitHub and the identity provider.",
        },
        (2003, "GitHubNoAuthenticationMethodError"): {
            "message": "No GitHub authentication method found",
            "remediation": "Check that any authentication method is properly set up for GitHub.",
        },
        (2006, "GitHubArgumentTypeValidationError"): {
            "message": "GitHub argument type validation error",
            "remediation": "Check the provided argument types specific to GitHub and ensure they meet the required format.",
        },
        (2010, "GitHubHTTPResponseError"): {
            "message": "Error in HTTP response from GitHub",
            "remediation": "",
        },
        (2014, "GitHubClientAuthenticationError"): {
            "message": "Error in client authentication",
            "remediation": "Check the client authentication and ensure it is properly set up.",
        },
        (2015, "GitHubSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "GitHub"
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


class GitHubCredentialsError(GitHubBaseException):
    """Base class for GitHub credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class GitHubEnvironmentVariableError(GitHubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2000, file=file, original_exception=original_exception, message=message
        )


class GitHubInvalidTokenError(GitHubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2001, file=file, original_exception=original_exception, message=message
        )


class GitHubSetUpIdentityError(GitHubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2002, file=file, original_exception=original_exception, message=message
        )


class GitHubNoAuthenticationMethodError(GitHubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2003, file=file, original_exception=original_exception, message=message
        )


class GitHubArgumentTypeValidationError(GitHubBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2006, file=file, original_exception=original_exception, message=message
        )


class GitHubHTTPResponseError(GitHubBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2010, file=file, original_exception=original_exception, message=message
        )


class GitHubClientAuthenticationError(GitHubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2014, file=file, original_exception=original_exception, message=message
        )


class GitHubSetUpSessionError(GitHubCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2015, file=file, original_exception=original_exception, message=message
        )
