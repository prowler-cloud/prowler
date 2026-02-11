from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 6000 to 6999 are reserved for Google Workspace exceptions
class GoogleWorkspaceBaseException(ProwlerException):
    """Base class for Google Workspace Errors."""

    GOOGLEWORKSPACE_ERROR_CODES = {
        (6000, "GoogleWorkspaceEnvironmentVariableError"): {
            "message": "Google Workspace environment variable error",
            "remediation": "Check the Google Workspace environment variables and ensure they are properly set.",
        },
        (6001, "GoogleWorkspaceNoCredentialsError"): {
            "message": "Google Workspace credentials are required to authenticate",
            "remediation": "Provide either --credentials-file or --credentials-content with a valid Service Account JSON.",
        },
        (6002, "GoogleWorkspaceInvalidCredentialsError"): {
            "message": "Google Workspace credentials provided are not valid",
            "remediation": "Check the Service Account credentials and ensure they are valid.",
        },
        (6003, "GoogleWorkspaceSetUpSessionError"): {
            "message": "Error setting up Google Workspace session",
            "remediation": "Check the session setup and ensure credentials are properly configured.",
        },
        (6004, "GoogleWorkspaceSetUpIdentityError"): {
            "message": "Google Workspace identity setup error due to bad credentials or API access",
            "remediation": "Check credentials and ensure the Service Account has proper API access and Domain-Wide Delegation configured.",
        },
        (6005, "GoogleWorkspaceImpersonationError"): {
            "message": "Error impersonating user with Domain-Wide Delegation",
            "remediation": "Ensure the Service Account has Domain-Wide Delegation enabled and the delegated user email is correct.",
        },
        (6006, "GoogleWorkspaceMissingDelegatedUserError"): {
            "message": "Delegated user email is required for Domain-Wide Delegation",
            "remediation": "Provide --delegated-user with a valid user email from your domain.",
        },
        (6007, "GoogleWorkspaceInsufficientScopesError"): {
            "message": "Service Account does not have required OAuth scopes",
            "remediation": "Ensure the Service Account has the required scopes configured in Domain-Wide Delegation settings.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "GoogleWorkspace"
        error_info = self.GOOGLEWORKSPACE_ERROR_CODES.get(
            (code, self.__class__.__name__)
        )
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class GoogleWorkspaceCredentialsError(GoogleWorkspaceBaseException):
    """Base class for Google Workspace credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class GoogleWorkspaceEnvironmentVariableError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6000, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceNoCredentialsError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6001, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceInvalidCredentialsError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6002, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceSetUpSessionError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6003, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceSetUpIdentityError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6004, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceImpersonationError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6005, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceMissingDelegatedUserError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6006, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceInsufficientScopesError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6007, file=file, original_exception=original_exception, message=message
        )
