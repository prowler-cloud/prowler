from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 12000 to 12999 are reserved for Google Workspace exceptions
class GoogleWorkspaceBaseException(ProwlerException):
    """Base class for Google Workspace Errors."""

    GOOGLEWORKSPACE_ERROR_CODES = {
        (12000, "GoogleWorkspaceEnvironmentVariableError"): {
            "message": "Google Workspace environment variable error",
            "remediation": "Check the Google Workspace environment variables and ensure they are properly set.",
        },
        (12001, "GoogleWorkspaceNoCredentialsError"): {
            "message": "Google Workspace credentials are required to authenticate",
            "remediation": "Set the GOOGLEWORKSPACE_CREDENTIALS_FILE or GOOGLEWORKSPACE_CREDENTIALS_CONTENT environment variable with a valid Service Account JSON.",
        },
        (12002, "GoogleWorkspaceInvalidCredentialsError"): {
            "message": "Google Workspace credentials provided are not valid",
            "remediation": "Check the Service Account credentials and ensure they are valid.",
        },
        (12003, "GoogleWorkspaceSetUpSessionError"): {
            "message": "Error setting up Google Workspace session",
            "remediation": "Check the session setup and ensure credentials are properly configured.",
        },
        (12004, "GoogleWorkspaceSetUpIdentityError"): {
            "message": "Google Workspace identity setup error due to bad credentials or API access",
            "remediation": "Check credentials and ensure the Service Account has proper API access and Domain-Wide Delegation configured.",
        },
        (12005, "GoogleWorkspaceImpersonationError"): {
            "message": "Error impersonating user with Domain-Wide Delegation",
            "remediation": "Ensure the Service Account has Domain-Wide Delegation enabled and the delegated user email is correct.",
        },
        (12006, "GoogleWorkspaceMissingDelegatedUserError"): {
            "message": "Delegated user email is required for Domain-Wide Delegation",
            "remediation": "Set the GOOGLEWORKSPACE_DELEGATED_USER environment variable with a valid super admin email from your domain.",
        },
        (12007, "GoogleWorkspaceInsufficientScopesError"): {
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
            12000, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceNoCredentialsError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12001, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceInvalidCredentialsError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12002, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceSetUpSessionError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12003, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceSetUpIdentityError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12004, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceImpersonationError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12005, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceMissingDelegatedUserError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12006, file=file, original_exception=original_exception, message=message
        )


class GoogleWorkspaceInsufficientScopesError(GoogleWorkspaceCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            12007, file=file, original_exception=original_exception, message=message
        )
