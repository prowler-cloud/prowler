from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 9000 to 9999 are reserved for Jira exceptions
class JiraBaseException(ProwlerException):
    """Base class for Jira exceptions."""

    JIRA_ERROR_CODES = {
        (9000, "JiraNoProjectsError"): {
            "message": "No projects were found in Jira.",
            "remediation": "Please create a project in Jira.",
        },
        (9001, "JiraAuthenticationError"): {
            "message": "Failed to authenticate with Jira.",
            "remediation": "Please check the connection settings and permissions and try again. Needed scopes are: read:jira-user read:jira-work write:jira-work",
        },
        (9002, "JiraTestConnectionError"): {
            "message": "Failed to connect to Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9003, "JiraCreateIssueError"): {
            "message": "Failed to create an issue in Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9004, "JiraGetProjectsError"): {
            "message": "Failed to get projects from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9005, "JiraGetCloudIDError"): {
            "message": "Failed to get the cloud ID from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9006, "JiraGetCloudIDNoResourcesError"): {
            "message": "No resources were found in Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9007, "JiraGetCloudIDResponseError"): {
            "message": "Failed to get the cloud ID from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9008, "JiraRefreshTokenResponseError"): {
            "message": "Failed to refresh the access token, response code did not match 200.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9009, "JiraRefreshTokenError"): {
            "message": "Failed to refresh the access token.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9010, "JiraGetAccessTokenError"): {
            "message": "Failed to get the access token.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9011, "JiraGetAuthResponseError"): {
            "message": "Failed to authenticate with Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9012, "JiraGetProjectsResponseError"): {
            "message": "Failed to get projects from Jira, response code did not match 200.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9013, "JiraSendFindingsResponseError"): {
            "message": "Failed to send findings to Jira, response code did not match 201.",
            "remediation": "Please check the finding format and try again.",
        },
        (9014, "JiraGetAvailableIssueTypesError"): {
            "message": "Failed to get available issue types from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9015, "JiraGetAvailableIssueTypesResponseError"): {
            "message": "Failed to get available issue types from Jira, response code did not match 200.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (9016, "JiraInvalidIssueTypeError"): {
            "message": "The issue type is invalid.",
            "remediation": "Please check the issue type and try again.",
        },
        (9017, "JiraNoTokenError"): {
            "message": "No token was found.",
            "remediation": "Make sure the token is set when using the Jira integration.",
        },
        (9018, "JiraInvalidProjectKeyError"): {
            "message": "The project key is invalid.",
            "remediation": "Please check the project key and try again.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        module = "Jira"
        error_info = self.JIRA_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=module,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class JiraNoProjectsError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9000, file=file, original_exception=original_exception, message=message
        )


class JiraAuthenticationError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9001, file=file, original_exception=original_exception, message=message
        )


class JiraTestConnectionError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9002, file=file, original_exception=original_exception, message=message
        )


class JiraCreateIssueError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9003, file=file, original_exception=original_exception, message=message
        )


class JiraGetProjectsError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9004, file=file, original_exception=original_exception, message=message
        )


class JiraGetCloudIDError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9005, file=file, original_exception=original_exception, message=message
        )


class JiraGetCloudIDNoResourcesError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9006, file=file, original_exception=original_exception, message=message
        )


class JiraGetCloudIDResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9007, file=file, original_exception=original_exception, message=message
        )


class JiraRefreshTokenResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9008, file=file, original_exception=original_exception, message=message
        )


class JiraRefreshTokenError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9009, file=file, original_exception=original_exception, message=message
        )


class JiraGetAccessTokenError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9010, file=file, original_exception=original_exception, message=message
        )


class JiraGetAuthResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9011, file=file, original_exception=original_exception, message=message
        )


class JiraGetProjectsResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9012, file=file, original_exception=original_exception, message=message
        )


class JiraSendFindingsResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9013, file=file, original_exception=original_exception, message=message
        )


class JiraGetAvailableIssueTypesError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9014, file=file, original_exception=original_exception, message=message
        )


class JiraGetAvailableIssueTypesResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9015, file=file, original_exception=original_exception, message=message
        )


class JiraInvalidIssueTypeError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9016, file=file, original_exception=original_exception, message=message
        )


class JiraNoTokenError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9017, file=file, original_exception=original_exception, message=message
        )


class JiraInvalidProjectKeyError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9018, file=file, original_exception=original_exception, message=message
        )
