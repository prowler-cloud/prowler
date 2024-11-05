from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 8000 to 8999 are reserved for Jira exceptions
class JiraBaseException(ProwlerException):
    """Base class for Security Hub exceptions."""

    JIRA_ERROR_CODES = {
        (8000, "JiraNoProjectsError"): {
            "message": "No projects were found in Jira.",
            "remediation": "Please create a project in Jira.",
        },
        (8001, "JiraAuthenticationError"): {
            "message": "Failed to authenticate with Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8002, "JiraTestConnectionError"): {
            "message": "Failed to connect to Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8003, "JiraCreateIssueError"): {
            "message": "Failed to create an issue in Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8004, "JiraGetProjectsError"): {
            "message": "Failed to get projects from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8005, "JiraGetCloudIdError"): {
            "message": "Failed to get the cloud ID from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8006, "JiraGetCloudIdNoResourcesError"): {
            "message": "No resources were found in Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8007, "JiraGetCloudIdResponseError"): {
            "message": "Failed to get the cloud ID from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8008, "JiraRefreshTokenResponseError"): {
            "message": "Failed to refresh the access token, response code did not match 200.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8009, "JiraRefreshTokenError"): {
            "message": "Failed to refresh the access token.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8010, "JiraGetAccessTokenError"): {
            "message": "Failed to get the access token.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8011, "JiraGetAuthResponseError"): {
            "message": "Failed to authenticate with Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8012, "JiraGetProjectsResponseError"): {
            "message": "Failed to get projects from Jira, response code did not match 200.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8013, "JiraSendFindingsResponseError"): {
            "message": "Failed to send findings to Jira, response code did not match 201.",
            "remediation": "Please check the finding format and try again.",
        },
        (8014, "JiraGetAvailableIssueTypesError"): {
            "message": "Failed to get available issue types from Jira.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8015, "JiraGetAvailableIssueTypesResponseError"): {
            "message": "Failed to get available issue types from Jira, response code did not match 200.",
            "remediation": "Please check the connection settings and permissions and try again.",
        },
        (8016, "JiraInvalidIssueTypeError"): {
            "message": "The issue type is invalid.",
            "remediation": "Please check the issue type and try again.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        module = "Jira"
        error_info = self.SECURITYHUB_ERROR_CODES.get((code, self.__class__.__name__))
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
            8000, file=file, original_exception=original_exception, message=message
        )


class JiraAuthenticationError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8001, file=file, original_exception=original_exception, message=message
        )


class JiraTestConnectionError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8002, file=file, original_exception=original_exception, message=message
        )


class JiraCreateIssueError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8003, file=file, original_exception=original_exception, message=message
        )


class JiraGetProjectsError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8004, file=file, original_exception=original_exception, message=message
        )


class JiraGetCloudIdError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8005, file=file, original_exception=original_exception, message=message
        )


class JiraGetCloudIdNoResourcesError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8006, file=file, original_exception=original_exception, message=message
        )


class JiraGetCloudIdResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8007, file=file, original_exception=original_exception, message=message
        )


class JiraRefreshTokenResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8008, file=file, original_exception=original_exception, message=message
        )


class JiraRefreshTokenError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8009, file=file, original_exception=original_exception, message=message
        )


class JiraGetAccessTokenError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8010, file=file, original_exception=original_exception, message=message
        )


class JiraGetAuthResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8011, file=file, original_exception=original_exception, message=message
        )


class JiraGetProjectsResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8012, file=file, original_exception=original_exception, message=message
        )


class JiraSendFindingsResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8013, file=file, original_exception=original_exception, message=message
        )


class JiraGetAvailableIssueTypesError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8014, file=file, original_exception=original_exception, message=message
        )


class JiraGetAvailableIssueTypesResponseError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8015, file=file, original_exception=original_exception, message=message
        )


class JiraInvalidIssueTypeError(JiraBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8016, file=file, original_exception=original_exception, message=message
        )
