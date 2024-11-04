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
