"""GitHub Integration Exceptions."""


class GitHubBaseException(Exception):
    """Base exception for all GitHub integration errors."""


class GitHubAuthenticationError(GitHubBaseException):
    """Exception raised when GitHub authentication fails."""


class GitHubTokenError(GitHubBaseException):
    """Exception raised when GitHub token is invalid or missing."""


class GitHubGetRepositoriesError(GitHubBaseException):
    """Exception raised when fetching repositories fails."""


class GitHubGetRepositoriesResponseError(GitHubBaseException):
    """Exception raised when the response from GitHub repositories API is invalid."""


class GitHubNoRepositoriesError(GitHubBaseException):
    """Exception raised when no repositories are found."""


class GitHubInvalidRepositoryError(GitHubBaseException):
    """Exception raised when an invalid repository is specified."""


class GitHubCreateIssueError(GitHubBaseException):
    """Exception raised when creating a GitHub issue fails."""


class GitHubCreateIssueResponseError(GitHubBaseException):
    """Exception raised when the response from GitHub create issue API is invalid."""


class GitHubTestConnectionError(GitHubBaseException):
    """Exception raised when testing the connection to GitHub fails."""


class GitHubInvalidParameterError(GitHubBaseException):
    """Exception raised when an invalid parameter is provided."""


class GitHubSendFindingsResponseError(GitHubBaseException):
    """Exception raised when sending findings to GitHub fails."""


class GitHubGetLabelsError(GitHubBaseException):
    """Exception raised when fetching repository labels fails."""


class GitHubGetLabelsResponseError(GitHubBaseException):
    """Exception raised when the response from GitHub labels API is invalid."""
