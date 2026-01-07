"""GitHub Integration Exceptions Package."""

from prowler.lib.outputs.github.exceptions.exceptions import (
    GitHubAuthenticationError,
    GitHubBaseException,
    GitHubCreateIssueError,
    GitHubCreateIssueResponseError,
    GitHubGetLabelsError,
    GitHubGetLabelsResponseError,
    GitHubGetRepositoriesError,
    GitHubGetRepositoriesResponseError,
    GitHubInvalidParameterError,
    GitHubInvalidRepositoryError,
    GitHubNoRepositoriesError,
    GitHubSendFindingsResponseError,
    GitHubTestConnectionError,
    GitHubTokenError,
)

__all__ = [
    "GitHubAuthenticationError",
    "GitHubBaseException",
    "GitHubCreateIssueError",
    "GitHubCreateIssueResponseError",
    "GitHubGetLabelsError",
    "GitHubGetLabelsResponseError",
    "GitHubGetRepositoriesError",
    "GitHubGetRepositoriesResponseError",
    "GitHubInvalidParameterError",
    "GitHubInvalidRepositoryError",
    "GitHubNoRepositoriesError",
    "GitHubSendFindingsResponseError",
    "GitHubTestConnectionError",
    "GitHubTokenError",
]
