"""Typed result models for Jira issue creation and lookup operations."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class JiraCreationOutcome(str, Enum):
    """Possible outcomes of a Jira issue creation attempt."""

    CONFIRMED_SUCCESS = "confirmed_success"
    CONFIRMED_REJECTION = "confirmed_rejection"
    RETRYABLE_FAILURE = "retryable_failure"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class JiraCreationResult:
    """Immutable result of a Jira issue creation attempt."""

    outcome: JiraCreationOutcome
    issue_key: Optional[str] = None
    issue_id: Optional[str] = None
    issue_url: Optional[str] = None
    delivery_marker: Optional[str] = None
    http_status: Optional[int] = None
    retry_after: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    def __post_init__(self) -> None:
        """Require a complete issue reference for confirmed creation."""
        if self.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS and not all(
            (self.issue_key, self.issue_id, self.issue_url)
        ):
            raise ValueError(
                "Confirmed Jira issue creation requires an issue key, ID, and URL"
            )

    @property
    def is_confirmed_success(self) -> bool:
        """Return whether Jira confirmed that it created the issue."""
        return self.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS

    def __bool__(self) -> bool:
        """Preserve boolean compatibility for confirmed creation only."""
        return self.is_confirmed_success


@dataclass(frozen=True)
class JiraIssueReference:
    """Stable Jira issue identity and its last known key."""

    issue_id: str
    issue_key: str


class JiraIssueLookupOutcome(str, Enum):
    """Possible outcomes of looking up a Jira issue."""

    OPEN = "open"
    DONE = "done"
    MOVED = "moved"
    MISSING = "missing"
    FORBIDDEN = "forbidden"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class JiraIssueStatusResult:
    """Immutable result of looking up a Jira issue's current state."""

    reference: JiraIssueReference
    outcome: JiraIssueLookupOutcome
    current_issue_id: Optional[str] = None
    current_issue_key: Optional[str] = None
    current_issue_url: Optional[str] = None
    status: Optional[str] = None
    status_category: Optional[str] = None
    http_status: Optional[int] = None
    retry_after: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class JiraIssueSearchOutcome(str, Enum):
    """Possible outcomes of searching Jira issues by a delivery marker."""

    SUCCESS = "success"
    RETRYABLE_FAILURE = "retryable_failure"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class JiraIssueSearchMatch:
    """A Jira issue found through a delivery-marker search."""

    issue_id: str
    issue_key: str
    issue_url: str


@dataclass(frozen=True)
class JiraIssueSearchResult:
    """Immutable result of searching Jira issues by a delivery marker."""

    outcome: JiraIssueSearchOutcome
    matches: Tuple[JiraIssueSearchMatch, ...] = ()
    http_status: Optional[int] = None
    retry_after: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
