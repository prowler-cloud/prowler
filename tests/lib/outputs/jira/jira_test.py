import base64
import hashlib
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import List, Optional
from unittest.mock import MagicMock, PropertyMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from freezegun import freeze_time

from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraBasicAuthError,
    JiraCreateIssueError,
    JiraGetAccessTokenError,
    JiraGetAvailableIssueTypesError,
    JiraGetCloudIDError,
    JiraGetProjectsError,
    JiraGetProjectsResponseError,
    JiraNoProjectsError,
    JiraRefreshTokenError,
    JiraRefreshTokenResponseError,
    JiraRequiredCustomFieldsError,
    JiraTestConnectionError,
)
from prowler.lib.outputs.jira.jira import Jira, MarkdownToADFConverter
from prowler.lib.outputs.jira.models import (
    JiraCreationOutcome,
    JiraCreationResult,
    JiraIssueLookupOutcome,
    JiraIssueReference,
    JiraIssueSearchMatch,
    JiraIssueSearchOutcome,
    JiraIssueSearchResult,
    JiraIssueStatusResult,
)

TEST_DATETIME = "2023-01-01T12:01:01+00:00"


class TestMarkdownToADFConverter:
    def setup_method(self):
        self.converter = MarkdownToADFConverter()

    def test_inline_code_nested_in_strong_has_only_code_mark(self):
        result = self.converter.convert("**before `code` after**")

        assert result[0]["content"] == [
            {"type": "text", "text": "before ", "marks": [{"type": "strong"}]},
            {"type": "text", "text": "code", "marks": [{"type": "code"}]},
            {"type": "text", "text": " after", "marks": [{"type": "strong"}]},
        ]

    def test_inline_code_nested_in_emphasis_has_only_code_mark(self):
        result = self.converter.convert("*before `code` after*")

        assert result[0]["content"] == [
            {"type": "text", "text": "before ", "marks": [{"type": "em"}]},
            {"type": "text", "text": "code", "marks": [{"type": "code"}]},
            {"type": "text", "text": " after", "marks": [{"type": "em"}]},
        ]

    def test_inline_code_in_link_preserves_link_and_code_marks(self):
        result = self.converter.convert("[`code`](https://example.com)")

        assert result[0]["content"][0]["marks"] == [
            {"type": "link", "attrs": {"href": "https://example.com"}},
            {"type": "code"},
        ]

    def test_inline_code_in_emphasized_link_preserves_link_and_code_marks(self):
        result = self.converter.convert("*[`code`](https://example.com)*")

        assert result[0]["content"][0]["marks"] == [
            {"type": "link", "attrs": {"href": "https://example.com"}},
            {"type": "code"},
        ]

    def test_standalone_inline_code_has_code_mark(self):
        result = self.converter.convert("`code`")

        assert result[0]["content"][0]["marks"] == [{"type": "code"}]


@pytest.mark.parametrize("missing_field", ["issue_key", "issue_id", "issue_url"])
def test_confirmed_creation_requires_complete_identity(missing_field):
    identity = {
        "issue_key": "SEC-1",
        "issue_id": "10001",
        "issue_url": "https://example.atlassian.net/browse/SEC-1",
    }
    identity[missing_field] = None

    with pytest.raises(ValueError, match="requires an issue key, ID, and URL"):
        JiraCreationResult(JiraCreationOutcome.CONFIRMED_SUCCESS, **identity)


@pytest.mark.parametrize(
    ("instance", "field"),
    [
        (JiraCreationResult(JiraCreationOutcome.UNCERTAIN), "error_code"),
        (JiraIssueReference("10001", "SEC-1"), "issue_key"),
        (
            JiraIssueStatusResult(
                JiraIssueReference("10001", "SEC-1"), JiraIssueLookupOutcome.OPEN
            ),
            "status",
        ),
        (JiraIssueSearchMatch("10001", "SEC-1", "https://example"), "issue_key"),
        (JiraIssueSearchResult(JiraIssueSearchOutcome.SUCCESS), "matches"),
    ],
)
def test_jira_result_models_are_immutable(instance, field):
    with pytest.raises(FrozenInstanceError):
        setattr(instance, field, None)


@pytest.mark.parametrize(
    ("enum", "values"),
    [
        (
            JiraCreationOutcome,
            {
                "confirmed_success",
                "confirmed_rejection",
                "retryable_failure",
                "uncertain",
            },
        ),
        (
            JiraIssueLookupOutcome,
            {"open", "done", "moved", "missing", "forbidden", "unknown"},
        ),
        (JiraIssueSearchOutcome, {"success", "retryable_failure", "unknown"}),
    ],
)
def test_jira_outcome_values_are_stable(enum, values):
    assert {outcome.value for outcome in enum} == values


class TestJiraIntegration:
    @pytest.fixture(autouse=True)
    @patch.object(Jira, "get_auth", return_value=None)
    def setup(self, mock_get_auth, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "test_authorization_code")

        # To disable vulture
        mock_get_auth = mock_get_auth

        self.redirect_uri = "https://example.com/callback"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.state_param = "unique_state_value"

        self.jira_integration = Jira(
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

    @pytest.fixture(autouse=True)
    @patch.object(Jira, "get_basic_auth", return_value=None)
    def setup_basic_auth(self, mock_get_basic_auth):
        # To disable vulture
        mock_get_basic_auth = mock_get_basic_auth

        self.user_mail = "test_user_mail"
        self.api_token = "test_api_token"
        self.domain = "test-domain"

        self.jira_integration_basic_auth = Jira(
            user_mail=self.user_mail,
            api_token=self.api_token,
            domain=self.domain,
        )

    @pytest.fixture
    def jira_response(self):
        def build(status_code=200, payload=None, headers=None, json_error=None):
            response = MagicMock(status_code=status_code, headers=headers or {})
            if json_error:
                response.json.side_effect = json_error
            else:
                response.json.return_value = payload
            return response

        return build

    @pytest.fixture
    def jira_issue(self):
        def build(issue_id, key, status=None, category=None):
            status_data = None
            if status is not None:
                status_data = {"name": status, "statusCategory": {"key": category}}
            return {"id": issue_id, "key": key, "fields": {"status": status_data}}

        return build

    @pytest.fixture
    def oauth_post(self):
        with (
            patch.object(Jira, "get_access_token", return_value="token"),
            patch.object(
                Jira, "cloud_id", new_callable=PropertyMock, return_value="cloud"
            ),
            patch("prowler.lib.outputs.jira.jira.requests.post") as post,
        ):
            yield post

    @pytest.fixture
    def send_finding_post(self, oauth_post):
        self.jira_integration._site_url = "https://example.atlassian.net"
        with (
            patch.object(Jira, "get_projects", return_value={"TEST": {}}) as projects,
            patch.object(
                Jira, "get_available_issue_types", return_value=["Bug"]
            ) as issue_types,
        ):
            yield SimpleNamespace(
                post=oauth_post, projects=projects, issue_types=issue_types
            )

    @staticmethod
    def _collect_text_from_cell(cell: dict) -> str:
        pieces: List[str] = []

        def walk(node: dict) -> None:
            node_type = node.get("type")
            if node_type == "text":
                pieces.append(node.get("text", ""))
            elif node_type == "hardBreak":
                pieces.append(" ")
            else:
                for child in node.get("content", []):
                    walk(child)
                if node_type in {"paragraph", "listItem"}:
                    pieces.append(" ")

        for child in cell.get("content", []):
            walk(child)

        flattened = "".join(pieces)
        return " ".join(flattened.split())

    @staticmethod
    def _find_link_mark(nodes: List[dict]) -> Optional[dict]:
        for node in nodes:
            if node.get("type") == "text":
                for mark in node.get("marks", []):
                    if mark.get("type") == "link":
                        return mark
            found = TestJiraIntegration._find_link_mark(node.get("content", []))
            if found:
                return found
        return None

    @staticmethod
    def _find_link_mark_by_href(nodes: List[dict], href: str) -> Optional[dict]:
        for node in nodes:
            if node.get("type") == "text":
                for mark in node.get("marks", []):
                    if (
                        mark.get("type") == "link"
                        and mark.get("attrs", {}).get("href") == href
                    ):
                        return mark
            found = TestJiraIntegration._find_link_mark_by_href(
                node.get("content", []), href
            )
            if found:
                return found
        return None

    @staticmethod
    def _collect_link_texts_by_href(nodes: List[dict], href: str) -> List[str]:
        link_texts: List[str] = []

        for node in nodes:
            if node.get("type") == "text" and any(
                mark.get("type") == "link" and mark.get("attrs", {}).get("href") == href
                for mark in node.get("marks", [])
            ):
                link_texts.append(node.get("text", ""))
            link_texts.extend(
                TestJiraIntegration._collect_link_texts_by_href(
                    node.get("content", []), href
                )
            )

        return link_texts

    @staticmethod
    def _find_table_row(rows: List[dict], header: str) -> dict:
        for row in rows:
            header_cell = row.get("content", [])[0]
            header_text = TestJiraIntegration._collect_text_from_cell(header_cell)
            if header_text == header:
                return row
        raise AssertionError(f"Row with header '{header}' not found")

    @patch.object(Jira, "get_auth", return_value=None)
    def test_auth_code_url(self, mock_get_auth):
        """Test to verify the authorization URL generation with correct query parameters"""

        # To disable vulture
        mock_get_auth = mock_get_auth

        generated_url = self.jira_integration.auth_code_url()

        expected_url = "https://auth.atlassian.com/authorize"

        parsed_url = urlparse(generated_url)
        query_params = parse_qs(parsed_url.query)

        assert (
            parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
            == expected_url
        )

        assert query_params["audience"][0] == "api.atlassian.com"
        assert query_params["client_id"][0] == self.client_id
        assert (
            query_params["scope"][0] == "read:jira-user read:jira-work write:jira-work"
        )
        assert query_params["redirect_uri"][0] == self.redirect_uri
        assert query_params["state"][0] is not None
        assert query_params["response_type"][0] == "code"
        assert query_params["prompt"][0] == "consent"

    @patch.object(Jira, "get_cloud_id", return_value="test_cloud_id")
    def test_get_auth_successful_basic_auth(self, mock_get_cloud_id):
        """Test successful token retrieval in get_basic_auth."""
        # To disable vulture
        mock_get_cloud_id = mock_get_cloud_id

        self.jira_integration_basic_auth.get_basic_auth()

        user_string = "test_user_mail:test_api_token"
        user_string_base64 = base64.b64encode(user_string.encode("utf-8")).decode(
            "utf-8"
        )

        assert self.jira_integration_basic_auth._access_token == user_string_base64
        assert self.jira_integration_basic_auth._cloud_id == "test_cloud_id"

    @patch.object(Jira, "get_cloud_id", side_effect=Exception("Connection error"))
    def test_get_auth_error_basic_auth(self, mock_get_cloud_id):
        """Test successful token retrieval in get_basic_auth."""
        # To disable vulture
        mock_get_cloud_id = mock_get_cloud_id

        with pytest.raises(JiraBasicAuthError):
            self.jira_integration_basic_auth.get_basic_auth()

    @freeze_time(TEST_DATETIME)
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    @patch.object(Jira, "get_cloud_id", return_value="test_cloud_id")
    def test_get_auth_successful(self, mock_get_cloud_id, mock_post):
        """Test successful token retrieval in get_auth."""
        # To disable vulture
        mock_get_cloud_id = mock_get_cloud_id

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        self.jira_integration.get_auth("test_auth_code")

        assert self.jira_integration._access_token == "test_access_token"
        assert self.jira_integration._refresh_token == "test_refresh_token"
        assert (
            self.jira_integration._expiration_date
            == (datetime.now() + timedelta(seconds=3600)).isoformat()
        )
        assert self.jira_integration._cloud_id == "test_cloud_id"

    @patch(
        "prowler.lib.outputs.jira.jira.requests.post",
        side_effect=Exception("Connection error"),
    )
    def test_get_auth_connection_error(self, mock_post):
        """Test get_auth raises JiraAuthenticationError on connection failure."""
        # To disable vulture
        mock_post = mock_post

        with pytest.raises(JiraAuthenticationError):
            self.jira_integration.get_auth("test_auth_code")

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_successful(self, mock_get):
        """Test successful retrieval of cloud ID."""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "test_cloud_id"}]
        mock_get.return_value = mock_response

        cloud_id = self.jira_integration.get_cloud_id("test_access_token")

        assert cloud_id == "test_cloud_id"

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_no_resources(self, mock_get):
        """Test get_cloud_id raises JiraGetCloudIDNoResourcesError when no resources are found, later JiraGetCloudIDError will be raised."""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetCloudIDError):
            self.jira_integration.get_cloud_id("test_access_token")

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_response_error(self, mock_get):
        """Test get_cloud_id raises JiraGetCloudIDResponseError when response code is not 200, later JiraGetCloudIDError will be raised."""

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Not Found"}
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetCloudIDError):
            self.jira_integration.get_cloud_id("test_access_token")

    @patch(
        "prowler.lib.outputs.jira.jira.requests.get",
        side_effect=Exception("Connection error"),
    )
    def test_get_cloud_id_unexpected_error(self, mock_get):
        """Test get_cloud_id raises JiraGetCloudIDError on an unexpected exception."""
        # To disable vulture
        mock_get = mock_get

        with pytest.raises(JiraGetCloudIDError):
            self.jira_integration.get_cloud_id("test_access_token")

    @patch.object(Jira, "refresh_access_token", return_value="new_access_token")
    def test_get_access_token_refresh(self, mock_refresh_access_token):
        """Test get_access_token refreshes token when expired."""

        self.jira_integration.auth_expiration = 0
        access_token = self.jira_integration.get_access_token()

        assert access_token == "new_access_token"
        mock_refresh_access_token.assert_called_once()

    @freeze_time(TEST_DATETIME)
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    @patch.object(Jira, "get_cloud_id", return_value="test_cloud_id")
    def test_get_access_token_valid_token(self, mock_get_cloud_id, mock_post):
        """Test successful token retrieval in get_auth."""
        # To disable vulture
        mock_get_cloud_id = mock_get_cloud_id

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "valid_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        self.jira_integration.get_auth("test_auth_code")

        access_token = self.jira_integration.get_access_token()
        assert access_token == "valid_access_token"

    @patch.object(Jira, "refresh_access_token", side_effect=JiraRefreshTokenError)
    def test_get_access_token_refresh_error(self, mock_refresh_access_token):
        """Test get_access_token raises JiraRefreshTokenError on token refresh failure."""

        # To disable vulture
        mock_refresh_access_token = mock_refresh_access_token

        self.jira_integration.auth_expiration = (
            datetime.now() + timedelta(seconds=0)
        ).isoformat()

        with pytest.raises(JiraRefreshTokenError):
            self.jira_integration.get_access_token()

    @freeze_time(TEST_DATETIME)
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_refresh_access_token_successful(self, mock_post):
        """Test successful access token refresh in refresh_access_token."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        expires_in_value = 3600
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": expires_in_value,
        }
        mock_post.return_value = mock_response

        new_access_token = self.jira_integration.refresh_access_token()

        assert new_access_token == "new_access_token"
        assert self.jira_integration._access_token == "new_access_token"
        assert self.jira_integration._refresh_token == "new_refresh_token"
        assert (
            self.jira_integration._expiration_date
            == (datetime.now() + timedelta(seconds=expires_in_value)).isoformat()
        )

    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_refresh_access_token_response_error(self, mock_post):
        """Test refresh_access_token raises JiraRefreshTokenResponseError when response code is not 200, later JiraRefreshTokenError will be raised."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_request"}
        mock_post.return_value = mock_response

        with pytest.raises(JiraRefreshTokenError):
            self.jira_integration.refresh_access_token()

    @patch(
        "prowler.lib.outputs.jira.jira.requests.post",
        side_effect=Exception("Connection error"),
    )
    def test_refresh_access_token_unexpected_error(self, mock_post):
        """Test refresh_access_token raises JiraRefreshTokenError on unexpected exception."""
        # To disable vulture
        mock_post = mock_post

        with pytest.raises(JiraRefreshTokenError):
            self.jira_integration.refresh_access_token()

    @patch("prowler.lib.outputs.jira.jira.requests.post")
    @patch.object(Jira, "get_cloud_id", return_value="test_cloud_id")
    def test_get_auth_sends_timeout(self, mock_get_cloud_id, mock_post):
        """get_auth must pass a request timeout to avoid hanging on an unresponsive Jira."""
        # To disable vulture
        mock_get_cloud_id = mock_get_cloud_id

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        self.jira_integration.get_auth("test_auth_code")

        assert mock_post.call_args.kwargs["timeout"] == Jira.REQUEST_TIMEOUT

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_sends_timeout(self, mock_get):
        """get_cloud_id (OAuth path) must pass a request timeout."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "test_cloud_id"}]
        mock_get.return_value = mock_response

        self.jira_integration.get_cloud_id("test_access_token")

        assert mock_get.call_args.kwargs["timeout"] == Jira.REQUEST_TIMEOUT

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_basic_auth_sends_timeout(self, mock_get):
        """get_cloud_id (basic-auth tenant_info path) must pass a request timeout."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cloudId": "test_cloud_id"}
        mock_get.return_value = mock_response

        self.jira_integration_basic_auth.get_cloud_id(domain=self.domain)

        assert mock_get.call_args.kwargs["timeout"] == Jira.REQUEST_TIMEOUT

    @pytest.mark.parametrize(
        "domain",
        (
            "169.254.169.254#",
            "internal/service",
            "internal?target",
            "internal\\target",
            "internal:8000",
            "user@internal",
        ),
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_basic_auth_rejects_invalid_domain(self, mock_get, domain):
        with pytest.raises(JiraGetCloudIDError):
            self.jira_integration_basic_auth.get_cloud_id(domain=domain)

        mock_get.assert_not_called()

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_basic_auth_disables_redirects(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cloudId": "test_cloud_id"}
        mock_get.return_value = mock_response

        self.jira_integration_basic_auth.get_cloud_id(domain=self.domain)

        assert mock_get.call_args.kwargs["allow_redirects"] is False

    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_refresh_access_token_sends_timeout(self, mock_post):
        """refresh_access_token must pass a request timeout."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        self.jira_integration.refresh_access_token()

        assert mock_post.call_args.kwargs["timeout"] == Jira.REQUEST_TIMEOUT

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_sends_timeout(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """get_projects must pass a request timeout."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"key": "PROJ1", "name": "Project One"}]
        mock_get.return_value = mock_response

        self.jira_integration.get_projects()

        assert mock_get.call_args.kwargs["timeout"] == Jira.REQUEST_TIMEOUT

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(
        Jira,
        "get_projects",
        return_value={"PROJ1": "Project One", "PROJ2": "Project Two"},
    )
    @patch.object(
        Jira,
        "get_available_issue_types",
        side_effect=lambda pk: ["Task", "Bug"] if pk == "PROJ1" else ["Story"],
    )
    def test_test_connection_successful(
        self, mock_get_issue_types, mock_get_projects, mock_get_auth
    ):
        """Test that a successful connection returns an active Connection object with projects."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth
        mock_get_issue_types = mock_get_issue_types

        connection = Jira.test_connection(
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        assert connection.is_connected
        assert connection.error is None
        assert connection.projects == {"PROJ1": "Project One", "PROJ2": "Project Two"}
        assert connection.issue_types == {
            "PROJ1": ["Task", "Bug"],
            "PROJ2": ["Story"],
        }

    @patch.object(Jira, "get_basic_auth", return_value=None)
    @patch.object(
        Jira,
        "get_projects",
        return_value={"PROJ1": "Project One", "PROJ2": "Project Two"},
    )
    @patch.object(
        Jira,
        "get_available_issue_types",
        side_effect=lambda pk: ["Task", "Bug"] if pk == "PROJ1" else ["Story"],
    )
    def test_test_connection_successful_basic_auth(
        self, mock_get_issue_types, mock_get_projects, mock_get_basic_auth
    ):
        """Test that a successful connection returns an active Connection object with projects."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_basic_auth = mock_get_basic_auth
        mock_get_issue_types = mock_get_issue_types

        connection = Jira.test_connection(
            user_mail=self.user_mail,
            api_token=self.api_token,
            domain=self.domain,
        )

        assert connection.is_connected
        assert connection.error is None
        assert connection.projects == {"PROJ1": "Project One", "PROJ2": "Project Two"}
        assert connection.issue_types == {
            "PROJ1": ["Task", "Bug"],
            "PROJ2": ["Story"],
        }

    @patch.object(
        Jira,
        "get_auth",
        side_effect=JiraAuthenticationError("Failed to authenticate with Jira"),
    )
    def test_test_connection_failed(self, mock_get_auth):
        """Test that a failed connection raises JiraAuthenticationError."""
        # To disable vulture
        mock_get_auth = mock_get_auth

        with pytest.raises(JiraAuthenticationError):
            Jira.test_connection(
                redirect_uri=self.redirect_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

    @patch.object(
        Jira,
        "get_basic_auth",
        side_effect=JiraBasicAuthError("Failed to authenticate with Jira"),
    )
    def test_test_connection_failed_basic_auth(self, mock_get_basic_auth):
        """Test that a failed connection raises JiraBasicAuthError."""
        # To disable vulture
        mock_get_basic_auth = mock_get_basic_auth

        with pytest.raises(JiraBasicAuthError):
            Jira.test_connection(
                user_mail=self.user_mail,
                api_token=self.api_token,
                domain=self.domain,
            )

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(
        Jira, "get_projects", side_effect=JiraNoProjectsError("No projects found")
    )
    def test_test_connection_no_projects_found(self, mock_get_projects, mock_get_auth):
        """Test that test_connection raises JiraNoProjectsError when no projects are found."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth

        with pytest.raises(JiraNoProjectsError):
            Jira.test_connection(
                redirect_uri=self.redirect_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(
        Jira,
        "get_projects",
        side_effect=JiraGetProjectsResponseError("Projects request failed"),
    )
    def test_test_connection_projects_request_error(
        self, mock_get_projects, mock_get_auth
    ):
        """Test that test_connection raises JiraGetProjectsResponseError when projects request fails."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth

        with pytest.raises(JiraGetProjectsResponseError):
            Jira.test_connection(
                redirect_uri=self.redirect_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(
        Jira, "get_projects", side_effect=JiraNoProjectsError("No projects found")
    )
    def test_test_connection_no_projects_found_no_exception(
        self, mock_get_projects, mock_get_auth
    ):
        """Test that test_connection returns error connection object when no projects found and raise_on_exception=False."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth

        connection = Jira.test_connection(
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            raise_on_exception=False,
        )

        assert not connection.is_connected
        assert isinstance(connection.error, JiraNoProjectsError)

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(
        Jira,
        "get_projects",
        side_effect=JiraGetProjectsResponseError("Projects request failed"),
    )
    def test_test_connection_projects_request_error_no_exception(
        self, mock_get_projects, mock_get_auth
    ):
        """Test that test_connection returns error connection object when projects request fails and raise_on_exception=False."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth

        connection = Jira.test_connection(
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            raise_on_exception=False,
        )

        assert not connection.is_connected
        assert isinstance(connection.error, JiraGetProjectsResponseError)

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(Jira, "get_projects", side_effect=Exception("Unexpected error"))
    def test_test_connection_unexpected_error(self, mock_get_projects, mock_get_auth):
        """Test that test_connection raises JiraTestConnectionError on unexpected exceptions."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth

        with pytest.raises(JiraTestConnectionError):
            Jira.test_connection(
                redirect_uri=self.redirect_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_successful(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test successful retrieval of projects from Jira."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"key": "PROJ1", "name": "Project One"},
            {"key": "PROJ2", "name": "Project Two"},
        ]
        mock_get.return_value = mock_response

        projects = self.jira_integration.get_projects()
        expected_projects = {"PROJ1": "Project One", "PROJ2": "Project Two"}
        assert projects == expected_projects

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_no_projects_found(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_projects raises JiraNoProjectsError when no projects are found."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        with pytest.raises(JiraNoProjectsError):
            self.jira_integration.get_projects()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_response_error(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_projects raises JiraGetProjectsResponseError on non-200 response."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Not Found"}
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetProjectsError):
            self.jira_integration.get_projects()

    @patch.object(
        Jira,
        "get_access_token",
        side_effect=JiraRefreshTokenError("Failed to refresh the access token"),
    )
    def test_get_projects_refresh_token_error(self, mock_get_access_token):
        """Test that get_projects raises JiraRefreshTokenError when refreshing the token fails."""
        # To disable vulture
        mock_get_access_token = mock_get_access_token

        with pytest.raises(JiraRefreshTokenError):
            self.jira_integration.get_projects()

    @pytest.mark.parametrize(
        ("method_name", "args", "error"),
        [
            ("get_projects", (), JiraGetProjectsError),
            ("get_available_issue_types", ("TEST",), JiraGetAvailableIssueTypesError),
        ],
    )
    @patch.object(Jira, "get_access_token", return_value=None)
    def test_catalog_methods_raise_without_access_token(
        self, mock_get_access_token, method_name, args, error
    ):
        with pytest.raises(error):
            getattr(self.jira_integration, method_name)(*args)

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_available_issue_types_successful(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test successful retrieval of issue types for a project."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "projects": [
                {
                    "issuetypes": [
                        {"name": "Bug"},
                        {"name": "Task"},
                        {"name": "Story"},
                    ]
                }
            ]
        }
        mock_get.return_value = mock_response

        issue_types = self.jira_integration.get_available_issue_types(
            project_key="TEST"
        )

        expected_issue_types = ["Bug", "Task", "Story"]
        assert issue_types == expected_issue_types

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_available_issue_types_no_projects_found(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_available_issue_types raises JiraNoProjectsError when no projects are found, later JiraGetAvailableIssueTypesError is raised."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"projects": []}
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetAvailableIssueTypesError):
            self.jira_integration.get_available_issue_types(project_key="TEST")

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_available_issue_types_response_error(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_available_issue_types raises JiraGetAvailableIssueTypesResponseError on non-200 response, JiraGetAvailableIssueTypesError will be raised later"""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Not Found"}
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetAvailableIssueTypesError):
            self.jira_integration.get_available_issue_types(project_key="TEST")

    @patch.object(
        Jira,
        "get_access_token",
        side_effect=JiraRefreshTokenError("Failed to refresh the access token"),
    )
    def test_get_available_issue_types_refresh_token_error(self, mock_get_access_token):
        """Test that get_available_issue_types raises JiraRefreshTokenError when refreshing the token fails."""
        # To disable vulture
        mock_get_access_token = mock_get_access_token

        with pytest.raises(JiraRefreshTokenError):
            self.jira_integration.get_available_issue_types(project_key="TEST")

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "get_available_issue_types", return_value=["Bug", "Task", "Story"]
    )
    @patch.object(Jira, "get_projects", return_value={"TEST-1": "Test Project"})
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_findings_successful(
        self,
        mock_post,
        mock_get_available_issue_types,
        mock_get_projects,
        mock_get_access_token,
    ):
        """Test successful sending of findings to Jira."""
        # To disable vulture
        mock_get_available_issue_types = mock_get_available_issue_types
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "12345", "key": "TEST-1"}
        mock_post.return_value = mock_response

        finding = MagicMock()
        finding.status.value = "FAIL"
        finding.status_extended = "status_extended"
        finding.metadata.Severity.value = "HIGH"
        finding.metadata.CheckID = "CHECK-1"
        finding.metadata.CheckTitle = "Check Title"
        finding.resource_uid = "resource-1"
        finding.resource_name = "resource_name"
        finding.metadata.Provider = "aws"
        finding.region = "region"
        finding.metadata.Risk = "risk"
        finding.metadata.Remediation.Recommendation.Text = "remediation_text"
        finding.metadata.Remediation.Recommendation.Url = "remediation_url"
        finding.metadata.Remediation.Code.NativeIaC = (
            'resource "aws_s3_bucket" "example" { bucket = "my-bucket" }'
        )
        finding.metadata.Remediation.Code.Terraform = (
            "terraform apply -target=aws_s3_bucket.example"
        )
        finding.metadata.Remediation.Code.CLI = (
            "aws s3api create-bucket --bucket my-bucket --region us-east-1"
        )
        finding.metadata.Remediation.Code.Other = (
            "Manual configuration required in AWS Console"
        )
        finding.resource_tags = {"Environment": "Production", "Owner": "SecurityTeam"}
        finding.compliance = {"CIS": ["2.1.1", "2.1.2"], "NIST": ["AC-3", "AC-6"]}

        self.jira_integration.cloud_id = "valid_cloud_id"
        self.jira_integration._site_url = "https://example.atlassian.net"

        self.jira_integration.send_findings(
            findings=[finding],
            project_key="TEST-1",
            issue_type="Bug",
            issue_labels=["scan-mocked", "whatever"],
            finding_url="https://prowler-cloud-link/findings/12345",
            tenant_info="Tenant Info",
        )

        mock_post.assert_called_once()

        call_args = mock_post.call_args

        expected_url = (
            "https://api.atlassian.com/ex/jira/valid_cloud_id/rest/api/3/issue"
        )
        expected_headers = {
            "Authorization": "Bearer valid_access_token",
            "Content-Type": "application/json",
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }

        assert call_args[0][0] == expected_url
        assert call_args.kwargs["headers"] == expected_headers

        payload = call_args.kwargs["json"]
        assert payload["fields"]["project"]["key"] == "TEST-1"
        assert payload["fields"]["summary"] == "[Prowler] HIGH - CHECK-1 - resource-1"
        assert payload["fields"]["issuetype"]["name"] == "Bug"
        assert payload["fields"]["description"]["type"] == "doc"
        assert payload["fields"]["labels"] == ["scan-mocked", "whatever"]

        description_content = payload["fields"]["description"]["content"]

        intro_paragraph = description_content[0]
        assert intro_paragraph["type"] == "paragraph"
        intro_text = intro_paragraph["content"][0]
        assert intro_text["type"] == "text"
        assert intro_text["text"] == "Prowler has discovered the following finding:"
        assert all(
            self._collect_text_from_cell({"content": node.get("content", [])})
            != "Summary"
            for node in description_content
            if node.get("type") == "heading"
        )

        table = description_content[1]
        assert table["type"] == "table"

        table_rows = table["content"]
        row_entries = {}
        recommendation_cell = None

        for row in table_rows:
            if row["type"] != "tableRow":
                continue

            cells = row["content"]
            if len(cells) != 2:
                continue

            key_text = self._collect_text_from_cell(cells[0])
            value_text = self._collect_text_from_cell(cells[1])

            if key_text:
                row_entries[key_text] = value_text
                if key_text == "Recommendation":
                    recommendation_cell = cells[1]

        expected_keys = [
            "Check Id",
            "Check Title",
            "Severity",
            "Status",
            "Status Extended",
            "Provider",
            "Region",
            "Resource UID",
            "Resource Name",
            "Risk",
            "Resource Tags",
            "Compliance",
            "Recommendation",
            "Remediation Native IaC",
            "Remediation Terraform",
            "Remediation CLI",
            "Remediation Other",
            "Finding URL",
            "Tenant Info",
        ]

        for expected_key in expected_keys:
            assert expected_key in row_entries, f"Missing row key: {expected_key}"

        row_dict = row_entries

        assert recommendation_cell is not None
        link_mark = self._find_link_mark(recommendation_cell.get("content", []))
        assert link_mark is not None
        assert link_mark.get("attrs", {}).get("href") == "remediation_url"
        assert row_dict["Check Id"] == "CHECK-1"
        assert row_dict["Check Title"] == "Check Title"
        assert row_dict["Status"] == "FAIL"
        assert row_dict["Severity"] == "HIGH"
        assert row_dict["Resource UID"] == "resource-1"
        assert row_dict["Resource Name"] == "resource_name"
        assert row_dict["Provider"] == "aws"
        assert row_dict["Region"] == "region"
        assert row_dict["Risk"] == "risk"
        assert "remediation_text" in row_dict["Recommendation"]
        assert "remediation_url" in row_dict["Recommendation"]
        assert (
            row_dict["Remediation Native IaC"]
            == 'resource "aws_s3_bucket" "example" { bucket = "my-bucket" }'
        )
        assert (
            row_dict["Remediation Terraform"]
            == "terraform apply -target=aws_s3_bucket.example"
        )
        assert (
            row_dict["Remediation CLI"]
            == "aws s3api create-bucket --bucket my-bucket --region us-east-1"
        )
        assert (
            row_dict["Remediation Other"]
            == "Manual configuration required in AWS Console"
        )
        assert "Environment=Production" in row_dict["Resource Tags"]
        assert "Owner=SecurityTeam" in row_dict["Resource Tags"]
        assert "CIS: 2.1.1, 2.1.2" in row_dict["Compliance"]
        assert "NIST: AC-3, AC-6" in row_dict["Compliance"]
        assert "https://prowler-cloud-link/findings/12345" in row_dict["Finding URL"]
        assert "Tenant Info" in row_dict["Tenant Info"]

    def test_get_adf_description_renders_markdown(self):
        status_extended_md = "Finding uses **bold** text and `code` snippets."
        risk_md = "High risk:\n- Item one\n- Item two"
        recommendation_md = "Apply fixes:\n- Step one\n- Step two"
        recommendation_url = "https://example.com/fix"

        adf_description = self.jira_integration.get_adf_description(
            check_id="CHECK-1",
            check_title="Sample check",
            severity="HIGH",
            severity_color="#FF0000",
            status="FAIL",
            status_color="#00FF00",
            status_extended=status_extended_md,
            provider="aws",
            region="us-east-1",
            resource_uid="resource-1",
            resource_name="resource-name",
            risk=risk_md,
            recommendation_text=recommendation_md,
            recommendation_url=recommendation_url,
        )

        assert adf_description["type"] == "doc"
        table = adf_description["content"][1]
        assert table["type"] == "table"

        rows = {}
        for row in table["content"]:
            if row.get("type") != "tableRow":
                continue
            key_cell, value_cell = row["content"]
            key_text = self._collect_text_from_cell(key_cell)
            rows[key_text] = value_cell

        assert "Status Extended" in rows
        assert "Risk" in rows
        assert "Recommendation" in rows

        def walk_nodes(nodes: List[dict]):
            stack = list(nodes)
            while stack:
                current = stack.pop()
                yield current
                stack.extend(current.get("content", []))

        status_text = self._collect_text_from_cell(rows["Status Extended"])
        assert status_text == status_extended_md

        risk_nodes = list(walk_nodes(rows["Risk"].get("content", [])))
        assert any(node.get("type") == "bulletList" for node in risk_nodes)

        recommendation_cell = rows["Recommendation"]
        recommendation_nodes = list(walk_nodes(recommendation_cell.get("content", [])))
        assert any(node.get("type") == "bulletList" for node in recommendation_nodes)
        link_mark = self._find_link_mark(recommendation_cell.get("content", []))
        assert link_mark is not None
        assert link_mark.get("attrs", {}).get("href") == recommendation_url

    def test_get_adf_description_code_blocks_strip_fences(self):
        code_block_value = """```hcl\nresource \"aws_s3_bucket\" \"example\" {\n  bucket = \"my-bucket\"\n}\n```"""

        adf_description = self.jira_integration.get_adf_description(
            check_id="CHECK-1",
            check_title="Sample check",
            severity="HIGH",
            severity_color="#FF0000",
            status="FAIL",
            status_color="#00FF00",
            recommendation_text="",
            remediation_code_native_iac=code_block_value,
        )

        table = adf_description["content"][1]
        code_row = self._find_table_row(table["content"], "Remediation Native IaC")
        code_cell = code_row["content"][1]
        code_block = code_cell["content"][0]

        assert code_block["type"] == "codeBlock"
        assert code_block.get("attrs", {}).get("language") == "hcl"
        expected_text = (
            'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n}'
        )
        assert code_block["content"][0]["text"] == expected_text

    def test_get_adf_description_other_remediation_uses_markdown(self):
        other_value = "Use **bold** text"

        adf_description = self.jira_integration.get_adf_description(
            check_id="CHECK-1",
            check_title="Sample check",
            severity="HIGH",
            severity_color="#FF0000",
            status="FAIL",
            status_color="#00FF00",
            recommendation_text="",
            remediation_code_other=other_value,
        )

        table = adf_description["content"][1]
        other_row = self._find_table_row(table["content"], "Remediation Other")
        other_cell = other_row["content"][1]

        paragraph = other_cell["content"][0]
        assert paragraph["type"] == "paragraph"
        assert any(
            mark.get("type") == "strong"
            for node in paragraph.get("content", [])
            for mark in node.get("marks", [])
        )

    @staticmethod
    def _find_empty_text_nodes(node) -> List[str]:
        # ADF forbids empty text nodes; collect any to assert the document is valid.
        empties: List[str] = []

        def walk(current) -> None:
            if isinstance(current, dict):
                if current.get("type") == "text" and current.get("text", "") == "":
                    empties.append(current.get("text", ""))
                for value in current.values():
                    walk(value)
            elif isinstance(current, list):
                for item in current:
                    walk(item)

        walk(node)
        return empties

    def test_get_adf_description_empty_resource_name_has_no_empty_text_nodes(self):
        # A resource without a name (e.g. an AWS-managed IAM policy) used to emit an
        # empty ADF text node, making Jira reject the issue with 400 INVALID_INPUT.
        adf_description = self.jira_integration.get_adf_description(
            check_id="CHECK-1",
            check_title="Sample check",
            severity="CRITICAL",
            severity_color="#FF0000",
            status="FAIL",
            status_color="#FF0000",
            status_extended="Some status",
            provider="aws",
            region="eu-west-1",
            resource_uid="arn:aws:iam::aws:policy/AdministratorAccess",
            resource_name="",
            recommendation_text="",
        )

        assert self._find_empty_text_nodes(adf_description) == []

        table = adf_description["content"][1]
        resource_name_row = self._find_table_row(table["content"], "Resource Name")
        value_cell = resource_name_row["content"][1]
        assert self._collect_text_from_cell(value_cell) == "-"

    @pytest.mark.parametrize(
        "field, header",
        [
            ("check_id", "Check Id"),
            ("check_title", "Check Title"),
            ("status_extended", "Status Extended"),
            ("provider", "Provider"),
            ("region", "Region"),
            ("resource_uid", "Resource UID"),
            ("resource_name", "Resource Name"),
        ],
    )
    def test_get_adf_description_empty_plain_text_fields_render_placeholder(
        self, field, header
    ):
        base_kwargs = dict(
            check_id="CHECK-1",
            check_title="Sample check",
            severity="HIGH",
            severity_color="#FF0000",
            status="FAIL",
            status_color="#00FF00",
            status_extended="Some status",
            provider="aws",
            region="us-east-1",
            resource_uid="resource-1",
            resource_name="resource-name",
            recommendation_text="",
        )
        base_kwargs[field] = ""

        adf_description = self.jira_integration.get_adf_description(**base_kwargs)

        assert self._find_empty_text_nodes(adf_description) == []

        table = adf_description["content"][1]
        row = self._find_table_row(table["content"], header)
        value_cell = row["content"][1]
        assert self._collect_text_from_cell(value_cell) == "-"

    def test_get_grouped_adf_description_uses_capped_finding_group_link_copy(self):
        finding_group_url = (
            "https://security.example.com/findings?"
            "filter%5Bcheck_id%5D=admincenter_users_admins_reduced_license_footprint&"
            "expandedCheckId=admincenter_users_admins_reduced_license_footprint"
        )
        finding_group_link_text = "View the remaining grouped findings."
        recommendation_url = (
            "https://hub.prowler.com/check/"
            "admincenter_users_admins_reduced_license_footprint"
        )
        adf_description = self.jira_integration.get_grouped_adf_description(
            check_id="admincenter_users_admins_reduced_license_footprint",
            check_title="Administrative user has no license or an allowed license",
            check_description="Administrative users are assigned productivity licenses.",
            severity="HIGH",
            status="FAIL",
            provider="m365",
            service="exchange",
            affected_failing_resources=123,
            last_seen="Jul 09, 2026 11:38AM UTC",
            failing_for="< 1 day",
            grouped_resources=[
                {
                    "resource_name": "rich@prowler.com",
                    "resource_uid": "3f9a216b-b66b-4d5d-a812-2ad538732cfb",
                    "provider": "m365",
                    "service": "exchange",
                    "provider_account": "ProwlerPro.onmicrosoft.com",
                    "status": "FAIL",
                    "severity": "high",
                    "region": "global",
                    "last_seen": "Jul 09, 2026 11:38AM UTC",
                    "failing_for": "< 1 day",
                    "triage": "Open",
                }
            ],
            resources_total=123,
            resources_shown=100,
            finding_group_url=finding_group_url,
            finding_group_link_text=finding_group_link_text,
            risk="Productivity licenses on privileged identities create risk.",
            recommendation_text="Maintain dedicated admin accounts.",
            recommendation_url=recommendation_url,
        )

        assert adf_description["type"] == "doc"
        assert self._find_empty_text_nodes(adf_description) == []

        main_table = adf_description["content"][1]
        main_rows = {}
        for row in main_table["content"]:
            key_cell, value_cell = row["content"]
            main_rows[self._collect_text_from_cell(key_cell)] = (
                self._collect_text_from_cell(value_cell)
            )

        assert (
            main_rows["Check Id"]
            == "admincenter_users_admins_reduced_license_footprint"
        )
        assert main_rows["Service"] == "exchange"
        assert main_rows["Affected Failing Resources"] == "123"
        assert (
            main_rows["Risk"]
            == "Productivity licenses on privileged identities create risk."
        )
        assert main_rows["Recommendation"] == (
            "Maintain dedicated admin accounts. " + recommendation_url
        )
        assert "Finding Group Link" not in main_rows
        assert "Region" not in main_rows

        top_level_headings = [
            self._collect_text_from_cell({"content": node.get("content", [])})
            for node in adf_description["content"]
            if node.get("type") == "heading"
        ]
        assert "Risk" not in top_level_headings
        assert "Recommendation" not in top_level_headings
        assert "Summary" not in top_level_headings

        def text_marks(cell: dict) -> list[dict]:
            return cell["content"][0]["content"][0]["marks"]

        severity_marks = text_marks(
            self._find_table_row(main_table["content"], "Severity")["content"][1]
        )
        status_marks = text_marks(
            self._find_table_row(main_table["content"], "Status")["content"][1]
        )
        assert {
            "type": "backgroundColor",
            "attrs": {"color": "#FFA500"},
        } in severity_marks
        assert {"type": "textColor", "attrs": {"color": "#FF0000"}} in status_marks

        resource_table = next(
            node
            for node in adf_description["content"]
            if node.get("type") == "table"
            and self._collect_text_from_cell(node["content"][0]["content"][0])
            == "Resource"
        )
        resource_cells = resource_table["content"][1]["content"]
        assert {"type": "textColor", "attrs": {"color": "#FF0000"}} in text_marks(
            resource_cells[5]
        )
        assert {
            "type": "backgroundColor",
            "attrs": {"color": "#FFA500"},
        } in text_marks(resource_cells[6])

        document_text = self._collect_text_from_cell(
            {"content": adf_description["content"]}
        )
        assert (
            "Administrative users are assigned productivity licenses."
            not in document_text
        )
        assert "Affected failing resources" in document_text
        capped_link_copy = (
            f"Showing 100 of 123 Findings in this Jira issue. {finding_group_link_text}"
        )
        assert document_text.count(capped_link_copy) == 1
        assert "Finding Group Link" not in document_text
        assert recommendation_url in document_text
        recommendation_link_mark = self._find_link_mark_by_href(
            adf_description["content"], recommendation_url
        )
        assert recommendation_link_mark is not None
        link_mark = self._find_link_mark_by_href(
            adf_description["content"], finding_group_url
        )
        assert link_mark is not None
        assert link_mark["attrs"]["href"] == finding_group_url
        assert self._collect_link_texts_by_href(
            adf_description["content"], finding_group_url
        ) == [finding_group_link_text]
        assert (
            len(
                self._collect_link_texts_by_href(
                    adf_description["content"], finding_group_url
                )
            )
            == 1
        )
        assert "filter%5Bcheck_id%5D=" in link_mark["attrs"]["href"]
        assert "expandedCheckId=" in link_mark["attrs"]["href"]

    def test_get_grouped_adf_description_includes_link_when_not_capped(self):
        finding_group_url = (
            "https://security.example.com/findings?"
            "filter%5Bcheck_id%5D=s3_bucket_public_access&"
            "expandedCheckId=s3_bucket_public_access"
        )
        finding_group_link_text = "View this grouped finding."
        adf_description = self.jira_integration.get_grouped_adf_description(
            check_id="s3_bucket_public_access",
            check_title="S3 bucket public access",
            severity="HIGH",
            status="FAIL",
            provider="aws",
            service="s3",
            affected_failing_resources=1,
            grouped_resources=[
                {
                    "resource_name": "bucket-a",
                    "resource_uid": "arn:aws:s3:::bucket-a",
                    "provider": "aws",
                    "service": "s3",
                    "provider_account": "production (123456789012)",
                    "status": "FAIL",
                    "severity": "high",
                    "region": "us-east-1",
                    "last_seen": "Jul 09, 2026 11:38AM UTC",
                    "failing_for": "< 1 day",
                    "triage": "Open",
                }
            ],
            resources_total=1,
            resources_shown=1,
            finding_group_url=finding_group_url,
            finding_group_link_text=finding_group_link_text,
        )

        document_text = self._collect_text_from_cell(
            {"content": adf_description["content"]}
        )
        assert "Showing 1 of 1 Findings." not in document_text
        assert "remaining Findings" not in document_text
        assert document_text.count(finding_group_link_text) == 1
        assert "Finding Group Link" not in document_text
        main_table = adf_description["content"][1]
        main_row_headers = [
            self._collect_text_from_cell(row["content"][0])
            for row in main_table["content"]
        ]
        assert "Finding Group Link" not in main_row_headers
        link_mark = self._find_link_mark_by_href(
            adf_description["content"], finding_group_url
        )
        assert link_mark is not None
        assert link_mark["attrs"]["href"] == finding_group_url
        assert self._collect_link_texts_by_href(
            adf_description["content"], finding_group_url
        ) == [finding_group_link_text]
        assert (
            "filter%5Bcheck_id%5D=s3_bucket_public_access" in link_mark["attrs"]["href"]
        )
        assert "expandedCheckId=s3_bucket_public_access" in link_mark["attrs"]["href"]

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "get_available_issue_types", return_value=["Bug", "Task", "Story"]
    )
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_findings_invalid_issue_type(
        self, mock_post, mock_get_available_issue_types, mock_get_access_token
    ):
        """Test that send_findings raises JiraInvalidIssueTypeError if the issue type is invalid that will raise JiraCreateIssueError later."""
        # To disable vulture
        mock_get_available_issue_types = mock_get_available_issue_types
        mock_get_access_token = mock_get_access_token
        mock_post = mock_post
        mock_post = mock_post

        with pytest.raises(JiraCreateIssueError):
            self.jira_integration.send_findings(
                findings=[MagicMock()], project_key="TEST", issue_type="InvalidType"
            )

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "get_available_issue_types", return_value=["Bug", "Task", "Story"]
    )
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_findings_response_error(
        self, mock_post, mock_get_available_issue_types, mock_get_access_token
    ):
        """Test that send_findings raises JiraSendFindingsResponseError on non-201 response that will raise JiraCreateIssueError later."""
        # To disable vulture
        mock_get_available_issue_types = mock_get_available_issue_types
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Bad Request"}
        mock_post.return_value = mock_response

        finding = MagicMock()
        finding.status.value = "FAIL"
        finding.metadata.Severity.value = "HIGH"
        finding.metadata.CheckID = "CHECK-1"
        finding.resource_uid = "resource-1"

        with pytest.raises(JiraCreateIssueError):
            self.jira_integration.send_findings(
                findings=[finding], project_key="TEST", issue_type="Bug"
            )

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "get_available_issue_types", return_value=["Bug", "Task", "Story"]
    )
    @patch.object(Jira, "get_projects", return_value={"TEST-1": "Test Project"})
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_findings_custom_fields_required_error(
        self,
        mock_post,
        mock_get_projects,
        mock_get_available_issue_types,
        mock_get_access_token,
    ):
        """Test that send_findings raises JiraRequiredCustomFieldsError when custom fields are required."""
        # To disable vulture
        mock_get_available_issue_types = mock_get_available_issue_types
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "errorMessages": [],
            "errors": {
                "customfield_10148": "Team is required.",
                "customfield_10088": "Component is required.",
            },
        }
        mock_post.return_value = mock_response

        finding = MagicMock()
        finding.status.value = "FAIL"
        finding.status_extended = "status_extended"
        finding.metadata.Severity.value = "HIGH"
        finding.metadata.CheckID = "CHECK-1"
        finding.metadata.CheckTitle = "Check Title"
        finding.resource_uid = "resource-1"
        finding.resource_name = "resource_name"
        finding.metadata.Provider = "aws"
        finding.region = "region"
        finding.metadata.Risk = "risk"
        finding.metadata.Remediation.Recommendation.Text = "remediation_text"
        finding.metadata.Remediation.Recommendation.Url = "remediation_url"
        finding.metadata.Remediation.Code.NativeIaC = ""
        finding.metadata.Remediation.Code.Terraform = ""
        finding.metadata.Remediation.Code.CLI = ""
        finding.metadata.Remediation.Code.Other = ""
        finding.resource_tags = {}
        finding.compliance = {}

        self.jira_integration.cloud_id = "valid_cloud_id"

        with pytest.raises(JiraRequiredCustomFieldsError):
            self.jira_integration.send_findings(
                findings=[finding],
                project_key="TEST-1",
                issue_type="Bug",
                issue_labels=["scan-mocked", "whatever"],
                finding_url="https://prowler-cloud-link/findings/12345",
                tenant_info="Tenant Info",
            )

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "get_available_issue_types", return_value=["Bug", "Task", "Story"]
    )
    @patch.object(Jira, "get_projects", return_value={"TEST-1": "Test Project"})
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_findings_non_custom_field_400_error(
        self,
        mock_post,
        mock_get_projects,
        mock_get_available_issue_types,
        mock_get_access_token,
    ):
        """Test that send_findings raises JiraCreateIssueError for non-custom field 400 errors."""
        # To disable vulture
        mock_get_available_issue_types = mock_get_available_issue_types
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "errorMessages": [],
            "errors": {
                "summary": "Summary is required.",
                "description": "Description is required.",
            },
        }
        mock_post.return_value = mock_response

        finding = MagicMock()
        finding.status.value = "FAIL"
        finding.status_extended = "status_extended"
        finding.metadata.Severity.value = "HIGH"
        finding.metadata.CheckID = "CHECK-1"
        finding.metadata.CheckTitle = "Check Title"
        finding.resource_uid = "resource-1"
        finding.resource_name = "resource_name"
        finding.metadata.Provider = "aws"
        finding.region = "region"
        finding.metadata.Risk = "risk"
        finding.metadata.Remediation.Recommendation.Text = "remediation_text"
        finding.metadata.Remediation.Recommendation.Url = "remediation_url"
        finding.metadata.Remediation.Code.NativeIaC = ""
        finding.metadata.Remediation.Code.Terraform = ""
        finding.metadata.Remediation.Code.CLI = ""
        finding.metadata.Remediation.Code.Other = ""
        finding.resource_tags = {}
        finding.compliance = {}

        self.jira_integration.cloud_id = "valid_cloud_id"

        with pytest.raises(JiraCreateIssueError):
            self.jira_integration.send_findings(
                findings=[finding],
                project_key="TEST-1",
                issue_type="Bug",
                issue_labels=["scan-mocked", "whatever"],
                finding_url="https://prowler-cloud-link/findings/12345",
                tenant_info="Tenant Info",
            )

    @pytest.mark.parametrize(
        "status, expected_color",
        [
            ("FAIL", "#FF0000"),
            ("PASS", "#008000"),
            ("MUTED", "#FFA500"),
            ("MANUAL", "#FFFF00"),
        ],
    )
    def test_get_color_from_status(self, status, expected_color):
        """Test that get_color_from_status returns the correct color for a status."""
        assert self.jira_integration.get_color_from_status(status) == expected_color

    @pytest.mark.parametrize(
        "severity, expected_color",
        [
            ("critical", "#FF0000"),
            ("high", "#FFA500"),
            ("medium", "#FFFF00"),
            ("low", "#008000"),
            ("informational", "#0000FF"),
            ("unknown", "#000000"),
        ],
    )
    def test_get_severity_color(self, severity, expected_color):
        """Test that get_severity_color returns the correct color for a severity."""
        assert self.jira_integration.get_severity_color(severity) == expected_color

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_and_issue_types_successful(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test successful retrieval of metadata associated to projects from Jira."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        # Mock the projects response
        mock_projects_response = MagicMock()
        mock_projects_response.status_code = 200
        mock_projects_response.json.return_value = [
            {"key": "PROJ1", "name": "Project One"},
            {"key": "PROJ2", "name": "Project Two"},
        ]

        # Mock the issue types responses
        mock_issue_types_response_1 = MagicMock()
        mock_issue_types_response_1.status_code = 200
        mock_issue_types_response_1.json.return_value = {
            "projects": [
                {
                    "issuetypes": [
                        {"name": "Bug", "id": "1"},
                        {"name": "Task", "id": "2"},
                    ]
                }
            ]
        }

        mock_issue_types_response_2 = MagicMock()
        mock_issue_types_response_2.status_code = 200
        mock_issue_types_response_2.json.return_value = {
            "projects": [
                {
                    "issuetypes": [
                        {"name": "Story", "id": "3"},
                        {"name": "Epic", "id": "4"},
                    ]
                }
            ]
        }

        # Configure side_effect to return different responses for different calls
        mock_get.side_effect = [
            mock_projects_response,
            mock_issue_types_response_1,
            mock_issue_types_response_2,
        ]

        jira_metadata = self.jira_integration.get_metadata()

        expected_result = {
            "PROJ1": {
                "name": "Project One",
                "issue_types": ["Bug", "Task"],
            },
            "PROJ2": {
                "name": "Project Two",
                "issue_types": ["Story", "Epic"],
            },
        }

        assert jira_metadata == expected_result

        # Verify the correct number of calls were made
        assert mock_get.call_count == 3

        # Verify the URLs called
        calls = mock_get.call_args_list
        assert (
            calls[0][0][0]
            == "https://api.atlassian.com/ex/jira/test_cloud_id/rest/api/3/project"
        )
        assert "projectKeys=PROJ1" in calls[1][0][0]
        assert "projectKeys=PROJ2" in calls[2][0][0]

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_and_issue_types_no_projects_found(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_metadata raises JiraNoProjectsError when no projects are found."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        with pytest.raises(JiraNoProjectsError):
            self.jira_integration.get_metadata()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_and_issue_types_projects_response_error(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_metadata raises JiraGetProjectsError when projects request fails."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetProjectsError):
            self.jira_integration.get_metadata()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_and_issue_types_issue_types_response_error(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_metadata raises JiraGetProjectsError when issue types request fails."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        # Mock successful projects response
        mock_projects_response = MagicMock()
        mock_projects_response.status_code = 200
        mock_projects_response.json.return_value = [
            {"key": "PROJ1", "name": "Project One"}
        ]

        # Mock failed issue types response
        mock_issue_types_response = MagicMock()
        mock_issue_types_response.status_code = 404

        mock_get.side_effect = [mock_projects_response, mock_issue_types_response]

        with pytest.raises(JiraGetProjectsError):
            self.jira_integration.get_metadata()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_and_issue_types_no_project_metadata(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test that get_metadata returns empty issue_types when project metadata is empty."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        # Mock successful projects response
        mock_projects_response = MagicMock()
        mock_projects_response.status_code = 200
        mock_projects_response.json.return_value = [
            {"key": "PROJ1", "name": "Project One"}
        ]

        # Mock issue types response with empty projects list
        mock_issue_types_response = MagicMock()
        mock_issue_types_response.status_code = 200
        mock_issue_types_response.json.return_value = {"projects": []}

        mock_get.side_effect = [mock_projects_response, mock_issue_types_response]

        projects_and_issue_types = self.jira_integration.get_metadata()

        expected_result = {
            "PROJ1": {
                "name": "Project One",
                "issue_types": [],
            }
        }

        assert projects_and_issue_types == expected_result

    @patch.object(
        Jira,
        "get_access_token",
        side_effect=JiraRefreshTokenError("Failed to refresh the access token"),
    )
    def test_get_projects_and_issue_types_refresh_token_error(
        self, mock_get_access_token
    ):
        """Test that get_metadata raises JiraRefreshTokenError when refreshing the token fails."""
        # To disable vulture
        mock_get_access_token = mock_get_access_token

        with pytest.raises(JiraRefreshTokenError):
            self.jira_integration.get_metadata()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_projects_and_issue_types_mixed_scenarios(
        self, mock_get, mock_cloud_id, mock_get_access_token
    ):
        """Test get_metadata with mixed success and empty metadata scenarios."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token

        # Mock projects response with two projects
        mock_projects_response = MagicMock()
        mock_projects_response.status_code = 200
        mock_projects_response.json.return_value = [
            {"key": "PROJ1", "name": "Project One"},
            {"key": "PROJ2", "name": "Project Two"},
        ]

        # Mock successful issue types response for first project
        mock_issue_types_response_1 = MagicMock()
        mock_issue_types_response_1.status_code = 200
        mock_issue_types_response_1.json.return_value = {
            "projects": [
                {
                    "issuetypes": [
                        {"name": "Bug", "id": "1"},
                        {"name": "Task", "id": "2"},
                    ]
                }
            ]
        }

        # Mock empty issue types response for second project
        mock_issue_types_response_2 = MagicMock()
        mock_issue_types_response_2.status_code = 200
        mock_issue_types_response_2.json.return_value = {"projects": []}

        mock_get.side_effect = [
            mock_projects_response,
            mock_issue_types_response_1,
            mock_issue_types_response_2,
        ]

        projects_and_issue_types = self.jira_integration.get_metadata()

        expected_result = {
            "PROJ1": {
                "name": "Project One",
                "issue_types": ["Bug", "Task"],
            },
            "PROJ2": {
                "name": "Project Two",
                "issue_types": [],
            },
        }

        assert projects_and_issue_types == expected_result

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_successful(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test that send_finding returns a confirmed typed result."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types

        mock_response = MagicMock(status_code=201, headers={})
        mock_response.json.return_value = {"id": "10001", "key": "TEST-123"}
        mock_post.return_value = mock_response
        self.jira_integration._site_url = "https://example.atlassian.net"

        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS
        assert result.issue_key == "TEST-123"
        assert result.issue_id == "10001"
        assert result.issue_url == "https://example.atlassian.net/browse/TEST-123"
        assert result.is_confirmed_success is True
        assert bool(result) is True
        mock_post.assert_called_once()

    @pytest.mark.parametrize(
        ("payload", "json_error", "site_url", "error_code"),
        [
            (
                None,
                ValueError("invalid JSON"),
                "https://example",
                "malformed_success_response",
            ),
            ({"id": "10001"}, None, "https://example", "incomplete_success_response"),
            ({"key": "TEST-1"}, None, "https://example", "incomplete_success_response"),
            (
                {"id": "10001", "key": "invalid key"},
                None,
                "https://example",
                "incomplete_success_response",
            ),
            (
                {"id": "not-an-id", "key": "TEST-1"},
                None,
                "https://example",
                "incomplete_success_response",
            ),
            (
                {"id": "10001", "key": "TEST-1"},
                None,
                None,
                "incomplete_success_response",
            ),
        ],
    )
    def test_send_finding_invalid_201_is_uncertain(
        self,
        send_finding_post,
        jira_response,
        payload,
        json_error,
        site_url,
        error_code,
    ):
        self.jira_integration._site_url = site_url
        send_finding_post.post.return_value = jira_response(
            201, payload, json_error=json_error
        )
        result = self.jira_integration.send_finding(
            project_key="TEST", issue_type="Bug", delivery_attempt_marker="attempt-123"
        )

        assert result.outcome == JiraCreationOutcome.UNCERTAIN
        assert result.error_code == error_code
        assert result.delivery_marker == "attempt-123"
        assert result.http_status == 201
        assert bool(result) is False
        if site_url is None:
            assert (result.issue_id, result.issue_key, result.issue_url) == (
                "10001",
                "TEST-1",
                None,
            )

    @pytest.mark.parametrize(
        ("status_code", "outcome", "retry_after"),
        [
            (401, JiraCreationOutcome.CONFIRMED_REJECTION, None),
            (403, JiraCreationOutcome.CONFIRMED_REJECTION, None),
            (408, JiraCreationOutcome.UNCERTAIN, None),
            (429, JiraCreationOutcome.RETRYABLE_FAILURE, "17"),
        ],
    )
    def test_send_finding_classifies_http_failures(
        self, send_finding_post, jira_response, status_code, outcome, retry_after
    ):
        send_finding_post.post.return_value = jira_response(
            status_code,
            {"errorMessages": ["Jira error"]},
            {"Retry-After": retry_after} if retry_after else None,
        )
        result = self.jira_integration.send_finding(
            project_key="TEST", issue_type="Bug"
        )

        assert result.outcome == outcome
        assert result.http_status == status_code
        assert result.retry_after == retry_after

    @pytest.mark.parametrize(
        "transport_error, expected_outcome",
        [
            (
                requests.exceptions.ConnectTimeout(),
                JiraCreationOutcome.RETRYABLE_FAILURE,
            ),
            (requests.exceptions.ReadTimeout(), JiraCreationOutcome.UNCERTAIN),
            (requests.exceptions.ConnectionError(), JiraCreationOutcome.UNCERTAIN),
        ],
    )
    def test_send_finding_classifies_transport_failures(
        self, send_finding_post, transport_error, expected_outcome
    ):
        send_finding_post.post.side_effect = transport_error
        result = self.jira_integration.send_finding(
            project_key="TEST",
            issue_type="Bug",
            delivery_attempt_marker="stable-marker",
        )

        assert result.outcome == expected_outcome
        assert result.delivery_marker == "stable-marker"

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_returns_issue_url_with_basic_auth(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test that send_finding builds the browse URL from the basic auth site name."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types

        mock_response = MagicMock(status_code=201, headers={})
        mock_response.json.return_value = {"id": "10001", "key": "TEST-7"}
        mock_post.return_value = mock_response

        result = self.jira_integration_basic_auth.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS
        assert result.issue_key == "TEST-7"
        assert result.issue_id == "10001"
        assert result.issue_url == "https://test-domain.atlassian.net/browse/TEST-7"

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_sanitizes_issue_labels(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test that labels are sanitized, deduplicated and empties dropped before sending."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types

        mock_response = MagicMock(status_code=201, headers={})
        mock_response.json.return_value = {"id": "10001", "key": "TEST-123"}
        mock_post.return_value = mock_response

        self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
            issue_labels=[
                "prowler",
                "prowler-finding-arn:aws:s3:::my bucket/with space",
                "prowler",
                "",
                "   ",
            ],
        )

        payload = mock_post.call_args.kwargs["json"]
        assert payload["fields"]["labels"] == [
            "prowler",
            "prowler-finding-arn:aws:s3:::my_bucket/with_space",
        ]

    def test_send_finding_reuses_marker_and_caches_valid_destinations(
        self, send_finding_post, jira_response
    ):
        """Test retries keep one marker and catalogs are cached per destination."""
        responses = [
            jira_response(
                201,
                {
                    "id": str(10001 + index),
                    "key": f"TEST-{index + 1}",
                },
            )
            for index in range(3)
        ]
        send_finding_post.projects.return_value = {"TEST": {}, "OPS": {}}
        send_finding_post.issue_types.side_effect = [["Bug"], ["Task"]]
        send_finding_post.post.side_effect = responses

        for _ in range(2):
            self.jira_integration.send_finding(
                project_key="TEST",
                issue_type="Bug",
                delivery_attempt_marker="marker 123",
            )
        self.jira_integration.send_finding(
            project_key="OPS",
            issue_type="Task",
            delivery_attempt_marker="marker 123",
        )

        assert send_finding_post.projects.call_count == 2
        assert send_finding_post.issue_types.call_count == 2
        labels = [
            call.kwargs["json"]["fields"]["labels"]
            for call in send_finding_post.post.call_args_list
        ]
        assert labels == [["prowler-attempt-marker_123"]] * 3

    @pytest.mark.parametrize(
        "projects, issue_types, expected_code",
        [
            ({}, ["Bug"], "invalid_project"),
            ({"TEST": {}}, [], "invalid_issue_type"),
            (JiraNoProjectsError(message="No projects"), ["Bug"], "invalid_project"),
        ],
    )
    def test_send_finding_invalid_destination_is_confirmed_rejection(
        self, send_finding_post, projects, issue_types, expected_code
    ):
        if isinstance(projects, Exception):
            send_finding_post.projects.side_effect = projects
        else:
            send_finding_post.projects.return_value = projects
        send_finding_post.issue_types.return_value = issue_types
        result = self.jira_integration.send_finding(
            project_key="TEST", issue_type="Bug"
        )

        assert result.outcome == JiraCreationOutcome.CONFIRMED_REJECTION
        assert result.error_code == expected_code
        send_finding_post.post.assert_not_called()

    @pytest.mark.parametrize(
        ("failure_stage", "status_code", "outcome", "error_code", "retry_after"),
        [
            (
                "projects",
                403,
                JiraCreationOutcome.CONFIRMED_REJECTION,
                "invalid_credentials",
                None,
            ),
            (
                "issue_types",
                403,
                JiraCreationOutcome.CONFIRMED_REJECTION,
                "invalid_credentials",
                None,
            ),
            (
                "projects",
                429,
                JiraCreationOutcome.RETRYABLE_FAILURE,
                "destination_temporarily_unavailable",
                "23",
            ),
        ],
    )
    def test_send_finding_classifies_catalog_failures(
        self,
        oauth_post,
        jira_response,
        failure_stage,
        status_code,
        outcome,
        error_code,
        retry_after,
    ):
        failure = jira_response(
            status_code, headers={"Retry-After": retry_after} if retry_after else None
        )
        failure.text = "unsafe response body"
        responses = [failure]
        if failure_stage == "issue_types":
            projects = jira_response(200, [{"key": "TEST", "name": "Test"}])
            responses = [projects, failure]

        with patch("prowler.lib.outputs.jira.jira.requests.get", side_effect=responses):
            result = self.jira_integration.send_finding(
                project_key="TEST", issue_type="Bug"
            )

        assert result.outcome == outcome
        assert result.http_status == status_code
        assert result.error_code == error_code
        assert result.retry_after == retry_after
        assert "unsafe response body" not in result.error_message
        oauth_post.assert_not_called()

    def test_sanitize_label(self):
        """Test the deterministic Jira label sanitizer."""
        assert Jira.sanitize_label("") == ""
        assert Jira.sanitize_label(None) == ""
        assert Jira.sanitize_label("   ") == ""
        assert Jira.sanitize_label("simple") == "simple"
        assert Jira.sanitize_label("with space") == "with_space"
        assert Jira.sanitize_label("  many   spaces \t tabs\nnewline ") == (
            "many_spaces_tabs_newline"
        )
        assert Jira.sanitize_label("ctrl\x00char\x07here") == "ctrlcharhere"
        assert Jira.sanitize_label("__ Keep__CASE  Here __") == "Keep_CASE_Here"
        assert Jira.sanitize_label("arn:aws:iam::123456789012:role/Admin") == (
            "arn:aws:iam::123456789012:role/Admin"
        )
        long_label = "x" * 300
        assert Jira.sanitize_label(long_label) == "x" * 255
        # Idempotent: sanitizing an already sanitized value is a no-op
        once = Jira.sanitize_label("a b\tc")
        assert Jira.sanitize_label(once) == once

    def test_prefixed_labels_are_length_safe_and_collision_resistant(self):
        """Test finding and attempt labels preserve identity at Jira's limit."""
        assert Jira.build_finding_label("") == ""
        assert Jira.build_delivery_attempt_label(None) == ""
        finding_prefix = f"{Jira.FINDING_LABEL_PREFIX}-"
        exact_uid = "A" * (Jira.LABEL_MAX_LENGTH - len(finding_prefix))
        assert Jira.build_finding_label(exact_uid) == f"{finding_prefix}{exact_uid}"

        long_prefix = "A" * 400
        first_uid = f"{long_prefix}-first"
        second_uid = f"{long_prefix}-second"
        first_label = Jira.build_finding_label(first_uid)
        second_label = Jira.build_finding_label(second_uid)

        assert len(first_label) == Jira.LABEL_MAX_LENGTH
        assert len(second_label) == Jira.LABEL_MAX_LENGTH
        assert first_label.endswith(hashlib.sha256(first_uid.encode()).hexdigest())
        assert second_label.endswith(hashlib.sha256(second_uid.encode()).hexdigest())
        assert first_label != second_label
        assert Jira.build_delivery_attempt_label("Attempt  CASE") == (
            "prowler-attempt-Attempt_CASE"
        )
        long_attempt_label = Jira.build_delivery_attempt_label(first_uid)
        assert len(long_attempt_label) == Jira.LABEL_MAX_LENGTH
        assert long_attempt_label.endswith(
            hashlib.sha256(first_uid.encode()).hexdigest()
        )

    def test_sanitize_labels(self):
        """Test list sanitization keeps order, drops empties and duplicates."""
        assert Jira.sanitize_labels(None) == []
        assert Jira.sanitize_labels([]) == []
        assert Jira.sanitize_labels(["b", "a b", "b", "", "a_b"]) == ["b", "a_b"]

    def test_site_url_and_issue_url(self):
        """Test site_url derivation and browse URL building for both auth modes."""
        assert (
            self.jira_integration_basic_auth.site_url
            == "https://test-domain.atlassian.net"
        )
        assert (
            self.jira_integration_basic_auth.get_issue_url("TEST-1")
            == "https://test-domain.atlassian.net/browse/TEST-1"
        )
        # OAuth: unknown until accessible-resources is fetched
        assert self.jira_integration.site_url is None
        assert self.jira_integration.get_issue_url("TEST-1") is None
        self.jira_integration._site_url = "https://oauth-site.atlassian.net/"
        assert (
            self.jira_integration.get_issue_url("TEST-1")
            == "https://oauth-site.atlassian.net/browse/TEST-1"
        )
        assert self.jira_integration.get_issue_url("") is None

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_get_issues_status(self, mock_post, mock_cloud_id, mock_get_access_token):
        """Test bulk status lookup returns explicit outcomes in input order."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_response = MagicMock(status_code=200, headers={})
        mock_response.json.return_value = {
            "issues": [
                {
                    "id": "10001",
                    "key": "SEC-1",
                    "fields": {
                        "status": {
                            "name": "Resolved by policy",
                            "statusCategory": {"key": "done"},
                        }
                    },
                },
                {
                    "id": "10002",
                    "key": "SEC-2",
                    "fields": {
                        "status": {
                            "name": "In Progress",
                            "statusCategory": {"key": "indeterminate"},
                        }
                    },
                },
            ],
            "issueErrors": [{"id": "10003", "statusCode": 404}],
        }
        mock_post.return_value = mock_response

        references = [
            JiraIssueReference("10001", "SEC-1"),
            JiraIssueReference("10002", "SEC-2"),
            JiraIssueReference("10003", "SEC-3"),
            JiraIssueReference("10001", "SEC-1"),
        ]
        result = self.jira_integration.get_issues_status(references)

        assert [item.reference for item in result] == references[:3]
        assert [item.outcome for item in result] == [
            JiraIssueLookupOutcome.DONE,
            JiraIssueLookupOutcome.OPEN,
            JiraIssueLookupOutcome.MISSING,
        ]
        assert result[0].status == "Resolved by policy"
        assert result[1].status_category == "indeterminate"
        assert result[2].http_status == 404
        mock_post.assert_called_once()
        assert mock_post.call_args.args[0].endswith("/rest/api/3/issue/bulkfetch")
        assert mock_post.call_args.kwargs["json"] == {
            "issueIdsOrKeys": ["10001", "10002", "10003"],
            "fields": ["status"],
        }

    def test_get_issues_status_moved_precedes_status_and_parses_mixed_errors(
        self, oauth_post, jira_response, jira_issue
    ):
        self.jira_integration._site_url = "https://example.atlassian.net"
        oauth_post.return_value = jira_response(
            200,
            {
                "issues": [
                    jira_issue("10001", "OPS-9", "Custom completion", "done"),
                    jira_issue("10004", "SEC-4"),
                    jira_issue("10006", "SEC-6", "Custom", "unclassified"),
                ],
                "issueErrors": [
                    {"issueIdOrKey": "10002", "errorCode": 403},
                    {"issueId": "10003", "status": 404},
                ],
            },
        )
        references = [
            JiraIssueReference("10001", "SEC-1"),
            JiraIssueReference("10002", "SEC-2"),
            JiraIssueReference("10003", "SEC-3"),
            JiraIssueReference("10004", "SEC-4"),
            JiraIssueReference("10005", "SEC-5"),
            JiraIssueReference("10006", "SEC-6"),
        ]

        results = self.jira_integration.get_issues_status(references)

        assert [result.outcome for result in results] == [
            JiraIssueLookupOutcome.MOVED,
            JiraIssueLookupOutcome.FORBIDDEN,
            JiraIssueLookupOutcome.MISSING,
            JiraIssueLookupOutcome.UNKNOWN,
            JiraIssueLookupOutcome.UNKNOWN,
            JiraIssueLookupOutcome.UNKNOWN,
        ]
        assert results[0].current_issue_key == "OPS-9"
        assert results[0].current_issue_url.endswith("/browse/OPS-9")
        assert results[0].status == "Custom completion"
        assert results[3].error_code == "malformed_issue"
        assert results[4].error_code == "omitted_issue"
        assert results[5].error_code == "malformed_issue"

    def test_get_issues_status_malformed_batch_is_unknown(
        self, oauth_post, jira_response
    ):
        oauth_post.return_value = jira_response(200, {"issues": "invalid"})
        reference = JiraIssueReference("10001", "SEC-1")

        result = self.jira_integration.get_issues_status([reference])[0]

        assert result.outcome == JiraIssueLookupOutcome.UNKNOWN
        assert result.error_code == "malformed_response"

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_get_issues_status_batches_requests(
        self, mock_post, mock_cloud_id, mock_get_access_token
    ):
        """Test that more than ISSUE_STATUS_BATCH_SIZE keys are fetched in batches."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_response = MagicMock(status_code=200, headers={})
        mock_response.json.return_value = {"issues": []}
        mock_post.return_value = mock_response

        references = [JiraIssueReference(str(i), f"SEC-{i}") for i in range(1, 251)]
        results = self.jira_integration.get_issues_status(references)
        assert len(results) == 250
        assert all(
            result.outcome == JiraIssueLookupOutcome.UNKNOWN for result in results
        )
        assert mock_post.call_count == 3
        sizes = [
            len(call.kwargs["json"]["issueIdsOrKeys"])
            for call in mock_post.call_args_list
        ]
        assert sizes == [100, 100, 50]

    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_get_issues_status_without_keys(self, mock_post):
        """Test that no request is made when there is nothing to look up."""
        assert self.jira_integration.get_issues_status([]) == []
        invalid_references = [
            JiraIssueReference("1", "SEC-1\n"),
            JiraIssueReference("2", "SEC-١"),
            JiraIssueReference("not-an-id", "SEC-3"),
        ]
        results = self.jira_integration.get_issues_status(invalid_references)
        assert [result.outcome for result in results] == [
            JiraIssueLookupOutcome.UNKNOWN,
            JiraIssueLookupOutcome.UNKNOWN,
            JiraIssueLookupOutcome.UNKNOWN,
        ]
        assert all(result.error_code == "invalid_reference" for result in results)
        mock_post.assert_not_called()

    def test_get_issues_status_preserves_success_when_later_batch_fails(
        self, oauth_post, jira_response, jira_issue
    ):
        """Test that a failing later batch does not erase earlier results."""
        ok = jira_response(
            200,
            {"issues": [jira_issue("1", "SEC-1", "Done", "done")]},
        )
        failed = jira_response(502, headers={"Retry-After": "12"})
        oauth_post.side_effect = [ok, failed]

        references = [JiraIssueReference(str(i), f"SEC-{i}") for i in range(1, 102)]
        results = self.jira_integration.get_issues_status(references)
        assert results[0].outcome == JiraIssueLookupOutcome.DONE
        assert all(
            result.outcome == JiraIssueLookupOutcome.UNKNOWN for result in results[1:]
        )
        assert results[-1].http_status == 502
        assert results[-1].retry_after == "12"
        assert oauth_post.call_count == 2

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_get_issues_status_response_error(
        self, mock_post, mock_cloud_id, mock_get_access_token
    ):
        """Test that a whole-batch error produces unknown without losing input."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_response = MagicMock(status_code=403, headers={})
        mock_response.text = "forbidden"
        mock_post.return_value = mock_response

        reference = JiraIssueReference("10001", "SEC-1")
        result = self.jira_integration.get_issues_status([reference])[0]
        assert result.reference == reference
        assert result.outcome == JiraIssueLookupOutcome.UNKNOWN
        assert result.http_status == 403

    @pytest.mark.parametrize(
        "issues",
        [
            [],
            [{"id": "10001", "key": "SEC-1"}],
            [
                {"id": "10001", "key": "SEC-1"},
                {"id": "10002", "key": "SEC-2"},
            ],
        ],
    )
    def test_search_issues_by_delivery_attempt_returns_all_matches(
        self, oauth_post, jira_response, issues
    ):
        self.jira_integration._site_url = "https://example.atlassian.net"
        oauth_post.return_value = jira_response(200, {"issues": issues})
        result = self.jira_integration.search_issues_by_delivery_attempt("attempt 123")

        assert result.outcome == JiraIssueSearchOutcome.SUCCESS
        assert [match.issue_id for match in result.matches] == [
            issue["id"] for issue in issues
        ]
        assert all(
            match.issue_url.endswith(match.issue_key) for match in result.matches
        )
        assert oauth_post.call_args.args[0].endswith("/rest/api/3/search/jql")
        assert oauth_post.call_args.kwargs["json"]["jql"] == (
            'labels = "prowler-attempt-attempt_123"'
        )

    @pytest.mark.parametrize(
        "response_kwargs, side_effect, expected_outcome, expected_code, retry_after",
        [
            (
                {"status_code": 429, "headers": {"Retry-After": "9"}},
                None,
                JiraIssueSearchOutcome.RETRYABLE_FAILURE,
                "jira_http_429",
                "9",
            ),
            (
                {"json_error": ValueError("invalid JSON")},
                None,
                JiraIssueSearchOutcome.UNKNOWN,
                "malformed_response",
                None,
            ),
            (
                {},
                requests.exceptions.ReadTimeout(),
                JiraIssueSearchOutcome.RETRYABLE_FAILURE,
                "transport_failure",
                None,
            ),
            (
                {"payload": {"issues": [], "nextPageToken": "repeated"}},
                None,
                JiraIssueSearchOutcome.UNKNOWN,
                "pagination_stalled",
                None,
            ),
        ],
    )
    def test_search_issues_by_delivery_attempt_classifies_failures(
        self,
        oauth_post,
        jira_response,
        response_kwargs,
        side_effect,
        expected_outcome,
        expected_code,
        retry_after,
    ):
        oauth_post.return_value = jira_response(**response_kwargs)
        oauth_post.side_effect = side_effect
        result = self.jira_integration.search_issues_by_delivery_attempt("attempt-123")

        assert result.outcome == expected_outcome
        assert result.error_code == expected_code
        assert result.retry_after == retry_after

    @pytest.mark.parametrize(
        "issue",
        [
            {"id": "not-an-id", "key": "SEC-1"},
            {"id": "10001", "key": "invalid key"},
        ],
    )
    def test_search_issues_by_delivery_attempt_rejects_invalid_identity(
        self, oauth_post, jira_response, issue
    ):
        self.jira_integration._site_url = "https://example.atlassian.net"
        oauth_post.return_value = jira_response(200, {"issues": [issue]})
        result = self.jira_integration.search_issues_by_delivery_attempt("attempt-123")

        assert result.outcome == JiraIssueSearchOutcome.UNKNOWN
        assert result.error_code == "malformed_issue"

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_captures_site_url(self, mock_get):
        """Test that the OAuth cloud id lookup records the site URL."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": "cloud-1", "url": "https://oauth-site.atlassian.net"}
        ]
        mock_get.return_value = mock_response

        assert self.jira_integration.get_cloud_id("token") == "cloud-1"
        assert self.jira_integration.site_url == "https://oauth-site.atlassian.net"

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_sanitizes_summary_control_characters(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test that Jira summary is sent as one line."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types
        mock_response = MagicMock(status_code=201, headers={})
        mock_response.json.return_value = {"id": "10001", "key": "TEST-123"}
        mock_post.return_value = mock_response
        long_check_id = "check\nwith\rcontrol\tcharacters " + "x" * 260

        result = self.jira_integration.send_finding(
            check_id=long_check_id,
            check_title="Test Finding",
            severity="High\n",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
            affected_failing_resources=2,
            grouped_resources=[],
        )

        assert result.issue_key == "TEST-123"
        payload = mock_post.call_args.kwargs["json"]
        expected_summary = (
            f"[Prowler] HIGH - {' '.join(long_check_id.split())} - "
            "2 affected failing resources"
        )[:255]
        assert payload["fields"]["summary"] == expected_summary
        assert len(payload["fields"]["summary"]) == 255

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_failure(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test that a definitive Jira 400 is a confirmed rejection."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types
        mock_response = MagicMock(status_code=400, headers={})
        mock_response.json.return_value = {
            "errors": {"Team": "Team is required."},
            "errorMessages": ["Field 'Team' cannot be set."],
        }
        mock_post.return_value = mock_response

        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.CONFIRMED_REJECTION
        assert result.error_code == "jira_http_400"
        assert "'Team': 'Team is required.'" in result.error_message
        assert "Field 'Team' cannot be set." in result.error_message
        mock_post.assert_called_once()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_response_error_without_json_body(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test a 5xx response is uncertain even without a JSON body."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types
        mock_response = MagicMock(status_code=502, headers={})
        mock_response.json.side_effect = ValueError("No JSON body")
        mock_post.return_value = mock_response

        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.UNCERTAIN
        assert result.error_code == "jira_http_502"
        assert "Jira returned status code 502" in result.error_message
        mock_post.assert_called_once()

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(
        Jira, "cloud_id", new_callable=PropertyMock, return_value="test_cloud_id"
    )
    @patch.object(Jira, "get_projects", return_value={"TEST": {"name": "Test Project"}})
    @patch.object(Jira, "get_available_issue_types", return_value=["Bug"])
    @patch("prowler.lib.outputs.jira.jira.requests.post")
    def test_send_finding_custom_fields_error(
        self,
        mock_post,
        mock_get_issue_types,
        mock_get_projects,
        mock_cloud_id,
        mock_get_access_token,
    ):
        """Test that required custom fields are a confirmed rejection."""
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types
        mock_response = MagicMock(status_code=400, headers={})
        mock_response.json.return_value = {
            "errors": {
                "customfield_10001": "This custom field is required",
                "customfield_10002": "Invalid value for custom field",
            }
        }
        mock_post.return_value = mock_response

        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.CONFIRMED_REJECTION
        assert "customfield_10001" in result.error_message
        mock_post.assert_called_once()

    @pytest.mark.parametrize(
        "access_token_error",
        [
            JiraRefreshTokenError(message="Failed to refresh the access token"),
            JiraGetAccessTokenError(message="Failed to get the access token"),
        ],
    )
    @patch.object(Jira, "get_access_token")
    def test_send_finding_access_token_errors_are_retryable(
        self, mock_get_access_token, access_token_error
    ):
        """Test access-token failures before sending are retryable."""
        mock_get_access_token.side_effect = access_token_error
        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.RETRYABLE_FAILURE

    @patch.object(Jira, "get_access_token", return_value=None)
    def test_send_finding_reraises_no_token_error(self, mock_get_access_token):
        """Test missing credentials are a confirmed rejection."""
        mock_get_access_token = mock_get_access_token
        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.CONFIRMED_REJECTION

    @patch.object(
        Jira,
        "get_access_token",
        side_effect=JiraRefreshTokenResponseError(
            message="Failed to refresh the access token, response code did not match 200"
        ),
    )
    def test_send_finding_reraises_refresh_token_response_error(
        self, mock_get_access_token
    ):
        """Test refresh response failures before sending are retryable."""
        mock_get_access_token = mock_get_access_token
        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result.outcome == JiraCreationOutcome.RETRYABLE_FAILURE

    def test_get_headers_oauth_with_access_token(self):
        """Test get_headers returns correct OAuth headers with access token."""
        self.jira_integration._using_basic_auth = False

        headers = self.jira_integration.get_headers(
            access_token="test_oauth_token", content_type_json=True
        )

        expected_headers = {
            "Authorization": "Bearer test_oauth_token",
            "Content-Type": "application/json",
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers

    def test_get_headers_oauth_without_content_type(self):
        """Test get_headers returns OAuth headers without Content-Type when content_type_json=False."""
        self.jira_integration._using_basic_auth = False

        headers = self.jira_integration.get_headers(
            access_token="test_oauth_token", content_type_json=False
        )

        expected_headers = {
            "Authorization": "Bearer test_oauth_token",
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers
        assert "Content-Type" not in headers

    def test_get_headers_basic_auth_with_access_token(self):
        """Test get_headers returns correct Basic Auth headers with access token."""
        self.jira_integration_basic_auth._using_basic_auth = True

        headers = self.jira_integration_basic_auth.get_headers(
            access_token="test_basic_token", content_type_json=True
        )

        expected_headers = {
            "Authorization": "Basic test_basic_token",
            "Content-Type": "application/json",
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers

    def test_get_headers_basic_auth_without_content_type(self):
        """Test get_headers returns Basic Auth headers without Content-Type when content_type_json=False."""
        self.jira_integration_basic_auth._using_basic_auth = True

        headers = self.jira_integration_basic_auth.get_headers(
            access_token="test_basic_token", content_type_json=False
        )

        expected_headers = {
            "Authorization": "Basic test_basic_token",
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers
        assert "Content-Type" not in headers

    def test_get_headers_without_access_token_with_content_type(self):
        """Test get_headers returns headers without Authorization when no access token provided."""
        headers = self.jira_integration.get_headers(content_type_json=True)

        expected_headers = {
            "Content-Type": "application/json",
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers
        assert "Authorization" not in headers

    def test_get_headers_without_access_token_without_content_type(self):
        """Test get_headers returns minimal headers when no access token and no content type."""
        headers = self.jira_integration.get_headers(content_type_json=False)

        expected_headers = {
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers
        assert "Authorization" not in headers
        assert "Content-Type" not in headers

    def test_get_headers_default_parameters(self):
        """Test get_headers with default parameters (no access token, no content type)."""
        headers = self.jira_integration.get_headers()

        expected_headers = {
            "X-Force-Accept-Language": "true",
            "Accept-Language": "en",
        }
        assert headers == expected_headers
        assert "Authorization" not in headers
        assert "Content-Type" not in headers
