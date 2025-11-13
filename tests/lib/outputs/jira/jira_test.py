import base64
from datetime import datetime, timedelta
from typing import List, Optional
from unittest.mock import MagicMock, PropertyMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from freezegun import freeze_time

from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraBasicAuthError,
    JiraCreateIssueError,
    JiraGetAvailableIssueTypesError,
    JiraGetCloudIDError,
    JiraGetProjectsError,
    JiraGetProjectsResponseError,
    JiraNoProjectsError,
    JiraRefreshTokenError,
    JiraRequiredCustomFieldsError,
    JiraTestConnectionError,
)
from prowler.lib.outputs.jira.jira import Jira

TEST_DATETIME = "2023-01-01T12:01:01+00:00"


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
        self.domain = "test_domain"

        self.jira_integration_basic_auth = Jira(
            user_mail=self.user_mail,
            api_token=self.api_token,
            domain=self.domain,
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

    @patch.object(Jira, "get_auth", return_value=None)
    @patch.object(
        Jira,
        "get_projects",
        return_value={"PROJ1": "Project One", "PROJ2": "Project Two"},
    )
    def test_test_connection_successful(self, mock_get_projects, mock_get_auth):
        """Test that a successful connection returns an active Connection object with projects."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_auth = mock_get_auth

        connection = Jira.test_connection(
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        assert connection.is_connected
        assert connection.error is None
        assert connection.projects == {"PROJ1": "Project One", "PROJ2": "Project Two"}

    @patch.object(Jira, "get_basic_auth", return_value=None)
    @patch.object(
        Jira,
        "get_projects",
        return_value={"PROJ1": "Project One", "PROJ2": "Project Two"},
    )
    def test_test_connection_successful_basic_auth(
        self, mock_get_projects, mock_get_basic_auth
    ):
        """Test that a successful connection returns an active Connection object with projects."""
        # To disable vulture
        mock_get_projects = mock_get_projects
        mock_get_basic_auth = mock_get_basic_auth

        connection = Jira.test_connection(
            user_mail=self.user_mail,
            api_token=self.api_token,
            domain=self.domain,
        )

        assert connection.is_connected
        assert connection.error is None
        assert connection.projects == {"PROJ1": "Project One", "PROJ2": "Project Two"}

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
        """Test that send_finding returns True when the finding is sent successfully."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "ISSUE-123", "key": "TEST-123"}
        mock_post.return_value = mock_response

        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result is True
        mock_post.assert_called_once()

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
        """Test that send_finding returns False when the request fails."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types

        # Mock failed response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"errors": {"summary": "Required field"}}
        mock_post.return_value = mock_response

        result = self.jira_integration.send_finding(
            check_id="test-check",
            check_title="Test Finding",
            severity="High",
            status="FAIL",
            project_key="TEST",
            issue_type="Bug",
        )

        assert result is False
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
        """Test that send_finding returns False when custom fields cause an error."""
        # To disable vulture
        mock_cloud_id = mock_cloud_id
        mock_get_access_token = mock_get_access_token
        mock_get_projects = mock_get_projects
        mock_get_issue_types = mock_get_issue_types

        # Mock response with custom fields error
        mock_response = MagicMock()
        mock_response.status_code = 400
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

        assert result is False
        mock_post.assert_called_once()

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
