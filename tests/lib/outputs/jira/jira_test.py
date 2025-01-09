from datetime import datetime, timedelta
from unittest.mock import MagicMock, PropertyMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from freezegun import freeze_time

from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraCreateIssueError,
    JiraGetAvailableIssueTypesError,
    JiraGetCloudIDError,
    JiraGetProjectsError,
    JiraNoProjectsError,
    JiraRefreshTokenError,
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

    @patch.object(Jira, "get_access_token", return_value="valid_access_token")
    @patch.object(Jira, "get_cloud_id", return_value="test_cloud_id")
    @patch.object(Jira, "get_auth", return_value=None)
    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_test_connection_successful(
        self, mock_get, mock_get_cloud_id, mock_get_auth, mock_get_access_token
    ):
        """Test that a successful connection returns an active Connection object."""
        # To disable vulture
        mock_get_cloud_id = mock_get_cloud_id
        mock_get_auth = mock_get_auth
        mock_get_access_token = mock_get_access_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "test_user_id"}
        mock_get.return_value = mock_response

        connection = self.jira_integration.test_connection(
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        assert connection.is_connected
        assert connection.error is None

    @patch.object(
        Jira,
        "get_access_token",
        side_effect=JiraAuthenticationError("Failed to authenticate with Jira"),
    )
    def test_test_connection_failed(self, mock_get_access_token):
        """Test that a failed connection raises JiraAuthenticationError."""
        # To disable vulture
        mock_get_access_token = mock_get_access_token

        with pytest.raises(JiraAuthenticationError):
            self.jira_integration.test_connection(
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

        self.jira_integration.cloud_id = "valid_cloud_id"

        self.jira_integration.send_findings(
            findings=[finding], project_key="TEST-1", issue_type="Bug"
        )

        expected_url = (
            "https://api.atlassian.com/ex/jira/valid_cloud_id/rest/api/3/issue"
        )
        expected_json = {
            "fields": {
                "project": {"key": "TEST-1"},
                "summary": "[Prowler] HIGH - CHECK-1 - resource-1",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Prowler has discovered the following finding:",
                                }
                            ],
                        },
                        {
                            "type": "table",
                            "attrs": {"layout": "full-width"},
                            "content": [
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Check Id",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "CHECK-1",
                                                            "marks": [{"type": "code"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Check Title",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Check Title",
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Severity",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {"type": "text", "text": "HIGH"}
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Status",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "FAIL",
                                                            "marks": [
                                                                {"type": "strong"},
                                                                {
                                                                    "type": "textColor",
                                                                    "attrs": {
                                                                        "color": "#FF0000"
                                                                    },
                                                                },
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Status Extended",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "status_extended",
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Provider",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "aws",
                                                            "marks": [{"type": "code"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Region",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "region",
                                                            "marks": [{"type": "code"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Resource UID",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "resource-1",
                                                            "marks": [{"type": "code"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Resource Name",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "resource_name",
                                                            "marks": [{"type": "code"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Risk",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {"type": "text", "text": "risk"}
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [1]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "Recommendation",
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
                                        {
                                            "type": "tableCell",
                                            "attrs": {"colwidth": [3]},
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "remediation_text ",
                                                        },
                                                        {
                                                            "type": "text",
                                                            "text": "remediation_url",
                                                            "marks": [
                                                                {
                                                                    "type": "link",
                                                                    "attrs": {
                                                                        "href": "remediation_url"
                                                                    },
                                                                }
                                                            ],
                                                        },
                                                    ],
                                                }
                                            ],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
                "issuetype": {"name": "Bug"},
            }
        }
        expected_headers = {
            "Authorization": "Bearer valid_access_token",
            "Content-Type": "application/json",
        }

        mock_post.assert_called_once_with(
            expected_url, json=expected_json, headers=expected_headers
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

    @pytest.mark.parametrize(
        "status, expected_color",
        [("FAIL", "#FF0000"), ("PASS", "#008000"), ("MUTED", "#FFA500")],
    )
    def test_get_color_from_status(self, status, expected_color):
        """Test that get_color_from_status returns the correct color for a status."""
        assert self.jira_integration.get_color_from_status(status) == expected_color
