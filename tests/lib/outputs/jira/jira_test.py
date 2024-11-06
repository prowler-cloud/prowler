from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraGetCloudIdError,
)
from prowler.lib.outputs.jira.jira import Jira


class TestJiraIntegration:
    @pytest.fixture(autouse=True)
    @patch.object(Jira, "get_auth", return_value=None)
    def setup(self, mock_get_auth, monkeypatch):
        # To disable vulture
        mock_get_auth = mock_get_auth

        monkeypatch.setattr("builtins.input", lambda _: "test_authorization_code")

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
        assert self.jira_integration._auth_expiration == 3600
        assert self.jira_integration._cloud_id == "test_cloud_id"

    @patch(
        "prowler.lib.outputs.jira.jira.requests.post",
        side_effect=Exception("Connection error"),
    )
    def test_get_auth_connection_error(self, mock_post):
        """Test get_auth raises JiraAuthenticationError on connection failure."""

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
        """Test get_cloud_id raises JiraGetCloudIdNoResourcesError when no resources are found, later JiraGetCloudIdError will be raised."""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetCloudIdError):
            self.jira_integration.get_cloud_id("test_access_token")

    @patch("prowler.lib.outputs.jira.jira.requests.get")
    def test_get_cloud_id_response_error(self, mock_get):
        """Test get_cloud_id raises JiraGetCloudIdResponseError when response code is not 200, later JiraGetCloudIdError will be raised."""

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Not Found"}
        mock_get.return_value = mock_response

        with pytest.raises(JiraGetCloudIdError):
            self.jira_integration.get_cloud_id("test_access_token")

    @patch(
        "prowler.lib.outputs.jira.jira.requests.get",
        side_effect=Exception("Connection error"),
    )
    def test_get_cloud_id_unexpected_error(self, mock_get):
        """Test get_cloud_id raises JiraGetCloudIdError on an unexpected exception."""

        with pytest.raises(JiraGetCloudIdError):
            self.jira_integration.get_cloud_id("test_access_token")
