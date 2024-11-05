from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest

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
