from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.common.models import Connection
from prowler.providers.nhn.nhn_provider import NhnProvider


class TestNhnProvider:
    @patch("prowler.providers.nhn.nhn_provider.load_and_validate_config_file")
    @patch("requests.post")
    def test_nhn_provider_init_success(self, mock_post, mock_load_config):
        """
        Test a successful initialization of NhnProvider
        with valid username/password/tenant_id and a Keystone token response = 200.
        """
        # 1) Mock load_and_validate_config_file to avoid reading real config file
        mock_load_config.return_value = {}

        # 2) Mock the requests.post to simulate a successful token response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access": {"token": {"id": "fake_keystone_token"}}
        }
        mock_post.return_value = mock_response

        # 3) Create provider
        provider = NhnProvider(
            username="test_user",
            password="test_pass",
            tenant_id="test_tenant",
        )

        # 4) Assertions
        assert provider._token == "fake_keystone_token"
        assert provider.session is not None
        assert provider.session.headers["X-Auth-Token"] == "fake_keystone_token"

    @patch(
        "prowler.providers.nhn.nhn_provider.load_and_validate_config_file",
        return_value={},
    )
    def test_nhn_provider_init_missing_args(self, mock_load_config):
        """
        Test initialization when username/password/tenant_id is missing => ValueError
        """
        with pytest.raises(ValueError) as exc_info:
            NhnProvider(username="", password="secret", tenant_id="tenant")
        assert "requires username, password and tenant_id" in str(exc_info.value)

    @patch(
        "prowler.providers.nhn.nhn_provider.load_and_validate_config_file",
        return_value={},
    )
    @patch("requests.post")
    def test_nhn_provider_init_token_fail(self, mock_post, mock_load_config):
        """
        Test the case where Keystone token request fails (non-200)
        => provider._session remains None
        """
        mock_post.return_value.status_code = 401
        mock_post.return_value.text = "Unauthorized"

        provider = NhnProvider(
            username="test_user",
            password="test_pass",
            tenant_id="tenant123",
        )

        assert provider._token is None
        assert provider.session is None

    @patch("prowler.providers.nhn.nhn_provider.requests")
    def test_test_connection_success(self, mock_requests):
        """
        Test test_connection static method => success case
        """
        # 1) Mock token success
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            "access": {"token": {"id": "fake_keystone_token"}}
        }
        # 2) Mock /servers success
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_requests.post.return_value = mock_post_response
        mock_requests.get.return_value = mock_get_response

        conn = NhnProvider.test_connection(
            username="test_user",
            password="test_pass",
            tenant_id="tenant123",
            raise_on_exception=True,
        )

        assert isinstance(conn, Connection)
        assert conn.is_connected is True
        assert conn.error is None

    @patch("prowler.providers.nhn.nhn_provider.requests")
    def test_test_connection_token_fail(self, mock_requests):
        """
        Test test_connection => token request fails => returns Connection(error=...)
        """
        mock_requests.post.return_value.status_code = 403
        mock_requests.post.return_value.text = "Forbidden"

        conn = NhnProvider.test_connection(
            username="bad_user",
            password="bad_pass",
            tenant_id="tenant123",
            raise_on_exception=False,  # so we don't raise, we get Connection object
        )
        assert conn.is_connected is False
        assert conn.error is not None
        assert "Failed to get token" in str(conn.error)

    @patch("prowler.providers.nhn.nhn_provider.requests")
    def test_test_connection_servers_fail(self, mock_requests):
        """
        Test test_connection => token OK, but /servers fails => returns Connection(error=...)
        """
        # Keystone token success
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            "access": {"token": {"id": "fake_keystone_token"}}
        }
        mock_requests.post.return_value = mock_post_response

        # /servers fail
        mock_get_response = MagicMock()
        mock_get_response.status_code = 500
        mock_get_response.text = "Internal Server Error"
        mock_requests.get.return_value = mock_get_response

        conn = NhnProvider.test_connection(
            username="test_user",
            password="test_pass",
            tenant_id="tenant123",
            raise_on_exception=False,
        )
        assert conn.is_connected is False
        assert conn.error is not None
        assert "/servers call failed" in str(conn.error)
