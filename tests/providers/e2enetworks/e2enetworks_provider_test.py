import os
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.common.models import Connection
from prowler.providers.e2enetworks.e2enetworks_provider import E2enetworksProvider
from prowler.providers.e2enetworks.exceptions.exceptions import (
    E2eNetworksCredentialsError,
)


class TestE2enetworksProvider:
    @patch(
        "prowler.providers.e2enetworks.e2enetworks_provider.load_and_validate_config_file"
    )
    def test_e2enetworks_provider_init_success(self, mock_load_config):
        mock_load_config.return_value = {}

        provider = E2enetworksProvider(
            api_key="test-api-key",
            auth_token="test-auth-token",
            project_id="12345",
            locations=["Delhi"],
        )

        assert provider.session.api_key == "test-api-key"
        assert provider.session.auth_token == "test-auth-token"
        assert provider.session.project_id == 12345
        assert provider.identity.project_id == 12345
        assert provider.session.locations == ["Delhi"]
        assert provider.session.http_session.headers["Authorization"] == (
            "Bearer test-auth-token"
        )

    @patch(
        "prowler.providers.e2enetworks.e2enetworks_provider.load_and_validate_config_file"
    )
    def test_e2enetworks_provider_init_missing_credentials(self, mock_load_config):
        mock_load_config.return_value = {}

        with pytest.raises(E2eNetworksCredentialsError):
            E2enetworksProvider(api_key="", auth_token="token", project_id="1")

    @patch.dict(
        os.environ,
        {
            "E2E_NETWORKS_API_KEY": "env-api-key",
            "E2E_NETWORKS_AUTH_TOKEN": "env-auth-token",
            "E2E_NETWORKS_PROJECT_ID": "99",
            "E2E_NETWORKS_REGION": "Chennai",
        },
        clear=False,
    )
    @patch(
        "prowler.providers.e2enetworks.e2enetworks_provider.load_and_validate_config_file"
    )
    def test_e2enetworks_provider_init_from_env(self, mock_load_config):
        mock_load_config.return_value = {}

        provider = E2enetworksProvider()

        assert provider.session.api_key == "env-api-key"
        assert provider.session.project_id == 99
        assert provider.session.locations == ["Chennai"]

    @patch(
        "prowler.providers.e2enetworks.e2enetworks_provider.E2enetworksProvider.setup_session"
    )
    def test_e2enetworks_test_connection_success(self, mock_setup_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.http_session.get.return_value = mock_response
        mock_session.api_key = "key"
        mock_session.project_id = 1
        mock_session.base_url = "https://api.e2enetworks.com/myaccount/api/v1"
        mock_setup_session.return_value = mock_session

        result = E2enetworksProvider.test_connection(
            api_key="key",
            auth_token="token",
            project_id=1,
            locations=["Delhi"],
        )

        assert result == Connection(is_connected=True)

    def test_e2enetworks_test_connection_missing_credentials(self):
        with pytest.raises(E2eNetworksCredentialsError):
            E2enetworksProvider.test_connection(
                api_key="", auth_token="", project_id=None
            )
