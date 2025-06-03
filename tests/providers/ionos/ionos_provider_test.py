import os
from unittest.mock import MagicMock, patch
import pytest
import ionoscloud
from ionoscloud.rest import ApiException
from prowler.providers.common.models import Connection
from prowler.providers.ionos.ionos_provider import IonosProvider
from prowler.providers.ionos.models import IonosIdentityInfo

class TestIonosProvider:
    @patch.dict(
        os.environ,
        {
            "IONOS_USERNAME": "env_user",
            "IONOS_PASSWORD": "env_pass",
            "IONOS_TOKEN": "env_token",
        },
    )
    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    def test_ionos_provider_init_success(self, mock_load_config):
        """
        Test a successful initialization of IonosProvider
        with valid username/password/token.
        """
        # Mock load_and_validate_config_file
        mock_load_config.return_value = {}

        # Create provider with test credentials
        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        # Assertions
        assert isinstance(provider.identity, IonosIdentityInfo)
        assert provider.session is not None

    @patch.dict(os.environ, {}, clear=True)
    @patch(
        "prowler.providers.ionos.ionos_provider.load_and_validate_config_file",
        return_value={},
    )
    def test_ionos_provider_load_env_credentials(self, mock_load_config):
        """
        Test loading credentials from environment variables
        """
        username, password, token = IonosProvider.load_env_credentials()
        assert username is None
        assert password is None
        assert token is None

    @patch("prowler.providers.ionos.ionos_provider.ApiClient")
    @patch("ionoscloud.DataCentersApi")
    def test_test_connection_success(self, mock_datacenters_api, mock_api_client):
        """
        Test test_connection method - success case
        """
        # Mock the API response
        mock_api_instance = MagicMock()
        mock_datacenters_api.return_value = mock_api_instance
        mock_api_instance.datacenters_get.return_value = MagicMock()

        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        assert provider.test_connection() is True

    @patch("prowler.providers.ionos.ionos_provider.ApiClient")
    @patch("ionoscloud.DataCentersApi")
    def test_test_connection_failure(self, mock_datacenters_api, mock_api_client):
        """
        Test test_connection method - failure case
        """
        # Mock the API response to raise an exception
        mock_api_instance = MagicMock()
        mock_datacenters_api.return_value = mock_api_instance
        mock_api_instance.datacenters_get.side_effect = ApiException()

        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        assert provider.test_connection() is False

    @patch("prowler.providers.ionos.ionos_provider.ApiClient")
    @patch("ionoscloud.DataCentersApi")
    def test_get_datacenters_success(self, mock_datacenters_api, mock_api_client):
        """
        Test get_datacenters method - success case
        """
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.items = [MagicMock()]
        
        mock_api_instance = MagicMock()
        mock_datacenters_api.return_value = mock_api_instance
        mock_api_instance.datacenters_get.return_value = mock_response

        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        datacenters = provider.get_datacenters()
        assert len(datacenters) == 1

    @patch("prowler.providers.ionos.ionos_provider.ApiClient")
    @patch("ionoscloud.DataCentersApi")
    def test_get_datacenters_failure(self, mock_datacenters_api, mock_api_client):
        """
        Test get_datacenters method - failure case
        """
        # Mock API exception
        mock_api_instance = MagicMock()
        mock_datacenters_api.return_value = mock_api_instance
        mock_api_instance.datacenters_get.side_effect = ApiException()

        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        datacenters = provider.get_datacenters()
        assert len(datacenters) == 0