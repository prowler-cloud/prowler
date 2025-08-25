import os
import sys
from unittest.mock import MagicMock, patch
import pytest
import ionoscloud
from ionoscloud.rest import ApiException
from prowler.providers.common.models import Connection
from prowler.providers.ionos.ionos_provider import IonosProvider
from prowler.providers.ionos.models import IonosIdentityInfo
from prowler.providers.ionos.exceptions.exceptions import (
    IonosNoAuthMethodProvidedError,
    IonosIncompleteCredentialsError,
    IonosEnvironmentCredentialsError,
    IonosTokenLoadError,
)

class TestIonosProvider:
    def setup_method(self):
        self.mock_datacenter = MagicMock()
        self.mock_datacenter.id = "dc-1"
        self.mock_datacenter.properties = MagicMock()
        self.mock_datacenter.properties.name = "Test DC"
        self.mock_datacenter.properties.location = "us/las"

        # Mock API response
        self.mock_response = MagicMock()
        self.mock_response.items = [self.mock_datacenter]

    @patch.dict(
        os.environ,
        {
            "IONOS_USERNAME": "env_user",
            "IONOS_PASSWORD": "env_pass",
        },
    )
    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    @patch("prowler.providers.ionos.ionos_provider.DataCentersApi")
    def test_ionos_provider_init_with_env_vars(self, mock_datacenters_api, mock_load_config):
        """Test initialization of IonosProvider using environment variables"""
        # Mock config and API responses
        mock_load_config.return_value = {}
        mock_datacenters_api.return_value.datacenters_get.return_value = self.mock_response

        # Create provider with environment variables
        provider = IonosProvider(use_env_vars=True)

        assert provider._username == "env_user"
        assert provider._password == "env_pass"
        assert provider._token is None
        assert isinstance(provider.identity, IonosIdentityInfo)
        assert provider.session is not None

    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    @patch("prowler.providers.ionos.ionos_provider.DataCentersApi")
    def test_ionos_provider_init_with_credentials(self, mock_datacenters_api, mock_load_config):
        """Test initialization of IonosProvider using direct credentials"""
        # Mock config and API responses
        mock_load_config.return_value = {}
        mock_datacenter = MagicMock()
        mock_datacenter.id = "dc-1"
        mock_datacenters_api.return_value.datacenters_get.return_value.items = [mock_datacenter]

        # Create provider with credentials
        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        assert provider._username == "test_user"
        assert provider._password == "test_pass"
        assert provider._token is None
        assert isinstance(provider.identity, IonosIdentityInfo)
        assert provider.session is not None

    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    def test_ionos_provider_init_no_auth_method(self, mock_load_config):
        """Test initialization fails when no authentication method is provided"""
        mock_load_config.return_value = {}
        
        with pytest.raises(IonosNoAuthMethodProvidedError):
            IonosProvider()

    @patch.dict(os.environ, {"IONOS_USERNAME": "user"})
    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    def test_ionos_provider_init_incomplete_env_vars(self, mock_load_config):
        """Test initialization fails with incomplete environment variables"""
        mock_load_config.return_value = {}
        
        with pytest.raises(IonosEnvironmentCredentialsError):
            IonosProvider(use_env_vars=True)

    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    def test_ionos_provider_init_incomplete_credentials(self, mock_load_config):
        """Test initialization fails with incomplete direct credentials"""
        mock_load_config.return_value = {}
        
        with pytest.raises(IonosNoAuthMethodProvidedError):
            IonosProvider(ionos_username="user")

    @patch("prowler.providers.ionos.ionos_provider.ApiClient")
    @patch("prowler.providers.ionos.ionos_provider.DataCentersApi")
    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    def test_setup_identity_with_username_password(self, mock_load_config, mock_datacenters_api, mock_api_client):
        """Test identity setup with username/password"""
        # Mock config and API responses
        mock_load_config.return_value = {}
        mock_datacenters_api.return_value.datacenters_get.return_value = self.mock_response

        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        identity = provider.setup_identity(
            username="test_user",
            password="test_pass",
            datacenter_id="dc-1",
        )
        assert isinstance(identity, IonosIdentityInfo)
        assert identity.username == "test_user"
        assert identity.password == "test_pass"
        assert identity.datacenter_id == "dc-1"
        assert identity.token is None

    @patch("prowler.providers.ionos.ionos_provider.ApiClient")
    @patch("prowler.providers.ionos.ionos_provider.DataCentersApi")
    @patch("prowler.providers.ionos.ionos_provider.load_and_validate_config_file")
    def test_setup_identity_with_token(self, mock_load_config, mock_datacenters_api, mock_api_client):
        """Test identity setup with token"""
        # Mock config and API responses
        mock_load_config.return_value = {}
        mock_datacenters_api.return_value.datacenters_get.return_value = self.mock_response

        provider = IonosProvider(
            ionos_username="test_user",
            ionos_password="test_pass",
        )

        provider._token = "test-token"

        identity = provider.setup_identity(
            username=None,
            password=None,
            datacenter_id="dc-1",
        )
        assert isinstance(identity, IonosIdentityInfo)
        assert identity.username is None
        assert identity.password is None
        assert identity.datacenter_id == "dc-1"
        assert identity.token == "test-token"