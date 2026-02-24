"""Tests for OpenStack Provider."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from openstack import exceptions as openstack_exceptions

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.openstack.exceptions.exceptions import (
    OpenStackAmbiguousRegionError,
    OpenStackAuthenticationError,
    OpenStackCloudNotFoundError,
    OpenStackConfigFileNotFoundError,
    OpenStackCredentialsError,
    OpenStackInvalidConfigError,
    OpenStackInvalidProviderIdError,
    OpenStackNoRegionError,
)
from prowler.providers.openstack.models import OpenStackIdentityInfo, OpenStackSession
from prowler.providers.openstack.openstack_provider import OpenstackProvider


class TestOpenstackProvider:
    """Test suite for OpenStack Provider initialization."""

    @pytest.fixture(autouse=True)
    def clean_openstack_env(self, monkeypatch):
        """Ensure clean OpenStack environment for all tests."""
        openstack_env_vars = [
            "OS_AUTH_URL",
            "OS_USERNAME",
            "OS_PASSWORD",
            "OS_PROJECT_ID",
            "OS_REGION_NAME",
            "OS_CLOUD",
            "OS_IDENTITY_API_VERSION",
            "OS_USER_DOMAIN_NAME",
            "OS_PROJECT_DOMAIN_NAME",
        ]
        for env_var in openstack_env_vars:
            monkeypatch.delenv(env_var, raising=False)

    def test_openstack_provider_with_all_parameters(self):
        """Test OpenStack provider initialization with all parameters provided."""
        auth_url = "https://openstack.example.com:5000/v3"
        identity_api_version = "3"
        username = "test-user"
        password = "test-password"
        project_id = "test-project-id"
        region_name = "RegionOne"
        user_domain_name = "Default"
        project_domain_name = "Default"

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = "test-user-id"
        mock_connection.current_project_id = "test-project-id"

        mock_user = MagicMock()
        mock_user.name = "test-user"
        mock_connection.identity.get_user.return_value = mock_user

        mock_project = MagicMock()
        mock_project.name = "test-project"
        mock_connection.identity.get_project.return_value = mock_project

        fixer_config = load_and_validate_config_file(
            "openstack", default_fixer_config_file_path
        )

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(
                auth_url=auth_url,
                identity_api_version=identity_api_version,
                username=username,
                password=password,
                project_id=project_id,
                region_name=region_name,
                user_domain_name=user_domain_name,
                project_domain_name=project_domain_name,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
            )

            assert provider.type == "openstack"
            assert provider.session.auth_url == auth_url
            assert provider.session.username == username
            assert provider.session.project_id == project_id
            assert provider.session.region_name == region_name
            assert provider.session.user_domain_name == user_domain_name
            assert provider.session.project_domain_name == project_domain_name
            assert provider.identity.username == "test-user"
            assert provider.identity.project_name == "test-project"
            assert provider.identity.user_id == "test-user-id"
            assert provider.identity.project_id == "test-project-id"
            assert provider.identity.region_name == region_name
            assert provider.connection == mock_connection
            assert provider.audit_config is not None
            assert provider.fixer_config == fixer_config

    def test_openstack_provider_with_environment_variables(self, monkeypatch):
        """Test OpenStack provider initialization using environment variables."""
        auth_url = "https://openstack.example.com:5000/v3"
        username = "env-user"
        password = "env-password"
        project_id = "env-project-id"
        region_name = "RegionOne"

        monkeypatch.setenv("OS_AUTH_URL", auth_url)
        monkeypatch.setenv("OS_USERNAME", username)
        monkeypatch.setenv("OS_PASSWORD", password)
        monkeypatch.setenv("OS_PROJECT_ID", project_id)
        monkeypatch.setenv("OS_REGION_NAME", region_name)

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = "env-user-id"
        mock_connection.current_project_id = project_id

        mock_user = MagicMock()
        mock_user.name = username
        mock_connection.identity.get_user.return_value = mock_user

        mock_project = MagicMock()
        mock_project.name = "env-project"
        mock_connection.identity.get_project.return_value = mock_project

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()

            assert provider.session.auth_url == auth_url
            assert provider.session.username == username
            assert provider.session.project_id == project_id
            assert provider.session.region_name == region_name
            assert provider.identity.username == username

    def test_openstack_provider_missing_auth_url(self):
        """Test OpenStack provider initialization fails when OS_AUTH_URL is missing."""
        with pytest.raises(OpenStackCredentialsError) as excinfo:
            OpenstackProvider(
                username="test-user",
                password="test-password",
                project_id="test-project",
                region_name="RegionOne",
            )

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_AUTH_URL" in str(excinfo.value)

    def test_openstack_provider_missing_username(self, monkeypatch):
        """Test OpenStack provider initialization fails when OS_USERNAME is missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        with pytest.raises(OpenStackCredentialsError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_USERNAME" in str(excinfo.value)

    def test_openstack_provider_missing_password(self, monkeypatch):
        """Test OpenStack provider initialization fails when OS_PASSWORD is missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        with pytest.raises(OpenStackCredentialsError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_PASSWORD" in str(excinfo.value)

    def test_openstack_provider_missing_project_id(self, monkeypatch):
        """Test OpenStack provider initialization fails when OS_PROJECT_ID is missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        with pytest.raises(OpenStackCredentialsError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_PROJECT_ID" in str(excinfo.value)

    def test_openstack_provider_missing_region(self, monkeypatch):
        """Test OpenStack provider initialization fails when OS_REGION_NAME is missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")

        with pytest.raises(OpenStackCredentialsError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_REGION_NAME" in str(excinfo.value)

    def test_openstack_provider_with_custom_identity_api_version(self, monkeypatch):
        """Test OpenStack provider with custom identity API version."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")
        monkeypatch.setenv("OS_IDENTITY_API_VERSION", "3.5")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()

            assert provider.session.identity_api_version == "3.5"

    def test_openstack_provider_with_custom_domain_names(self, monkeypatch):
        """Test OpenStack provider with custom user and project domain names."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")
        monkeypatch.setenv("OS_USER_DOMAIN_NAME", "CustomUserDomain")
        monkeypatch.setenv("OS_PROJECT_DOMAIN_NAME", "CustomProjectDomain")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()

            assert provider.session.user_domain_name == "CustomUserDomain"
            assert provider.session.project_domain_name == "CustomProjectDomain"

    def test_openstack_provider_connection_failure(self, monkeypatch):
        """Test OpenStack provider initialization fails when connection cannot be established."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.side_effect = openstack_exceptions.SDKException(
                "Connection failed"
            )

            with pytest.raises(OpenStackAuthenticationError):
                OpenstackProvider()

    def test_openstack_provider_static_test_connection_success(self):
        """Test static test_connection method with valid credentials."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            connection_result = OpenstackProvider.test_connection(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="test-project",
                region_name="RegionOne",
                raise_on_exception=False,
            )

            assert isinstance(connection_result, Connection)
            assert connection_result.is_connected is True
            assert connection_result.error is None
            mock_connect.assert_called_once()

    def test_openstack_provider_static_test_connection_missing_credentials(self):
        """Test static test_connection fails with missing credentials."""
        connection_result = OpenstackProvider.test_connection(
            auth_url="https://openstack.example.com:5000/v3",
            username="test-user",
            password="test-password",
            # Missing project_id
            region_name="RegionOne",
            raise_on_exception=False,
        )

        assert isinstance(connection_result, Connection)
        assert connection_result.is_connected is False
        assert connection_result.error is not None
        assert "Missing mandatory OpenStack environment variables" in str(
            connection_result.error
        )

    def test_openstack_provider_static_test_connection_failure(self):
        """Test static test_connection handles connection failures."""
        mock_connection = MagicMock()
        mock_connection.authorize.side_effect = openstack_exceptions.SDKException(
            "Connection failed"
        )

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            connection_result = OpenstackProvider.test_connection(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="test-project",
                region_name="RegionOne",
                raise_on_exception=False,
            )

            assert isinstance(connection_result, Connection)
            assert connection_result.is_connected is False
            assert connection_result.error is not None

    def test_openstack_provider_static_test_connection_raise_on_exception(self):
        """Test static test_connection raises exception when raise_on_exception=True."""
        mock_connection = MagicMock()
        mock_connection.authorize.side_effect = openstack_exceptions.SDKException(
            "Connection failed"
        )

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            with pytest.raises(OpenStackAuthenticationError):
                OpenstackProvider.test_connection(
                    auth_url="https://openstack.example.com:5000/v3",
                    username="test-user",
                    password="test-password",
                    project_id="test-project",
                    region_name="RegionOne",
                    raise_on_exception=True,
                )

    def test_openstack_provider_static_test_connection_with_custom_domains(self):
        """Test static test_connection with custom domain names."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            connection_result = OpenstackProvider.test_connection(
                auth_url="https://openstack.example.com:5000/v3",
                identity_api_version="3",
                username="test-user",
                password="test-password",
                project_id="test-project",
                region_name="RegionOne",
                user_domain_name="CustomUserDomain",
                project_domain_name="CustomProjectDomain",
                raise_on_exception=False,
            )

            assert isinstance(connection_result, Connection)
            assert connection_result.is_connected is True
            assert connection_result.error is None

    def test_openstack_provider_identity_enrichment_failure(self, monkeypatch):
        """Test OpenStack provider handles identity enrichment failures gracefully."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = "test-user-id"
        mock_connection.current_project_id = "test-project-id"
        mock_connection.identity.get_user.side_effect = (
            openstack_exceptions.SDKException("User not found")
        )
        mock_connection.identity.get_project.side_effect = (
            openstack_exceptions.SDKException("Project not found")
        )

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()

            # Provider should still work with basic session info
            assert provider.identity.username == "test-user"
            assert provider.identity.project_id == "test-project"

    def test_openstack_provider_print_credentials(self, monkeypatch, capsys):
        """Test OpenStack provider prints credentials correctly."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project-id")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = "test-user-id"
        mock_connection.current_project_id = "test-project-id"

        mock_user = MagicMock()
        mock_user.name = "test-user"
        mock_connection.identity.get_user.return_value = mock_user

        mock_project = MagicMock()
        mock_project.name = "test-project"
        mock_connection.identity.get_project.return_value = mock_project

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()
            provider.print_credentials()

            captured = capsys.readouterr()
            assert "OpenStack Credentials" in captured.out
            assert "Auth URL: https://openstack.example.com:5000/v3" in captured.out
            assert "Project ID: test-project-id" in captured.out
            assert "Username: test-user" in captured.out
            assert "Region: RegionOne" in captured.out

    def test_openstack_provider_with_config_content(self, monkeypatch):
        """Test OpenStack provider with config content instead of config path."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        config_content = {"custom_key": "custom_value"}

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(config_content=config_content)

            assert provider.audit_config == config_content

    def test_openstack_provider_with_mutelist_content(self, monkeypatch):
        """Test OpenStack provider with mutelist content instead of mutelist path."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        mutelist_content = {"Accounts": {"*": []}}

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(mutelist_content=mutelist_content)

            assert provider.mutelist is not None

    def test_openstack_session_as_sdk_config(self):
        """Test OpenStackSession.as_sdk_config() with non-UUID project_id."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="test-project",
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config()

        assert sdk_config["auth_url"] == "https://openstack.example.com:5000/v3"
        assert sdk_config["username"] == "test-user"
        assert sdk_config["password"] == "test-password"
        # Non-UUID project_id should be returned as project_name
        assert sdk_config["project_name"] == "test-project"
        assert "project_id" not in sdk_config
        assert sdk_config["region_name"] == "RegionOne"
        assert sdk_config["user_domain_name"] == "Default"
        assert sdk_config["project_domain_name"] == "Default"
        assert sdk_config["identity_api_version"] == "3"

    def test_openstack_session_as_sdk_config_with_uuid(self):
        """Test OpenStackSession.as_sdk_config() with UUID project_id (standard format with dashes)."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config()

        assert sdk_config["auth_url"] == "https://openstack.example.com:5000/v3"
        assert sdk_config["username"] == "test-user"
        assert sdk_config["password"] == "test-password"
        # UUID project_id should be returned as project_id
        assert sdk_config["project_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert "project_name" not in sdk_config
        assert sdk_config["region_name"] == "RegionOne"
        assert sdk_config["user_domain_name"] == "Default"
        assert sdk_config["project_domain_name"] == "Default"
        assert sdk_config["identity_api_version"] == "3"

    def test_openstack_session_as_sdk_config_with_uuid_no_dashes(self):
        """Test OpenStackSession.as_sdk_config() with UUID project_id (compact format without dashes, e.g., OVH)."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="f60368c2d0e04193bd61e14ae5754eeb",  # OVH-style UUID without dashes
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config()

        assert sdk_config["auth_url"] == "https://openstack.example.com:5000/v3"
        assert sdk_config["username"] == "test-user"
        assert sdk_config["password"] == "test-password"
        # UUID without dashes should still be returned as project_id
        assert sdk_config["project_id"] == "f60368c2d0e04193bd61e14ae5754eeb"
        assert "project_name" not in sdk_config
        assert sdk_config["region_name"] == "RegionOne"
        assert sdk_config["user_domain_name"] == "Default"
        assert sdk_config["project_domain_name"] == "Default"
        assert sdk_config["identity_api_version"] == "3"

    def test_openstack_identity_info_defaults(self):
        """Test OpenStackIdentityInfo has correct defaults."""
        identity = OpenStackIdentityInfo(
            username="test-user",
            project_id="test-project",
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
        )

        assert identity.user_id is None
        assert identity.project_name is None
        assert identity.username == "test-user"
        assert identity.project_id == "test-project"
        assert identity.region_name == "RegionOne"


class TestOpenstackProviderCloudsYaml:
    """Test suite for OpenStack Provider clouds.yaml support."""

    @pytest.fixture(autouse=True)
    def clean_openstack_env(self, monkeypatch):
        """Ensure clean OpenStack environment for all tests."""
        openstack_env_vars = [
            "OS_AUTH_URL",
            "OS_USERNAME",
            "OS_PASSWORD",
            "OS_PROJECT_ID",
            "OS_REGION_NAME",
            "OS_CLOUD",
            "OS_IDENTITY_API_VERSION",
            "OS_USER_DOMAIN_NAME",
            "OS_PROJECT_DOMAIN_NAME",
        ]
        for env_var in openstack_env_vars:
            monkeypatch.delenv(env_var, raising=False)

    def test_clouds_yaml_explicit_file_path(self, tmp_path):
        """Test loading clouds.yaml from an explicit file path."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: yaml-user
      password: yaml-password
      project_id: yaml-project-id
      user_domain_name: YamlUserDomain
      project_domain_name: YamlProjectDomain
    region_name: RegionOne
    identity_api_version: 3
"""
        )

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = "yaml-user-id"
        mock_connection.current_project_id = "yaml-project-id"

        mock_user = MagicMock()
        mock_user.name = "yaml-user"
        mock_connection.identity.get_user.return_value = mock_user

        mock_project = MagicMock()
        mock_project.name = "yaml-project"
        mock_connection.identity.get_project.return_value = mock_project

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
            )

            assert provider.session.auth_url == "https://openstack.example.com:5000/v3"
            assert provider.session.username == "yaml-user"
            assert provider.session.project_id == "yaml-project-id"
            assert provider.session.region_name == "RegionOne"
            assert provider.session.user_domain_name == "YamlUserDomain"
            assert provider.session.project_domain_name == "YamlProjectDomain"
            assert provider.identity.username == "yaml-user"

    def test_clouds_yaml_with_explicit_cloud_name(self, tmp_path):
        """Test loading clouds.yaml with an explicit cloud name."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  default-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: default-user
      password: default-password
      project_id: default-project-id
    region_name: RegionOne
    identity_api_version: 3
"""
        )

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "default-project-id"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            # Explicitly specify the cloud name
            provider = OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="default-cloud",
            )

            assert provider.session.auth_url == "https://openstack.example.com:5000/v3"
            assert provider.session.username == "default-user"
            assert provider.session.project_id == "default-project-id"

    def test_clouds_yaml_file_without_cloud_name(self, tmp_path):
        """Test error when clouds.yaml file is provided without cloud name."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
"""
        )

        with pytest.raises(OpenStackInvalidConfigError) as excinfo:
            OpenstackProvider(clouds_yaml_file=str(clouds_yaml))

        assert "Cloud name (--clouds-yaml-cloud) is required" in str(excinfo.value)

    def test_clouds_yaml_file_not_found(self):
        """Test error when clouds.yaml file does not exist."""
        with pytest.raises(OpenStackConfigFileNotFoundError) as excinfo:
            OpenstackProvider(
                clouds_yaml_file="/nonexistent/path/to/clouds.yaml",
                clouds_yaml_cloud="test-cloud",
            )

        assert "clouds.yaml file not found" in str(excinfo.value)

    def test_clouds_yaml_cloud_not_found(self, tmp_path):
        """Test error when specified cloud is not in clouds.yaml."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  existing-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
"""
        )

        with pytest.raises(OpenStackCloudNotFoundError) as excinfo:
            OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="nonexistent-cloud",
            )

        assert "Cloud 'nonexistent-cloud' not found" in str(excinfo.value)

    def test_clouds_yaml_missing_required_fields(self, tmp_path):
        """Test error when clouds.yaml is missing required fields."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  incomplete-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      # Missing password and other required fields
    region_name: RegionOne
"""
        )

        with pytest.raises(OpenStackInvalidConfigError) as excinfo:
            OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="incomplete-cloud",
            )

        assert "Missing required fields" in str(excinfo.value)
        assert "password" in str(excinfo.value)

    def test_clouds_yaml_malformed_yaml(self, tmp_path):
        """Test error when clouds.yaml is malformed."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  malformed-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
    - invalid: yaml: structure
"""
        )

        with pytest.raises(OpenStackInvalidConfigError):
            OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="malformed-cloud",
            )

    def test_clouds_yaml_with_project_name(self, tmp_path):
        """Test clouds.yaml using project_name instead of project_id."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_name: test-project-name
      user_domain_name: Default
      project_domain_name: Default
    region_name: RegionOne
    identity_api_version: 3
"""
        )

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project-id"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
            )

            # project_name should be used when project_id is not available
            assert provider.session.project_id == "test-project-name"

    def test_clouds_yaml_priority_over_env_vars(self, tmp_path, monkeypatch):
        """Test that clouds.yaml takes priority over environment variables."""
        # Set environment variables that should be ignored
        monkeypatch.setenv("OS_AUTH_URL", "https://env.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "env-user")
        monkeypatch.setenv("OS_PASSWORD", "env-password")
        monkeypatch.setenv("OS_PROJECT_ID", "env-project")
        monkeypatch.setenv("OS_REGION_NAME", "EnvRegion")

        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://yaml.example.com:5000/v3
      username: yaml-user
      password: yaml-password
      project_id: yaml-project-id
    region_name: YamlRegion
    identity_api_version: 3
"""
        )

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "yaml-project-id"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
            )

            # Should use clouds.yaml values, not environment variables
            assert provider.session.auth_url == "https://yaml.example.com:5000/v3"
            assert provider.session.username == "yaml-user"
            assert provider.session.project_id == "yaml-project-id"
            assert provider.session.region_name == "YamlRegion"

    def test_test_connection_with_clouds_yaml(self, tmp_path):
        """Test static test_connection method with clouds.yaml."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
    identity_api_version: 3
"""
        )

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            connection_result = OpenstackProvider.test_connection(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
                raise_on_exception=False,
            )

            assert isinstance(connection_result, Connection)
            assert connection_result.is_connected is True
            assert connection_result.error is None
            mock_connect.assert_called_once()

    def test_test_connection_clouds_yaml_file_not_found(self):
        """Test test_connection error when clouds.yaml file does not exist."""
        connection_result = OpenstackProvider.test_connection(
            clouds_yaml_file="/nonexistent/path/to/clouds.yaml",
            clouds_yaml_cloud="test-cloud",
            raise_on_exception=False,
        )

        assert isinstance(connection_result, Connection)
        assert connection_result.is_connected is False
        assert isinstance(connection_result.error, OpenStackConfigFileNotFoundError)

    def test_test_connection_clouds_yaml_cloud_not_found(self, tmp_path):
        """Test test_connection error when cloud is not in clouds.yaml."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  existing-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
"""
        )

        connection_result = OpenstackProvider.test_connection(
            clouds_yaml_file=str(clouds_yaml),
            clouds_yaml_cloud="nonexistent-cloud",
            raise_on_exception=False,
        )

        assert isinstance(connection_result, Connection)
        assert connection_result.is_connected is False
        assert isinstance(connection_result.error, OpenStackCloudNotFoundError)

    def test_backward_compatibility_env_vars_still_work(self, monkeypatch):
        """Test that existing environment variable authentication still works (backward compatibility)."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            # Initialize without clouds.yaml parameters
            provider = OpenstackProvider()

            # Should use environment variables as before
            assert provider.session.auth_url == "https://openstack.example.com:5000/v3"
            assert provider.session.username == "test-user"
            assert provider.session.project_id == "test-project"

    def test_backward_compatibility_explicit_params_still_work(self):
        """Test that explicit parameter authentication still works (backward compatibility)."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            # Initialize with explicit parameters (no clouds.yaml)
            provider = OpenstackProvider(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="test-project",
                region_name="RegionOne",
            )

            # Should use explicit parameters as before
            assert provider.session.auth_url == "https://openstack.example.com:5000/v3"
            assert provider.session.username == "test-user"
            assert provider.session.project_id == "test-project"


class TestOpenstackProviderRegionValidation:
    """Test suite for OpenStack Provider region validation (region_name XOR regions)."""

    @pytest.fixture(autouse=True)
    def clean_openstack_env(self, monkeypatch):
        """Ensure clean OpenStack environment for all tests."""
        openstack_env_vars = [
            "OS_AUTH_URL",
            "OS_USERNAME",
            "OS_PASSWORD",
            "OS_PROJECT_ID",
            "OS_REGION_NAME",
            "OS_CLOUD",
            "OS_IDENTITY_API_VERSION",
            "OS_USER_DOMAIN_NAME",
            "OS_PROJECT_DOMAIN_NAME",
        ]
        for env_var in openstack_env_vars:
            monkeypatch.delenv(env_var, raising=False)

    def test_clouds_yaml_content_with_region_name_only(self):
        """Test that clouds.yaml content with only region_name produces a valid session."""
        clouds_yaml_content = """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
    identity_api_version: 3
"""
        session = OpenstackProvider._setup_session_from_clouds_yaml_content(
            clouds_yaml_content=clouds_yaml_content,
            clouds_yaml_cloud="test-cloud",
        )

        assert session.region_name == "RegionOne"
        assert session.regions is None

    def test_clouds_yaml_content_with_regions_list_only(self):
        """Test that clouds.yaml content with only regions list produces a valid session."""
        clouds_yaml_content = """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    regions:
      - RegionOne
      - RegionTwo
    identity_api_version: 3
"""
        session = OpenstackProvider._setup_session_from_clouds_yaml_content(
            clouds_yaml_content=clouds_yaml_content,
            clouds_yaml_cloud="test-cloud",
        )

        assert session.region_name is None
        assert session.regions == ["RegionOne", "RegionTwo"]

    def test_clouds_yaml_content_with_both_region_name_and_regions(self):
        """Test that clouds.yaml content with both region_name and regions raises error."""
        clouds_yaml_content = """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
    regions:
      - RegionOne
      - RegionTwo
    identity_api_version: 3
"""
        with pytest.raises(OpenStackAmbiguousRegionError) as excinfo:
            OpenstackProvider._setup_session_from_clouds_yaml_content(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud="test-cloud",
            )

        assert "both 'region_name' and 'regions'" in str(excinfo.value)

    def test_clouds_yaml_content_with_neither_region_name_nor_regions(self):
        """Test that clouds.yaml content with neither region_name nor regions raises error."""
        clouds_yaml_content = """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    identity_api_version: 3
"""
        with pytest.raises(OpenStackNoRegionError) as excinfo:
            OpenstackProvider._setup_session_from_clouds_yaml_content(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud="test-cloud",
            )

        assert "neither 'region_name' nor 'regions'" in str(excinfo.value)

    def test_clouds_yaml_file_with_regions_list(self, tmp_path):
        """Test loading clouds.yaml file with regions list."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    regions:
      - RegionOne
      - RegionTwo
    identity_api_version: 3
"""
        )

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project-id"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
            )

            assert provider.session.region_name is None
            assert provider.session.regions == ["RegionOne", "RegionTwo"]

    def test_clouds_yaml_file_with_both_regions_raises_error(self, tmp_path):
        """Test that clouds.yaml file with both region_name and regions raises error."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    region_name: RegionOne
    regions:
      - RegionOne
      - RegionTwo
    identity_api_version: 3
"""
        )

        with pytest.raises(OpenStackAmbiguousRegionError):
            OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
            )

    def test_clouds_yaml_file_with_no_region_raises_error(self, tmp_path):
        """Test that clouds.yaml file with neither region_name nor regions raises error."""
        clouds_yaml = tmp_path / "clouds.yaml"
        clouds_yaml.write_text(
            """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    identity_api_version: 3
"""
        )

        with pytest.raises(OpenStackNoRegionError):
            OpenstackProvider(
                clouds_yaml_file=str(clouds_yaml),
                clouds_yaml_cloud="test-cloud",
            )

    def test_session_as_sdk_config_with_regions_list(self):
        """Test OpenStackSession.as_sdk_config() with regions list uses first region."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="test-project",
            regions=["RegionOne", "RegionTwo"],
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config()

        # SDK does not iterate over regions automatically, so we pass the
        # first region as region_name for the default connection
        assert sdk_config["region_name"] == "RegionOne"
        assert "regions" not in sdk_config

    def test_session_as_sdk_config_with_region_name(self):
        """Test OpenStackSession.as_sdk_config() with single region_name."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="test-project",
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config()

        assert sdk_config["region_name"] == "RegionOne"
        assert "regions" not in sdk_config


class TestOpenstackProviderIdValidation:
    """Test suite for OpenStack Provider ID validation."""

    @pytest.fixture(autouse=True)
    def clean_openstack_env(self, monkeypatch):
        """Ensure clean OpenStack environment for all tests."""
        openstack_env_vars = [
            "OS_AUTH_URL",
            "OS_USERNAME",
            "OS_PASSWORD",
            "OS_PROJECT_ID",
            "OS_REGION_NAME",
            "OS_CLOUD",
            "OS_IDENTITY_API_VERSION",
            "OS_USER_DOMAIN_NAME",
            "OS_PROJECT_DOMAIN_NAME",
        ]
        for env_var in openstack_env_vars:
            monkeypatch.delenv(env_var, raising=False)

    def test_test_connection_provider_id_matches(self):
        """Test test_connection succeeds when provider_id matches project_id."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            connection_result = OpenstackProvider.test_connection(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="test-project-id",
                region_name="RegionOne",
                provider_id="test-project-id",
                raise_on_exception=False,
            )

            assert connection_result.is_connected is True
            assert connection_result.error is None

    def test_test_connection_provider_id_does_not_match(self):
        """Test test_connection fails when provider_id doesn't match project_id."""
        connection_result = OpenstackProvider.test_connection(
            auth_url="https://openstack.example.com:5000/v3",
            username="test-user",
            password="test-password",
            project_id="actual-project-id",
            region_name="RegionOne",
            provider_id="different-project-id",
            raise_on_exception=False,
        )

        assert connection_result.is_connected is False
        assert isinstance(connection_result.error, OpenStackInvalidProviderIdError)

    def test_test_connection_provider_id_mismatch_raises(self):
        """Test test_connection raises when provider_id doesn't match and raise_on_exception=True."""
        with pytest.raises(OpenStackInvalidProviderIdError) as excinfo:
            OpenstackProvider.test_connection(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="actual-project-id",
                region_name="RegionOne",
                provider_id="different-project-id",
                raise_on_exception=True,
            )

        assert "different-project-id" in str(excinfo.value)
        assert "actual-project-id" in str(excinfo.value)

    def test_test_connection_no_provider_id_skips_validation(self):
        """Test test_connection skips provider_id validation when not provided."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            connection_result = OpenstackProvider.test_connection(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="test-project-id",
                region_name="RegionOne",
                raise_on_exception=False,
            )

            assert connection_result.is_connected is True

    def test_test_connection_provider_id_with_clouds_yaml_content(self):
        """Test test_connection validates provider_id against clouds.yaml content project_id."""
        clouds_yaml_content = """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: yaml-project-id
    region_name: RegionOne
"""
        connection_result = OpenstackProvider.test_connection(
            clouds_yaml_content=clouds_yaml_content,
            clouds_yaml_cloud="test-cloud",
            provider_id="wrong-project-id",
            raise_on_exception=False,
        )

        assert connection_result.is_connected is False
        assert isinstance(connection_result.error, OpenStackInvalidProviderIdError)

    def test_test_connection_region_error_surfaced(self):
        """Test test_connection surfaces region validation errors."""
        clouds_yaml_content = """
clouds:
  test-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    identity_api_version: 3
"""
        connection_result = OpenstackProvider.test_connection(
            clouds_yaml_content=clouds_yaml_content,
            clouds_yaml_cloud="test-cloud",
            raise_on_exception=False,
        )

        assert connection_result.is_connected is False
        assert isinstance(connection_result.error, OpenStackNoRegionError)


class TestOpenstackProviderRegionalConnections:
    """Test suite for OpenStack Provider regional_connections."""

    @pytest.fixture(autouse=True)
    def clean_openstack_env(self, monkeypatch):
        """Ensure clean OpenStack environment for all tests."""
        openstack_env_vars = [
            "OS_AUTH_URL",
            "OS_USERNAME",
            "OS_PASSWORD",
            "OS_PROJECT_ID",
            "OS_REGION_NAME",
            "OS_CLOUD",
            "OS_IDENTITY_API_VERSION",
            "OS_USER_DOMAIN_NAME",
            "OS_PROJECT_DOMAIN_NAME",
        ]
        for env_var in openstack_env_vars:
            monkeypatch.delenv(env_var, raising=False)

    def test_single_region_regional_connections(self):
        """Test regional_connections has one entry for single-region provider."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = "test-project"
        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(
                auth_url="https://openstack.example.com:5000/v3",
                username="test-user",
                password="test-password",
                project_id="test-project",
                region_name="RegionOne",
            )

            assert len(provider.regional_connections) == 1
            assert "RegionOne" in provider.regional_connections
            assert provider.regional_connections["RegionOne"] is provider.connection
            mock_connect.assert_called_once()

    def test_multi_region_regional_connections(self):
        """Test regional_connections has entries for each region in multi-region setup."""
        mock_conn_region1 = MagicMock()
        mock_conn_region1.authorize.return_value = None
        mock_conn_region1.current_user_id = None
        mock_conn_region1.current_project_id = "test-project-id"
        mock_conn_region1.identity.get_project.return_value = None

        mock_conn_region2 = MagicMock()
        mock_conn_region2.authorize.return_value = None

        clouds_yaml_content = """
clouds:
  multi-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    regions:
      - UK1
      - DE1
    identity_api_version: 3
"""
        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.side_effect = [mock_conn_region1, mock_conn_region2]

            provider = OpenstackProvider(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud="multi-cloud",
            )

            assert len(provider.regional_connections) == 2
            assert "UK1" in provider.regional_connections
            assert "DE1" in provider.regional_connections
            assert provider.regional_connections["UK1"] is mock_conn_region1
            assert provider.regional_connections["DE1"] is mock_conn_region2
            # Default connection should be the first region
            assert provider.connection is mock_conn_region1
            assert mock_connect.call_count == 2

    def test_multi_region_test_connection_tests_all_regions(self):
        """Test test_connection tests connectivity to every region."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        clouds_yaml_content = """
clouds:
  multi-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    regions:
      - UK1
      - DE1
    identity_api_version: 3
"""
        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            result = OpenstackProvider.test_connection(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud="multi-cloud",
                raise_on_exception=False,
            )

            assert result.is_connected is True
            # Should have called connect once per region
            assert mock_connect.call_count == 2

    def test_multi_region_test_connection_fails_if_one_region_fails(self):
        """Test test_connection fails if any region fails."""
        mock_conn_ok = MagicMock()
        mock_conn_ok.authorize.return_value = None

        mock_conn_fail = MagicMock()
        mock_conn_fail.authorize.side_effect = openstack_exceptions.SDKException(
            "Connection failed in DE1"
        )

        clouds_yaml_content = """
clouds:
  multi-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    regions:
      - UK1
      - DE1
    identity_api_version: 3
"""
        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.side_effect = [mock_conn_ok, mock_conn_fail]

            result = OpenstackProvider.test_connection(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud="multi-cloud",
                raise_on_exception=False,
            )

            assert result.is_connected is False

    def test_session_as_sdk_config_region_override(self):
        """Test as_sdk_config with region_override overrides region_name."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="test-project",
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config(region_override="RegionTwo")
        assert sdk_config["region_name"] == "RegionTwo"

    def test_session_as_sdk_config_region_override_with_regions_list(self):
        """Test as_sdk_config with region_override overrides regions list."""
        session = OpenStackSession(
            auth_url="https://openstack.example.com:5000/v3",
            identity_api_version="3",
            username="test-user",
            password="test-password",
            project_id="test-project",
            regions=["UK1", "DE1"],
            user_domain_name="Default",
            project_domain_name="Default",
        )

        sdk_config = session.as_sdk_config(region_override="DE1")
        assert sdk_config["region_name"] == "DE1"

    def test_multi_region_test_connection_provider_id_matches(self):
        """Test test_connection validates provider_id in multi-region setup."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        clouds_yaml_content = """
clouds:
  multi-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: test-project-id
    regions:
      - UK1
      - DE1
    identity_api_version: 3
"""
        with patch(
            "prowler.providers.openstack.openstack_provider.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            result = OpenstackProvider.test_connection(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud="multi-cloud",
                provider_id="test-project-id",
                raise_on_exception=False,
            )

            assert result.is_connected is True

    def test_multi_region_test_connection_provider_id_mismatch(self):
        """Test test_connection fails when provider_id doesn't match in multi-region."""
        clouds_yaml_content = """
clouds:
  multi-cloud:
    auth:
      auth_url: https://openstack.example.com:5000/v3
      username: test-user
      password: test-password
      project_id: actual-project-id
    regions:
      - UK1
      - DE1
    identity_api_version: 3
"""
        result = OpenstackProvider.test_connection(
            clouds_yaml_content=clouds_yaml_content,
            clouds_yaml_cloud="multi-cloud",
            provider_id="wrong-project-id",
            raise_on_exception=False,
        )

        assert result.is_connected is False
        assert isinstance(result.error, OpenStackInvalidProviderIdError)
