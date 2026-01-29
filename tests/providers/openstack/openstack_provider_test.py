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
    OpenStackAuthenticationError,
    OpenStackCloudNotFoundError,
    OpenStackConfigFileNotFoundError,
    OpenStackCredentialsError,
    OpenStackInvalidConfigError,
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
