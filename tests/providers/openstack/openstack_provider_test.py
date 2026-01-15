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
from prowler.providers.openstack.models import OpenStackIdentityInfo, OpenStackSession
from prowler.providers.openstack.openstack_provider import OpenstackProvider


class TestOpenstackProvider:
    """Test suite for OpenStack Provider initialization."""

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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()

            assert provider.session.auth_url == auth_url
            assert provider.session.username == username
            assert provider.session.project_id == project_id
            assert provider.session.region_name == region_name
            assert provider.identity.username == username

    def test_openstack_provider_with_tenant_id(self, monkeypatch):
        """Test OpenStack provider initialization using OS_TENANT_ID instead of OS_PROJECT_ID."""
        auth_url = "https://openstack.example.com:5000/v3"
        username = "test-user"
        password = "test-password"
        tenant_id = "test-tenant-id"
        region_name = "RegionOne"

        monkeypatch.setenv("OS_AUTH_URL", auth_url)
        monkeypatch.setenv("OS_USERNAME", username)
        monkeypatch.setenv("OS_PASSWORD", password)
        monkeypatch.setenv("OS_TENANT_ID", tenant_id)
        monkeypatch.setenv("OS_REGION_NAME", region_name)

        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None
        mock_connection.current_user_id = None
        mock_connection.current_project_id = tenant_id

        mock_connection.identity.get_project.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.openstack.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider()

            assert provider.session.project_id == tenant_id

    def test_openstack_provider_missing_auth_url(self):
        """Test OpenStack provider initialization fails when OS_AUTH_URL is missing."""
        with pytest.raises(RuntimeError) as excinfo:
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

        with pytest.raises(RuntimeError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_USERNAME" in str(excinfo.value)

    def test_openstack_provider_missing_password(self, monkeypatch):
        """Test OpenStack provider initialization fails when OS_PASSWORD is missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        with pytest.raises(RuntimeError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_PASSWORD" in str(excinfo.value)

    def test_openstack_provider_missing_project_id(self, monkeypatch):
        """Test OpenStack provider initialization fails when both OS_PROJECT_ID and OS_TENANT_ID are missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_REGION_NAME", "RegionOne")

        with pytest.raises(RuntimeError) as excinfo:
            OpenstackProvider()

        assert "Missing mandatory OpenStack environment variables" in str(excinfo.value)
        assert "OS_PROJECT_ID/OS_TENANT_ID" in str(excinfo.value)

    def test_openstack_provider_missing_region(self, monkeypatch):
        """Test OpenStack provider initialization fails when OS_REGION_NAME is missing."""
        monkeypatch.setenv("OS_AUTH_URL", "https://openstack.example.com:5000/v3")
        monkeypatch.setenv("OS_USERNAME", "test-user")
        monkeypatch.setenv("OS_PASSWORD", "test-password")
        monkeypatch.setenv("OS_PROJECT_ID", "test-project")

        with pytest.raises(RuntimeError) as excinfo:
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
        ) as mock_connect:
            mock_connect.side_effect = openstack_exceptions.SDKException(
                "Connection failed"
            )

            with pytest.raises(openstack_exceptions.SDKException):
                OpenstackProvider()

    def test_openstack_provider_static_test_connection_success(self):
        """Test static test_connection method with valid credentials."""
        mock_connection = MagicMock()
        mock_connection.authorize.return_value = None

        with patch(
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            with pytest.raises(openstack_exceptions.SDKException):
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
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
            "prowler.providers.openstack.openstack_provider.openstack.connect"
        ) as mock_connect:
            mock_connect.return_value = mock_connection

            provider = OpenstackProvider(mutelist_content=mutelist_content)

            assert provider.mutelist is not None

    def test_openstack_session_as_sdk_config(self):
        """Test OpenStackSession.as_sdk_config() returns correct dictionary."""
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
        assert sdk_config["project_id"] == "test-project"
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
