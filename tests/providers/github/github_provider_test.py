from unittest.mock import MagicMock, patch

import pytest

from prowler.config.config import (
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.github.exceptions.exceptions import (
    GithubEnvironmentVariableError,
    GithubInvalidCredentialsError,
    GithubInvalidProviderIdError,
    GithubInvalidTokenError,
    GithubSetUpIdentityError,
    GithubSetUpSessionError,
)
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.models import (
    GithubAppIdentityInfo,
    GithubIdentityInfo,
    GithubSession,
)
from tests.providers.github.github_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    ACCOUNT_URL,
    APP_ID,
    APP_KEY,
    OAUTH_TOKEN,
    PAT_TOKEN,
)


class TestGitHubProvider:
    def test_github_provider_PAT(self):
        personal_access_token = PAT_TOKEN
        oauth_app_token = None
        github_app_id = None
        github_app_key = None
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
        ):
            provider = GithubProvider(
                personal_access_token,
                oauth_app_token,
                github_app_id,
                github_app_key,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token=PAT_TOKEN, id="", key="")
            assert provider.identity == GithubIdentityInfo(
                account_name=ACCOUNT_NAME,
                account_id=ACCOUNT_ID,
                account_url=ACCOUNT_URL,
            )
            assert provider._audit_config == {
                "inactive_not_archived_days_threshold": 180,
            }
            assert provider._fixer_config == fixer_config

    def test_github_provider_OAuth(self):
        personal_access_token = None
        oauth_app_token = OAUTH_TOKEN
        github_app_id = None
        github_app_key = None
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=OAUTH_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
        ):
            provider = GithubProvider(
                personal_access_token,
                oauth_app_token,
                github_app_id,
                github_app_key,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token=OAUTH_TOKEN, id="", key="")
            assert provider.identity == GithubIdentityInfo(
                account_name=ACCOUNT_NAME,
                account_id=ACCOUNT_ID,
                account_url=ACCOUNT_URL,
            )
            assert provider._audit_config == {
                "inactive_not_archived_days_threshold": 180,
            }
            assert provider._fixer_config == fixer_config

    def test_github_provider_App(self):
        personal_access_token = None
        oauth_app_token = None
        github_app_id = APP_ID
        github_app_key = APP_KEY
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="", id=APP_ID, key=APP_KEY),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubAppIdentityInfo(
                    app_id=APP_ID,
                ),
            ),
        ):
            provider = GithubProvider(
                personal_access_token,
                oauth_app_token,
                github_app_id,
                github_app_key,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token="", id=APP_ID, key=APP_KEY)
            assert provider.identity == GithubAppIdentityInfo(app_id=APP_ID)
            assert provider._audit_config == {
                "inactive_not_archived_days_threshold": 180,
            }
            assert provider._fixer_config == fixer_config

    def test_test_connection_with_personal_access_token_success(self):
        """Test successful connection with personal access token."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
        ):
            connection = GithubProvider.test_connection(personal_access_token=PAT_TOKEN)

            assert isinstance(connection, Connection)
            assert connection.is_connected is True
            assert connection.error is None

    def test_test_connection_with_oauth_app_token_success(self):
        """Test successful connection with OAuth app token."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=OAUTH_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
        ):
            connection = GithubProvider.test_connection(oauth_app_token=OAUTH_TOKEN)

            assert isinstance(connection, Connection)
            assert connection.is_connected is True
            assert connection.error is None

    def test_test_connection_with_github_app_success(self):
        """Test successful connection with GitHub App credentials."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="", id=APP_ID, key=APP_KEY),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubAppIdentityInfo(app_id=APP_ID),
            ),
        ):
            connection = GithubProvider.test_connection(
                github_app_id=APP_ID, github_app_key=APP_KEY
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is True
            assert connection.error is None

    def test_test_connection_with_invalid_token_raises_exception(self):
        """Test connection with invalid token raises exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="invalid-token", id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                side_effect=GithubInvalidTokenError(
                    original_exception=Exception("Invalid token")
                ),
            ),
        ):
            with pytest.raises(GithubInvalidTokenError):
                GithubProvider.test_connection(personal_access_token="invalid-token")

    def test_test_connection_with_invalid_token_no_raise(self):
        """Test connection with invalid token without raising exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="invalid-token", id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                side_effect=GithubInvalidTokenError(
                    original_exception=Exception("Invalid token")
                ),
            ),
        ):
            connection = GithubProvider.test_connection(
                personal_access_token="invalid-token", raise_on_exception=False
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, GithubInvalidTokenError)

    def test_test_connection_with_invalid_app_credentials_raises_exception(self):
        """Test connection with invalid GitHub App credentials raises exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="", id=APP_ID, key="invalid-key"),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                side_effect=GithubInvalidCredentialsError(
                    original_exception=Exception("Invalid credentials")
                ),
            ),
        ):
            with pytest.raises(GithubInvalidCredentialsError):
                GithubProvider.test_connection(
                    github_app_id=APP_ID, github_app_key="invalid-key"
                )

    def test_test_connection_with_invalid_app_credentials_no_raise(self):
        """Test connection with invalid GitHub App credentials without raising exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="", id=APP_ID, key="invalid-key"),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                side_effect=GithubInvalidCredentialsError(
                    original_exception=Exception("Invalid credentials")
                ),
            ),
        ):
            connection = GithubProvider.test_connection(
                github_app_id=APP_ID,
                github_app_key="invalid-key",
                raise_on_exception=False,
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, GithubInvalidCredentialsError)

    def test_test_connection_setup_session_error_raises_exception(self):
        """Test connection when setup_session raises an exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                side_effect=GithubSetUpSessionError(
                    original_exception=Exception("Setup error")
                ),
            ),
            patch("prowler.providers.github.github_provider.logger") as mock_logger,
        ):
            with pytest.raises(GithubSetUpSessionError):
                GithubProvider.test_connection(personal_access_token=PAT_TOKEN)

            mock_logger.critical.assert_called_once()

    def test_test_connection_setup_session_error_no_raise(self):
        """Test connection when setup_session raises an exception without raising."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                side_effect=GithubSetUpSessionError(
                    original_exception=Exception("Setup error")
                ),
            ),
            patch("prowler.providers.github.github_provider.logger") as mock_logger,
        ):
            connection = GithubProvider.test_connection(
                personal_access_token=PAT_TOKEN, raise_on_exception=False
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, GithubSetUpSessionError)
            mock_logger.critical.assert_called_once()

    def test_test_connection_environment_variable_error_raises_exception(self):
        """Test connection when environment variable error occurs."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                side_effect=GithubEnvironmentVariableError(
                    file="test_file.py", message="Env error"
                ),
            ),
            patch("prowler.providers.github.github_provider.logger") as mock_logger,
        ):
            with pytest.raises(GithubEnvironmentVariableError):
                GithubProvider.test_connection(personal_access_token=PAT_TOKEN)

            mock_logger.critical.assert_called_once()

    def test_test_connection_environment_variable_error_no_raise(self):
        """Test connection when environment variable error occurs without raising."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                side_effect=GithubEnvironmentVariableError(
                    file="test_file.py", message="Env error"
                ),
            ),
            patch("prowler.providers.github.github_provider.logger") as mock_logger,
        ):
            connection = GithubProvider.test_connection(
                personal_access_token=PAT_TOKEN, raise_on_exception=False
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, GithubEnvironmentVariableError)
            mock_logger.critical.assert_called_once()

    def test_test_connection_setup_identity_error_raises_exception(self):
        """Test connection when setup_identity raises an exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                side_effect=GithubSetUpIdentityError(
                    original_exception=Exception("Identity error")
                ),
            ),
        ):
            with pytest.raises(GithubSetUpIdentityError):
                GithubProvider.test_connection(personal_access_token=PAT_TOKEN)

    def test_test_connection_setup_identity_error_no_raise(self):
        """Test connection when setup_identity raises an exception without raising."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                side_effect=GithubSetUpIdentityError(
                    original_exception=Exception("Identity error")
                ),
            ),
        ):
            connection = GithubProvider.test_connection(
                personal_access_token=PAT_TOKEN, raise_on_exception=False
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, GithubSetUpIdentityError)

    def test_test_connection_generic_exception_raises_exception(self):
        """Test connection when a generic exception occurs."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                side_effect=Exception("Generic error"),
            ),
            patch("prowler.providers.github.github_provider.logger") as mock_logger,
        ):
            with pytest.raises(Exception) as exc_info:
                GithubProvider.test_connection(personal_access_token=PAT_TOKEN)

            assert str(exc_info.value) == "Generic error"
            mock_logger.critical.assert_called_once()

    def test_test_connection_generic_exception_no_raise(self):
        """Test connection when a generic exception occurs without raising."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                side_effect=Exception("Generic error"),
            ),
            patch("prowler.providers.github.github_provider.logger") as mock_logger,
        ):
            connection = GithubProvider.test_connection(
                personal_access_token=PAT_TOKEN, raise_on_exception=False
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, Exception)
            assert str(connection.error) == "Generic error"
            mock_logger.critical.assert_called_once()

    def test_test_connection_with_provider_id(self):
        """Test connection with provider_id parameter (should validate provider ID)."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.validate_provider_id",
                return_value=None,
            ),
        ):
            connection = GithubProvider.test_connection(
                personal_access_token=PAT_TOKEN, provider_id="test-org"
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is True
            assert connection.error is None

    def test_test_connection_with_invalid_provider_id_raises_exception(self):
        """Test connection with invalid provider_id raises exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.validate_provider_id",
                side_effect=GithubInvalidProviderIdError(
                    file="test_file.py", message="Invalid provider ID"
                ),
            ),
        ):
            with pytest.raises(GithubInvalidProviderIdError):
                GithubProvider.test_connection(
                    personal_access_token=PAT_TOKEN, provider_id="invalid-org"
                )

    def test_test_connection_with_invalid_provider_id_no_raise(self):
        """Test connection with invalid provider_id without raising exception."""
        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.validate_provider_id",
                side_effect=GithubInvalidProviderIdError(
                    file="test_file.py", message="Invalid provider ID"
                ),
            ),
        ):
            connection = GithubProvider.test_connection(
                personal_access_token=PAT_TOKEN,
                provider_id="invalid-org",
                raise_on_exception=False,
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert isinstance(connection.error, GithubInvalidProviderIdError)

    def test_validate_provider_id_with_valid_user(self):
        """Test validate_provider_id with valid user (matches authenticated user)."""
        mock_session = GithubSession(token=PAT_TOKEN, id="", key="")

        with (
            patch("prowler.providers.github.github_provider.Auth.Token"),
            patch("prowler.providers.github.github_provider.Github") as mock_github,
            patch("prowler.providers.github.github_provider.GithubRetry"),
        ):
            # Mock the GitHub client and user
            mock_user = MagicMock()
            mock_user.login = "test-user"
            mock_github_instance = MagicMock()
            mock_github_instance.get_user.return_value = mock_user
            mock_github.return_value = mock_github_instance

            # Should not raise an exception
            GithubProvider.validate_provider_id(mock_session, "test-user")

    def test_validate_provider_id_with_valid_organization(self):
        """Test validate_provider_id with valid organization."""
        mock_session = GithubSession(token=PAT_TOKEN, id="", key="")

        with (
            patch("prowler.providers.github.github_provider.Auth.Token"),
            patch("prowler.providers.github.github_provider.Github") as mock_github,
            patch("prowler.providers.github.github_provider.GithubRetry"),
        ):
            # Mock the GitHub client and user
            mock_user = MagicMock()
            mock_user.login = "test-user"
            mock_github_instance = MagicMock()
            mock_github_instance.get_user.return_value = mock_user
            mock_github_instance.get_organization.return_value = (
                MagicMock()
            )  # Organization exists
            mock_github.return_value = mock_github_instance

            # Should not raise an exception
            GithubProvider.validate_provider_id(mock_session, "test-org")

    def test_validate_provider_id_with_invalid_provider_id(self):
        """Test validate_provider_id with invalid provider ID."""
        mock_session = GithubSession(token=PAT_TOKEN, id="", key="")

        with (
            patch("prowler.providers.github.github_provider.Auth.Token"),
            patch("prowler.providers.github.github_provider.Github") as mock_github,
            patch("prowler.providers.github.github_provider.GithubRetry"),
        ):
            # Mock the GitHub client and user
            mock_user = MagicMock()
            mock_user.login = "test-user"
            mock_github_instance = MagicMock()
            mock_github_instance.get_user.return_value = mock_user
            mock_github_instance.get_organization.side_effect = Exception("Not found")
            mock_github_instance.get_user.side_effect = [
                mock_user,
                Exception("Not found"),
            ]
            mock_github.return_value = mock_github_instance

            with pytest.raises(GithubInvalidProviderIdError):
                GithubProvider.validate_provider_id(mock_session, "invalid-provider")

    def test_validate_provider_id_with_github_app(self):
        """Test validate_provider_id with GitHub App credentials."""
        mock_session = GithubSession(token="", id=APP_ID, key=APP_KEY)

        with (
            patch("prowler.providers.github.github_provider.Auth.AppAuth"),
            patch(
                "prowler.providers.github.github_provider.GithubIntegration"
            ) as mock_integration,
            patch("prowler.providers.github.github_provider.GithubRetry"),
        ):
            # Mock the GitHub integration and installations
            mock_installation = MagicMock()
            mock_installation.raw_data = {"account": {"login": "test-org"}}
            mock_integration_instance = MagicMock()
            mock_integration_instance.get_installations.return_value = [
                mock_installation
            ]
            mock_integration.return_value = mock_integration_instance

            # Should not raise an exception
            GithubProvider.validate_provider_id(mock_session, "test-org")

    def test_validate_provider_id_with_github_app_invalid_org(self):
        """Test validate_provider_id with GitHub App credentials and invalid organization."""
        mock_session = GithubSession(token="", id=APP_ID, key=APP_KEY)

        with (
            patch("prowler.providers.github.github_provider.Auth.AppAuth"),
            patch(
                "prowler.providers.github.github_provider.GithubIntegration"
            ) as mock_integration,
            patch("prowler.providers.github.github_provider.GithubRetry"),
        ):
            # Mock the GitHub integration and installations
            mock_installation = MagicMock()
            mock_installation.raw_data = {"account": {"login": "other-org"}}
            mock_integration_instance = MagicMock()
            mock_integration_instance.get_installations.return_value = [
                mock_installation
            ]
            mock_integration.return_value = mock_integration_instance

            with pytest.raises(GithubInvalidProviderIdError):
                GithubProvider.validate_provider_id(mock_session, "invalid-org")


class Test_GithubProvider_Scoping:
    def setup_method(self):
        """Setup mock session and identity for testing"""
        self.mock_session = GithubSession(
            token=PAT_TOKEN,
            key="",
            id=0,
        )
        self.mock_identity = GithubIdentityInfo(
            account_id=ACCOUNT_ID,
            account_name=ACCOUNT_NAME,
            account_url=ACCOUNT_URL,
        )

    def test_provider_scoping_integration(self):
        """Test that provider correctly handles scoping parameters and integrates with services"""
        repositories = ["owner1/repo1", "owner2/repo2"]
        organizations = ["org1", "org2"]

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=self.mock_session,
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=self.mock_identity,
            ),
        ):
            # Test with both scoping parameters
            provider = GithubProvider(
                personal_access_token=PAT_TOKEN,
                repositories=repositories,
                organizations=organizations,
            )

            assert provider.repositories == repositories
            assert provider.organizations == organizations
            assert provider.type == "github"
            assert provider.auth_method == "Personal Access Token"

            # Test with no scoping (backward compatibility)
            provider_no_scoping = GithubProvider(
                personal_access_token=PAT_TOKEN,
            )

            assert provider_no_scoping.repositories == []
            assert provider_no_scoping.organizations == []

            # Test with None values (should convert to empty lists)
            provider_none = GithubProvider(
                personal_access_token=PAT_TOKEN,
                repositories=None,
                organizations=None,
            )

            assert provider_none.repositories == []
            assert provider_none.organizations == []
