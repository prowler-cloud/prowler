import os
from unittest.mock import patch
from uuid import uuid4

import pytest
from azure.core.credentials import AccessToken
from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)
from mock import MagicMock

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.m365.exceptions.exceptions import (
    M365HTTPResponseError,
    M365MissingEnvironmentCredentialsError,
    M365NoAuthenticationMethodError,
    M365NotValidEncryptedPasswordError,
    M365NotValidUserError,
    M365UserNotBelongingToTenantError,
)
from prowler.providers.m365.m365_provider import M365Provider
from prowler.providers.m365.models import (
    M365Credentials,
    M365IdentityInfo,
    M365RegionConfig,
)
from tests.providers.m365.m365_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    DOMAIN,
    IDENTITY_ID,
    IDENTITY_TYPE,
    LOCATION,
    TENANT_ID,
)


class TestM365Provider:
    def test_m365_provider(self):
        tenant_id = None
        client_id = None
        client_secret = None

        fixer_config = load_and_validate_config_file(
            "m365", default_fixer_config_file_path
        )
        azure_region = "M365Global"

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                return_value=ClientSecretCredential(
                    client_id=CLIENT_ID,
                    tenant_id=TENANT_ID,
                    client_secret=CLIENT_SECRET,
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type=IDENTITY_TYPE,
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                ),
            ),
        ):
            m365_provider = M365Provider(
                sp_env_auth=True,
                az_cli_auth=False,
                browser_auth=False,
                env_auth=False,
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                region=azure_region,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
            )

            assert m365_provider.region_config == M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )
            assert m365_provider.identity == M365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type=IDENTITY_TYPE,
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                location=LOCATION,
            )

    def test_m365_provider_env_auth(self):
        tenant_id = None
        client_id = None
        client_secret = None

        fixer_config = load_and_validate_config_file(
            "m365", default_fixer_config_file_path
        )
        azure_region = "M365Global"

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                return_value=ClientSecretCredential(
                    client_id=CLIENT_ID,
                    tenant_id=TENANT_ID,
                    client_secret=CLIENT_SECRET,
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type=IDENTITY_TYPE,
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_powershell",
                return_value=M365Credentials(
                    user="test@test.com",
                    passwd="password",
                ),
            ),
        ):
            m365_provider = M365Provider(
                sp_env_auth=False,
                az_cli_auth=False,
                browser_auth=False,
                env_auth=True,
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                region=azure_region,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
            )

            assert m365_provider.region_config == M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )
            assert m365_provider.identity == M365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type=IDENTITY_TYPE,
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                location=LOCATION,
            )

    def test_m365_provider_cli_auth(self):
        """Test M365 Provider initialization with CLI authentication"""
        azure_region = "M365Global"
        fixer_config = load_and_validate_config_file(
            "m365", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                return_value=DefaultAzureCredential(
                    exclude_environment_credential=True,
                    exclude_cli_credential=False,
                    exclude_managed_identity_credential=True,
                    exclude_visual_studio_code_credential=True,
                    exclude_shared_token_cache_credential=True,
                    exclude_powershell_credential=True,
                    exclude_browser_credential=True,
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                ),
            ),
        ):
            m365_provider = M365Provider(
                sp_env_auth=False,
                az_cli_auth=True,
                browser_auth=False,
                env_auth=False,
                region=azure_region,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
            )

            assert m365_provider.region_config == M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )
            assert m365_provider.identity == M365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type="User",
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                location=LOCATION,
            )
            assert isinstance(m365_provider.session, DefaultAzureCredential)

    def test_m365_provider_browser_auth(self):
        """Test M365 Provider initialization with Browser authentication"""
        azure_region = "M365Global"
        fixer_config = load_and_validate_config_file(
            "m365", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                return_value=InteractiveBrowserCredential(
                    tenant_id=TENANT_ID,
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                ),
            ),
        ):
            m365_provider = M365Provider(
                sp_env_auth=False,
                az_cli_auth=False,
                browser_auth=True,
                env_auth=False,
                tenant_id=TENANT_ID,
                region=azure_region,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
            )

            assert m365_provider.region_config == M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )
            assert m365_provider.identity == M365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type="User",
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                location=LOCATION,
            )
            assert isinstance(m365_provider.session, InteractiveBrowserCredential)

    def test_test_connection_browser_auth(self):
        with (
            patch(
                "prowler.providers.m365.m365_provider.DefaultAzureCredential"
            ) as mock_default_credential,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.GraphServiceClient"
            ) as mock_graph_client,
        ):
            # Mock the return value of DefaultAzureCredential
            mock_credentials = MagicMock()
            mock_credentials.get_token.return_value = AccessToken(
                token="fake_token", expires_on=9999999999
            )
            mock_default_credential.return_value = mock_credentials

            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock GraphServiceClient to avoid real API calls
            mock_client = MagicMock()
            mock_graph_client.return_value = mock_client

            test_connection = M365Provider.test_connection(
                browser_auth=True,
                tenant_id=str(uuid4()),
                region="M365Global",
                raise_on_exception=False,
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_tenant_id_client_id_client_secret(self):
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
            ) as mock_validate_static_credentials,
        ):
            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            test_connection = M365Provider.test_connection(
                tenant_id=str(uuid4()),
                region="M365Global",
                raise_on_exception=False,
                client_id=str(uuid4()),
                client_secret=str(uuid4()),
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_tenant_id_client_id_client_secret_no_user_encrypted_password(
        self,
    ):
        with patch(
            "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:
            mock_validate_static_credentials.side_effect = M365NotValidUserError(
                file=os.path.basename(__file__),
                message="The provided M365 User is not valid.",
            )

            with pytest.raises(M365NotValidUserError) as exception:
                M365Provider.test_connection(
                    tenant_id=str(uuid4()),
                    region="M365Global",
                    raise_on_exception=True,
                    client_id=str(uuid4()),
                    client_secret=str(uuid4()),
                    user=None,
                    encrypted_password="test_password",
                )

            assert exception.type == M365NotValidUserError
            assert "The provided M365 User is not valid." in str(exception.value)

    def test_test_connection_tenant_id_client_id_client_secret_user_no_encrypted_password(
        self,
    ):
        with patch(
            "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:
            mock_validate_static_credentials.side_effect = (
                M365NotValidEncryptedPasswordError(
                    file=os.path.basename(__file__),
                    message="The provided M365 Encrypted Password is not valid.",
                )
            )

            with pytest.raises(M365NotValidEncryptedPasswordError) as exception:
                M365Provider.test_connection(
                    tenant_id=str(uuid4()),
                    region="M365Global",
                    raise_on_exception=True,
                    client_id=str(uuid4()),
                    client_secret=str(uuid4()),
                    user="test@example.com",
                    encrypted_password=None,
                )

            assert exception.type == M365NotValidEncryptedPasswordError
            assert "The provided M365 Encrypted Password is not valid." in str(
                exception.value
            )

    def test_test_connection_with_httpresponseerror(self):
        with patch(
            "prowler.providers.m365.m365_provider.M365Provider.setup_session"
        ) as mock_setup_session:
            mock_setup_session.side_effect = M365HTTPResponseError(
                file="test_file", original_exception="Simulated HttpResponseError"
            )

            with pytest.raises(M365HTTPResponseError) as exception:
                M365Provider.test_connection(
                    az_cli_auth=True,
                    raise_on_exception=True,
                )

            assert exception.type == M365HTTPResponseError
            assert (
                exception.value.args[0]
                == "[6003] Error in HTTP response from Microsoft 365 - Simulated HttpResponseError"
            )

    def test_test_connection_with_exception(self):
        with patch(
            "prowler.providers.m365.m365_provider.M365Provider.setup_session"
        ) as mock_setup_session:
            mock_setup_session.side_effect = Exception("Simulated Exception")

            with pytest.raises(Exception) as exception:
                M365Provider.test_connection(
                    sp_env_auth=True,
                    raise_on_exception=True,
                )

            assert exception.type is Exception
            assert exception.value.args[0] == "Simulated Exception"

    def test_test_connection_without_any_method(self):
        with pytest.raises(M365NoAuthenticationMethodError) as exception:
            M365Provider.test_connection()

        assert exception.type == M365NoAuthenticationMethodError
        assert (
            "M365 provider requires at least one authentication method set: [--env-auth | --az-cli-auth | --sp-env-auth | --browser-auth]"
            in exception.value.args[0]
        )

    def test_setup_powershell_valid_credentials(self):
        credentials_dict = {
            "user": "test@example.com",
            "encrypted_password": "test_password",
            "client_id": "test_client_id",
            "tenant_id": "test_tenant_id",
            "client_secret": "test_client_secret",
        }

        with patch(
            "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
            return_value=True,
        ):
            result = M365Provider.setup_powershell(
                env_auth=False, m365_credentials=credentials_dict
            )

            assert result.user == credentials_dict["user"]
            assert result.passwd == credentials_dict["encrypted_password"]

    def test_setup_powershell_invalid_env_credentials(self):
        credentials = None

        with patch(
            "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell"
        ) as mock_powershell:
            mock_session = MagicMock()
            mock_session.test_credentials.return_value = False
            mock_powershell.return_value = mock_session

            with pytest.raises(M365MissingEnvironmentCredentialsError) as exc_info:
                M365Provider.setup_powershell(
                    env_auth=True, m365_credentials=credentials
                )

            assert (
                "Missing M365_USER or M365_ENCRYPTED_PASSWORD environment variables required for credentials authentication"
                in str(exc_info.value)
            )
            mock_session.test_credentials.assert_not_called()

    def test_test_connection_user_not_belonging_to_tenant(
        self,
    ):
        with patch(
            "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:
            mock_validate_static_credentials.side_effect = M365UserNotBelongingToTenantError(
                file=os.path.basename(__file__),
                message="The provided M365 User does not belong to the specified tenant.",
            )

            with pytest.raises(M365UserNotBelongingToTenantError) as exception:
                M365Provider.test_connection(
                    tenant_id="contoso.onmicrosoft.com",
                    region="M365Global",
                    raise_on_exception=True,
                    client_id=str(uuid4()),
                    client_secret=str(uuid4()),
                    user="user@otherdomain.com",
                    encrypted_password="test_password",
                )

            assert exception.type == M365UserNotBelongingToTenantError
            assert (
                "The provided M365 User does not belong to the specified tenant."
                in str(exception.value)
            )
