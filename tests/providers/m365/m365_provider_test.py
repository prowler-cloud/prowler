import base64
import os
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from azure.core.credentials import AccessToken
from azure.identity import (
    CertificateCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.m365.exceptions.exceptions import (
    M365BrowserAuthNoFlagError,
    M365BrowserAuthNoTenantIDError,
    M365ClientIdAndClientSecretNotBelongingToTenantIdError,
    M365ConfigCredentialsError,
    M365CredentialsUnavailableError,
    M365DefaultAzureCredentialError,
    M365EnvironmentVariableError,
    M365GetTokenIdentityError,
    M365HTTPResponseError,
    M365InvalidProviderIdError,
    M365MissingEnvironmentCredentialsError,
    M365NoAuthenticationMethodError,
    M365NotTenantIdButClientIdAndClientSecretError,
    M365NotValidClientIdError,
    M365NotValidClientSecretError,
    M365NotValidPasswordError,
    M365NotValidTenantIdError,
    M365NotValidUserError,
    M365TenantIdAndClientIdNotBelongingToClientSecretError,
    M365TenantIdAndClientSecretNotBelongingToClientIdError,
    M365UserCredentialsError,
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
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_powershell",
                return_value=M365Credentials(
                    client_id=CLIENT_ID,
                    tenant_id=TENANT_ID,
                    client_secret=CLIENT_SECRET,
                    user="",
                    passwd="",
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
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            ),
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

            # Mock GraphServiceClient
            mock_client = MagicMock()
            mock_graph_client.return_value = mock_client

            test_connection = M365Provider.test_connection(
                browser_auth=True,
                tenant_id=str(uuid4()),
                region="M365Global",
                raise_on_exception=False,
                provider_id="test.onmicrosoft.com",
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
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            ),
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
                provider_id="test.onmicrosoft.com",
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_tenant_id_client_id_client_secret_no_user_password(
        self,
    ):
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
            ) as mock_validate_static_credentials,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
        ):
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
                    password="test_password",
                )

            assert exception.type == M365NotValidUserError
            assert "The provided M365 User is not valid." in str(exception.value)

    def test_test_connection_tenant_id_client_id_client_secret_user_no_password(
        self,
    ):
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
            ) as mock_validate_static_credentials,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
        ):
            mock_validate_static_credentials.side_effect = M365NotValidPasswordError(
                file=os.path.basename(__file__),
                message="The provided M365 Password is not valid.",
            )

            with pytest.raises(M365NotValidPasswordError) as exception:
                M365Provider.test_connection(
                    tenant_id=str(uuid4()),
                    region="M365Global",
                    raise_on_exception=True,
                    client_id=str(uuid4()),
                    client_secret=str(uuid4()),
                    user="test@example.com",
                    password=None,
                )

            assert exception.type == M365NotValidPasswordError
            assert "The provided M365 Password is not valid." in str(exception.value)

    def test_test_connection_with_httpresponseerror(self):
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
        ):
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
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
        ):
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
            "M365 provider requires at least one authentication method set: [--env-auth | --az-cli-auth | --sp-env-auth | --browser-auth | --certificate-auth]"
            in exception.value.args[0]
        )

    def test_setup_powershell_valid_credentials(self):
        credentials_dict = {
            "user": "test@example.com",
            "password": "test_password",
            "client_id": "test_client_id",
            "tenant_id": "test_tenant_id",
            "client_secret": "test_client_secret",
        }

        with (
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
        ):
            result = M365Provider.setup_powershell(
                env_auth=False,
                m365_credentials=credentials_dict,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            )
            assert result.user == credentials_dict["user"]
            assert result.passwd == credentials_dict["password"]

    def test_test_connection_user_not_belonging_to_tenant(
        self,
    ):
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
            ) as mock_validate_static_credentials,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
        ):
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
                    password="test_password",
                )

            assert exception.type == M365UserNotBelongingToTenantError
            assert (
                "The provided M365 User does not belong to the specified tenant."
                in str(exception.value)
            )

    def test_validate_static_credentials_invalid_tenant_id(self):
        with pytest.raises(M365NotValidTenantIdError) as exception:
            M365Provider.validate_static_credentials(
                tenant_id="invalid-tenant-id",
                client_id="12345678-1234-5678-1234-567812345678",
                client_secret="test_secret",
                user="test@example.com",
                password="test_password",
            )
        assert "The provided Tenant ID is not valid." in str(exception.value)

    def test_validate_static_credentials_missing_client_id(self):
        with pytest.raises(M365NotValidClientIdError) as exception:
            M365Provider.validate_static_credentials(
                tenant_id="12345678-1234-5678-1234-567812345678",
                client_id="",
                client_secret="test_secret",
                user="test@example.com",
                password="test_password",
            )
        assert "The provided Client ID is not valid." in str(exception.value)

    def test_validate_static_credentials_missing_client_secret(self):
        with pytest.raises(M365NotValidClientSecretError) as exception:
            M365Provider.validate_static_credentials(
                tenant_id="12345678-1234-5678-1234-567812345678",
                client_id="12345678-1234-5678-1234-567812345678",
                client_secret="",
                user="test@example.com",
                password="test_password",
            )
        assert "The provided Client Secret is not valid." in str(exception.value)

    def test_validate_arguments_missing_env_credentials(self):
        with pytest.raises(M365ConfigCredentialsError) as exception:
            M365Provider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=True,
                browser_auth=False,
                certificate_auth=False,
                tenant_id="test_tenant_id",
                client_id="test_client_id",
                client_secret=None,
                user=None,
                password=None,
                certificate_content=None,
            )

        assert (
            "You must provide a valid set of credentials. Please check your credentials and try again."
            in str(exception.value)
        )

    def test_test_connection_invalid_provider_id(self):
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
            ) as mock_validate_static_credentials,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain="contoso.com",
                    tenant_domains=["contoso.com"],
                    location=LOCATION,
                ),
            ),
        ):
            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            user_domain = "contoso.com"
            provider_id = "Test.com"

            with pytest.raises(M365InvalidProviderIdError) as exception:
                M365Provider.test_connection(
                    tenant_id=str(uuid4()),
                    region="M365Global",
                    raise_on_exception=True,
                    client_id=str(uuid4()),
                    client_secret=str(uuid4()),
                    user=f"user@{user_domain}",
                    password="test_password",
                    provider_id=provider_id,
                )

            assert exception.type == M365InvalidProviderIdError
            assert (
                f"The provider ID {provider_id} does not match any of the service principal tenant domains: {user_domain}"
                in str(exception.value)
            )

    def test_provider_init_modules_false(self):
        """Test that initialize_m365_powershell_modules is not called when init_modules is False"""
        credentials_dict = {
            "user": "test@example.com",
            "password": "test_password",
            "client_id": "test_client_id",
            "tenant_id": "test_tenant_id",
            "client_secret": "test_client_secret",
        }

        with (
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
            patch(
                "prowler.providers.m365.m365_provider.initialize_m365_powershell_modules"
            ) as mock_init_modules,
        ):
            M365Provider.setup_powershell(
                env_auth=False,
                m365_credentials=credentials_dict,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
                init_modules=False,
            )
            mock_init_modules.assert_not_called()

    def test_provider_init_modules_true(self):
        """Test that initialize_m365_powershell_modules is called when init_modules is True"""
        credentials_dict = {
            "user": "test@example.com",
            "password": "test_password",
            "client_id": "test_client_id",
            "tenant_id": "test_tenant_id",
            "client_secret": "test_client_secret",
        }

        with (
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
            patch(
                "prowler.providers.m365.m365_provider.initialize_m365_powershell_modules"
            ) as mock_init_modules,
        ):
            M365Provider.setup_powershell(
                env_auth=False,
                m365_credentials=credentials_dict,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
                init_modules=True,
            )
            mock_init_modules.assert_called_once()

    def test_setup_powershell_init_modules_failure(self):
        """Test that setup_powershell handles initialization failures correctly"""
        credentials_dict = {
            "user": "test@example.com",
            "password": "test_password",
            "client_id": "test_client_id",
            "tenant_id": "test_tenant_id",
            "client_secret": "test_client_secret",
        }

        with (
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
            patch(
                "prowler.providers.m365.m365_provider.initialize_m365_powershell_modules",
                side_effect=Exception("Module initialization failed"),
            ),
        ):
            with pytest.raises(Exception) as exc_info:
                M365Provider.setup_powershell(
                    env_auth=False,
                    m365_credentials=credentials_dict,
                    identity=M365IdentityInfo(
                        identity_id=IDENTITY_ID,
                        identity_type="User",
                        tenant_id=TENANT_ID,
                        tenant_domain=DOMAIN,
                        tenant_domains=["test.onmicrosoft.com"],
                        location=LOCATION,
                    ),
                    init_modules=True,
                )

            assert str(exc_info.value) == "Module initialization failed"

    def test_test_connection_provider_id_not_in_tenant_domains(self):
        """Test that an exception is raised when provider_id is not in tenant_domains"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_static_credentials"
            ) as mock_validate_static_credentials,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain="contoso.onmicrosoft.com",
                    tenant_domains=["contoso.onmicrosoft.com", "contoso.com"],
                    location=LOCATION,
                ),
            ),
        ):
            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            provider_id = "test.onmicrosoft.com"

            with pytest.raises(M365InvalidProviderIdError) as exception:
                M365Provider.test_connection(
                    tenant_id=str(uuid4()),
                    region="M365Global",
                    raise_on_exception=True,
                    client_id=str(uuid4()),
                    client_secret=str(uuid4()),
                    user="user@contoso.onmicrosoft.com",
                    password="test_password",
                    provider_id=provider_id,
                )

            assert exception.type == M365InvalidProviderIdError
            assert (
                f"The provider ID {provider_id} does not match any of the service principal tenant domains: contoso.onmicrosoft.com, contoso.com"
                in str(exception.value)
            )

    def test_m365_provider_certificate_auth(self):
        """Test M365 Provider initialization with certificate authentication"""
        tenant_id = None
        client_id = None
        client_secret = None
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        fixer_config = load_and_validate_config_file(
            "m365", default_fixer_config_file_path
        )
        azure_region = "M365Global"

        # Mock certificate credential
        mock_cert_credential = MagicMock()
        mock_cert_credential.__class__ = CertificateCredential

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                return_value=mock_cert_credential,
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="Service Principal with Certificate",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                    certificate_thumbprint="ABC123",
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_powershell",
                return_value=M365Credentials(
                    client_id=CLIENT_ID,
                    tenant_id=TENANT_ID,
                    certificate_content=certificate_content,
                ),
            ),
        ):
            m365_provider = M365Provider(
                sp_env_auth=False,
                az_cli_auth=False,
                browser_auth=False,
                env_auth=False,
                certificate_auth=True,
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                certificate_content=certificate_content,
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
            assert (
                m365_provider.identity.identity_type
                == "Service Principal with Certificate"
            )
            assert m365_provider.session == mock_cert_credential

    def test_check_service_principal_creds_env_vars_missing_client_id(self):
        """Test check_service_principal_creds_env_vars with missing AZURE_CLIENT_ID"""
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(M365EnvironmentVariableError) as exception,
        ):
            M365Provider.check_service_principal_creds_env_vars()

        assert exception.type == M365EnvironmentVariableError
        assert (
            "Missing environment variable AZURE_CLIENT_ID required to authenticate."
            in str(exception.value)
        )

    def test_check_service_principal_creds_env_vars_missing_tenant_id(self):
        """Test check_service_principal_creds_env_vars with missing AZURE_TENANT_ID"""
        with (
            patch.dict(os.environ, {"AZURE_CLIENT_ID": "test_client_id"}, clear=True),
            pytest.raises(M365EnvironmentVariableError) as exception,
        ):
            M365Provider.check_service_principal_creds_env_vars()

        assert exception.type == M365EnvironmentVariableError
        assert (
            "Missing environment variable AZURE_TENANT_ID required to authenticate."
            in str(exception.value)
        )

    def test_check_service_principal_creds_env_vars_missing_client_secret(self):
        """Test check_service_principal_creds_env_vars with missing AZURE_CLIENT_SECRET"""
        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_CLIENT_ID": "test_client_id",
                    "AZURE_TENANT_ID": "test_tenant_id",
                },
                clear=True,
            ),
            pytest.raises(M365EnvironmentVariableError) as exception,
        ):
            M365Provider.check_service_principal_creds_env_vars()

        assert exception.type == M365EnvironmentVariableError
        assert (
            "Missing environment variable AZURE_CLIENT_SECRET required to authenticate."
            in str(exception.value)
        )

    def test_check_service_principal_creds_env_vars_success(self):
        """Test check_service_principal_creds_env_vars with all required variables"""
        with patch.dict(
            os.environ,
            {
                "AZURE_CLIENT_ID": "test_client_id",
                "AZURE_TENANT_ID": "test_tenant_id",
                "AZURE_CLIENT_SECRET": "test_client_secret",
            },
        ):
            # Should not raise any exception
            M365Provider.check_service_principal_creds_env_vars()

    def test_check_certificate_creds_env_vars_missing_client_id(self):
        """Test check_certificate_creds_env_vars with missing AZURE_CLIENT_ID"""
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(M365EnvironmentVariableError) as exception,
        ):
            M365Provider.check_certificate_creds_env_vars()

        assert exception.type == M365EnvironmentVariableError
        assert (
            "Missing environment variable AZURE_CLIENT_ID required to authenticate."
            in str(exception.value)
        )

    def test_check_certificate_creds_env_vars_missing_tenant_id(self):
        """Test check_certificate_creds_env_vars with missing AZURE_TENANT_ID"""
        with (
            patch.dict(os.environ, {"AZURE_CLIENT_ID": "test_client_id"}, clear=True),
            pytest.raises(M365EnvironmentVariableError) as exception,
        ):
            M365Provider.check_certificate_creds_env_vars()

        assert exception.type == M365EnvironmentVariableError
        assert (
            "Missing environment variable AZURE_TENANT_ID required to authenticate."
            in str(exception.value)
        )

    def test_check_certificate_creds_env_vars_missing_certificate_content(self):
        """Test check_certificate_creds_env_vars with missing M365_CERTIFICATE_CONTENT"""
        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_CLIENT_ID": "test_client_id",
                    "AZURE_TENANT_ID": "test_tenant_id",
                },
                clear=True,
            ),
            pytest.raises(M365EnvironmentVariableError) as exception,
        ):
            M365Provider.check_certificate_creds_env_vars()

        assert exception.type == M365EnvironmentVariableError
        assert (
            "Missing environment variable M365_CERTIFICATE_CONTENT required to authenticate."
            in str(exception.value)
        )

    def test_check_certificate_creds_env_vars_success(self):
        """Test check_certificate_creds_env_vars with all required variables"""
        with patch.dict(
            os.environ,
            {
                "AZURE_CLIENT_ID": "test_client_id",
                "AZURE_TENANT_ID": "test_tenant_id",
                "M365_CERTIFICATE_CONTENT": base64.b64encode(
                    b"fake_certificate"
                ).decode("utf-8"),
            },
        ):
            # Should not raise any exception
            M365Provider.check_certificate_creds_env_vars()

    def test_setup_powershell_env_auth_missing_credentials(self):
        """Test setup_powershell with env_auth but missing environment variables"""
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(M365MissingEnvironmentCredentialsError) as exception,
        ):
            M365Provider.setup_powershell(
                env_auth=True,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            )

        assert exception.type == M365MissingEnvironmentCredentialsError
        assert (
            "Missing M365_USER or M365_PASSWORD environment variables required for credentials authentication."
            in str(exception.value)
        )

    def test_setup_powershell_env_auth_success(self):
        """Test setup_powershell with env_auth and valid environment variables"""
        with (
            patch.dict(
                os.environ,
                {
                    "M365_USER": "test@example.com",
                    "M365_PASSWORD": "password",
                    "AZURE_CLIENT_ID": CLIENT_ID,
                    "AZURE_CLIENT_SECRET": CLIENT_SECRET,
                    "AZURE_TENANT_ID": TENANT_ID,
                },
            ),
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
        ):
            result = M365Provider.setup_powershell(
                env_auth=True,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            )

            assert result.user == "test@example.com"
            assert result.passwd == "password"
            assert result.client_id == CLIENT_ID

    def test_setup_powershell_sp_env_auth_success(self):
        """Test setup_powershell with sp_env_auth and valid environment variables"""
        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_CLIENT_ID": CLIENT_ID,
                    "AZURE_CLIENT_SECRET": CLIENT_SECRET,
                    "AZURE_TENANT_ID": TENANT_ID,
                },
            ),
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
        ):
            result = M365Provider.setup_powershell(
                sp_env_auth=True,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="Service Principal",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            )

            assert result.client_id == CLIENT_ID
            assert result.client_secret == CLIENT_SECRET
            assert result.tenant_id == TENANT_ID

    def test_setup_powershell_certificate_auth_success(self):
        """Test setup_powershell with certificate_auth and valid environment variables"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_CLIENT_ID": CLIENT_ID,
                    "AZURE_TENANT_ID": TENANT_ID,
                    "M365_CERTIFICATE_CONTENT": certificate_content,
                },
            ),
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=True,
            ),
        ):
            identity = M365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type="Service Principal with Certificate",
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                tenant_domains=["test.onmicrosoft.com"],
                location=LOCATION,
            )

            result = M365Provider.setup_powershell(
                certificate_auth=True,
                identity=identity,
            )

            assert result.client_id == CLIENT_ID
            assert result.tenant_id == TENANT_ID
            assert result.certificate_content == certificate_content
            assert identity.identity_type == "Service Principal with Certificate"

    def test_setup_powershell_invalid_credentials(self):
        """Test setup_powershell with invalid credentials"""
        credentials_dict = {
            "user": "test@example.com",
            "password": "test_password",
            "client_id": "test_client_id",
            "tenant_id": "test_tenant_id",
            "client_secret": "test_client_secret",
        }

        with (
            patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.test_credentials",
                return_value=False,
            ),
            pytest.raises(M365UserCredentialsError) as exception,
        ):
            M365Provider.setup_powershell(
                env_auth=False,
                m365_credentials=credentials_dict,
                identity=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="User",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            )

        assert exception.type == M365UserCredentialsError
        assert "The provided User credentials are not valid." in str(exception.value)

    def test_validate_arguments_browser_auth_without_tenant_id(self):
        """Test validate_arguments with browser_auth but missing tenant_id"""
        with pytest.raises(M365BrowserAuthNoTenantIDError) as exception:
            M365Provider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=True,
                certificate_auth=False,
                tenant_id=None,
                client_id=None,
                client_secret=None,
                user=None,
                password=None,
                certificate_content=None,
            )

        assert exception.type == M365BrowserAuthNoTenantIDError
        assert (
            "M365 Tenant ID (--tenant-id) is required for browser authentication mode"
            in str(exception.value)
        )

    def test_validate_arguments_tenant_id_without_browser_flag(self):
        """Test validate_arguments with tenant_id but without browser auth flag"""
        with pytest.raises(M365BrowserAuthNoFlagError) as exception:
            M365Provider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=False,
                certificate_auth=False,
                tenant_id=TENANT_ID,
                client_id=None,
                client_secret=None,
                user=None,
                password=None,
                certificate_content=None,
            )

        assert exception.type == M365BrowserAuthNoFlagError
        assert "browser authentication flag (--browser-auth) not found" in str(
            exception.value
        )

    def test_validate_arguments_missing_tenant_id_with_credentials(self):
        """Test validate_arguments with client credentials but missing tenant_id"""
        with pytest.raises(M365NotTenantIdButClientIdAndClientSecretError) as exception:
            M365Provider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=False,
                certificate_auth=False,
                tenant_id=None,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                user=None,
                password=None,
                certificate_content=None,
            )

        assert exception.type == M365NotTenantIdButClientIdAndClientSecretError
        assert "Tenant Id is required for M365 static credentials" in str(
            exception.value
        )

    def test_test_connection_certificate_auth(self):
        """Test test_connection with certificate authentication"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch("prowler.providers.m365.m365_provider.M365Provider.setup_powershell"),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="Service Principal with Certificate",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    tenant_domains=["test.onmicrosoft.com"],
                    location=LOCATION,
                ),
            ),
        ):
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            test_connection = M365Provider.test_connection(
                certificate_auth=True,
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                certificate_content=certificate_content,
                region="M365Global",
                raise_on_exception=False,
                provider_id="test.onmicrosoft.com",
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_get_token_identity_error(self):
        """Test test_connection when setup_identity returns None"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=None,
            ),
            pytest.raises(M365GetTokenIdentityError) as exception,
        ):
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            M365Provider.test_connection(
                az_cli_auth=True,
                raise_on_exception=True,
            )

        assert exception.type == M365GetTokenIdentityError
        assert "Failed to retrieve M365 identity" in str(exception.value)

    def test_validate_static_credentials_client_id_secret_tenant_error(self):
        """Test validate_static_credentials with client/secret/tenant mismatch errors"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.verify_client",
                side_effect=M365NotValidTenantIdError(
                    file="test", message="Invalid tenant"
                ),
            ),
            pytest.raises(
                M365ClientIdAndClientSecretNotBelongingToTenantIdError
            ) as exception,
        ):
            M365Provider.validate_static_credentials(
                tenant_id=str(uuid4()),
                client_id=str(uuid4()),
                client_secret="test_secret",
                user="test@example.com",
                password="test_password",
            )

        assert exception.type == M365ClientIdAndClientSecretNotBelongingToTenantIdError
        assert (
            "The provided Client ID and Client Secret do not belong to the specified Tenant ID."
            in str(exception.value)
        )

    def test_validate_static_credentials_tenant_secret_client_error(self):
        """Test validate_static_credentials with tenant/secret/client mismatch errors"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.verify_client",
                side_effect=M365NotValidClientIdError(
                    file="test", message="Invalid client ID"
                ),
            ),
            pytest.raises(
                M365TenantIdAndClientSecretNotBelongingToClientIdError
            ) as exception,
        ):
            M365Provider.validate_static_credentials(
                tenant_id=str(uuid4()),
                client_id=str(uuid4()),
                client_secret="test_secret",
                user="test@example.com",
                password="test_password",
            )

        assert exception.type == M365TenantIdAndClientSecretNotBelongingToClientIdError
        assert (
            "The provided Tenant ID and Client Secret do not belong to the specified Client ID."
            in str(exception.value)
        )

    def test_validate_static_credentials_tenant_client_secret_error(self):
        """Test validate_static_credentials with tenant/client/secret mismatch errors"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.verify_client",
                side_effect=M365NotValidClientSecretError(
                    file="test", message="Invalid client secret"
                ),
            ),
            pytest.raises(
                M365TenantIdAndClientIdNotBelongingToClientSecretError
            ) as exception,
        ):
            M365Provider.validate_static_credentials(
                tenant_id=str(uuid4()),
                client_id=str(uuid4()),
                client_secret="test_secret",
                user="test@example.com",
                password="test_password",
            )

        assert exception.type == M365TenantIdAndClientIdNotBelongingToClientSecretError
        assert (
            "The provided Tenant ID and Client ID do not belong to the specified Client Secret."
            in str(exception.value)
        )

    def test_test_connection_default_azure_credential_error(self):
        """Test test_connection with DefaultAzureCredential error in exception handling"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                side_effect=M365DefaultAzureCredentialError(
                    file="test",
                    original_exception=Exception("Default credential error"),
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            pytest.raises(M365DefaultAzureCredentialError) as exception,
        ):
            M365Provider.test_connection(
                az_cli_auth=True,
                raise_on_exception=True,
            )

        assert exception.type == M365DefaultAzureCredentialError

    def test_test_connection_credentials_unavailable_error_handling(self):
        """Test test_connection with CredentialsUnavailableError in exception handling"""
        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                side_effect=M365CredentialsUnavailableError(
                    file="test", original_exception=Exception("Credentials unavailable")
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.validate_arguments"
            ),
            pytest.raises(M365CredentialsUnavailableError) as exception,
        ):
            M365Provider.test_connection(
                sp_env_auth=True,
                raise_on_exception=True,
            )

        assert exception.type == M365CredentialsUnavailableError

    def test_setup_session_certificate_auth_success(self):
        """Test setup_session method with certificate authentication - success"""
        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_CLIENT_ID": CLIENT_ID,
                    "AZURE_TENANT_ID": TENANT_ID,
                    "M365_CERTIFICATE_CONTENT": base64.b64encode(
                        b"fake_certificate"
                    ).decode("utf-8"),
                },
            ),
            patch(
                "prowler.providers.m365.m365_provider.CertificateCredential"
            ) as mock_cert_credential,
        ):
            mock_credential_instance = MagicMock()
            mock_cert_credential.return_value = mock_credential_instance

            region_config = M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )

            result = M365Provider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=False,
                certificate_auth=True,
                tenant_id=None,
                m365_credentials=None,
                region_config=region_config,
            )

            assert result == mock_credential_instance
            mock_cert_credential.assert_called_once_with(
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                certificate_data=base64.b64decode(
                    base64.b64encode(b"fake_certificate").decode("utf-8")
                ),
            )

    def test_setup_session_certificate_auth_client_authentication_error(self):
        """Test setup_session method with certificate authentication - ClientAuthenticationError"""
        from azure.core.exceptions import ClientAuthenticationError

        from prowler.providers.m365.exceptions.exceptions import M365SetUpSessionError

        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_CLIENT_ID": CLIENT_ID,
                    "AZURE_TENANT_ID": TENANT_ID,
                    "M365_CERTIFICATE_CONTENT": base64.b64encode(
                        b"fake_certificate"
                    ).decode("utf-8"),
                },
            ),
            patch(
                "prowler.providers.m365.m365_provider.CertificateCredential",
                side_effect=ClientAuthenticationError("Authentication failed"),
            ),
            pytest.raises(M365SetUpSessionError) as exception,
        ):
            region_config = M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )

            M365Provider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=False,
                certificate_auth=True,
                tenant_id=None,
                m365_credentials=None,
                region_config=region_config,
            )

        # The error should be wrapped in M365SetUpSessionError and contain the ClientAuthenticationError
        assert exception.type == M365SetUpSessionError
        assert "M365ClientAuthenticationError" in str(exception.value)

    def test_setup_session_certificate_auth_with_static_credentials(self):
        """Test setup_session method with certificate authentication using static credentials"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")
        m365_credentials = {
            "tenant_id": TENANT_ID,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "user": None,
            "password": None,
            "certificate_content": certificate_content,
        }

        with (
            patch(
                "prowler.providers.m365.m365_provider.ClientSecretCredential"
            ) as mock_credential,
        ):
            mock_credential_instance = MagicMock()
            mock_credential.return_value = mock_credential_instance

            region_config = M365RegionConfig(
                name="M365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )

            result = M365Provider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=False,
                certificate_auth=False,
                tenant_id=None,
                m365_credentials=m365_credentials,
                region_config=region_config,
            )

            assert result == mock_credential_instance
            mock_credential.assert_called_once_with(
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                user=None,
                password=None,
                certificate_content=certificate_content,
            )

    def test_setup_powershell_certificate_auth_missing_env_vars(self):
        """Test setup_powershell with certificate_auth but missing environment variables"""
        from pydantic.v1.error_wrappers import ValidationError

        with (patch.dict(os.environ, {}, clear=True),):
            identity = M365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type="Service Principal with Certificate",
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                tenant_domains=["test.onmicrosoft.com"],
                location=LOCATION,
            )

            # Should raise ValidationError when trying to create credentials with None values
            with pytest.raises(ValidationError) as exc_info:
                M365Provider.setup_powershell(
                    certificate_auth=True,
                    identity=identity,
                )

            # Verify the error is about None values not being allowed
            assert "none is not an allowed value" in str(exc_info.value).lower()

    def test_validate_arguments_certificate_auth_valid(self):
        """Test validate_arguments method with valid certificate authentication arguments"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        # Should not raise any exception
        M365Provider.validate_arguments(
            az_cli_auth=False,
            sp_env_auth=False,
            env_auth=False,
            browser_auth=False,
            certificate_auth=True,
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            client_secret=None,
            user=None,
            password=None,
            certificate_content=certificate_content,
        )

    def test_validate_arguments_certificate_auth_missing_certificate_content(self):
        """Test validate_arguments method with certificate auth but missing certificate content"""
        with pytest.raises(M365ConfigCredentialsError) as exception:
            M365Provider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                env_auth=False,
                browser_auth=False,
                certificate_auth=False,
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                client_secret=None,
                user=None,
                password=None,
                certificate_content=None,
            )

        assert "You must provide a valid set of credentials" in str(exception.value)

    def test_print_credentials_with_certificate(self):
        """Test print_credentials method with certificate authentication"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        # Mock certificate credential
        mock_cert_credential = MagicMock()
        mock_cert_credential.__class__ = CertificateCredential

        with (
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_session",
                return_value=mock_cert_credential,
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_identity",
                return_value=M365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type="Service Principal with Certificate",
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                    certificate_thumbprint="ABC123DEF456",
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.M365Provider.setup_powershell",
                return_value=M365Credentials(
                    client_id=CLIENT_ID,
                    tenant_id=TENANT_ID,
                    certificate_content=certificate_content,
                ),
            ),
            patch(
                "prowler.providers.m365.m365_provider.print_boxes"
            ) as mock_print_boxes,
        ):
            m365_provider = M365Provider(
                certificate_auth=True,
                region="M365Global",
            )

            m365_provider.print_credentials()

            # Verify print_boxes was called
            mock_print_boxes.assert_called_once()
            args, _ = mock_print_boxes.call_args
            report_lines = args[0]

            # Check that certificate thumbprint is in the output
            cert_line_found = any(
                "Certificate Thumbprint" in line for line in report_lines
            )
            assert (
                cert_line_found
            ), "Certificate thumbprint should be in printed credentials"
