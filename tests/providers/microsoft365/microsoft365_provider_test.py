from unittest.mock import patch
from uuid import uuid4

import pytest
from azure.identity import ClientSecretCredential
from mock import MagicMock

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider
from prowler.providers.microsoft365.models import (
    Microsoft365IdentityInfo,
    Microsoft365RegionConfig,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    IDENTITY_ID,
    IDENTITY_TYPE,
    LOCATION,
    TENANT_ID,
)


class TestMicrosoft365Provider:
    def test_microsoft365_provider(self):
        tenant_id = None
        client_id = None
        client_secret = None

        fixer_config = load_and_validate_config_file(
            "microsoft365", default_fixer_config_file_path
        )
        azure_region = "Microsoft365Global"

        with (
            patch(
                "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session",
                return_value=ClientSecretCredential(
                    client_id=IDENTITY_ID,
                    tenant_id=TENANT_ID,
                    client_secret="client_secret",
                ),
            ),
            patch(
                "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_identity",
                return_value=Microsoft365IdentityInfo(
                    identity_id=IDENTITY_ID,
                    identity_type=IDENTITY_TYPE,
                    tenant_id=TENANT_ID,
                    tenant_domain=DOMAIN,
                    location=LOCATION,
                ),
            ),
        ):
            microsoft365_provider = Microsoft365Provider(
                tenant_id,
                azure_region,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
                client_id=client_id,
                client_secret=client_secret,
            )

            assert microsoft365_provider.region_config == Microsoft365RegionConfig(
                name="Microsoft365Global",
                authority=None,
                base_url="https://graph.microsoft.com",
                credential_scopes=["https://graph.microsoft.com/.default"],
            )
            assert microsoft365_provider.identity == Microsoft365IdentityInfo(
                identity_id=IDENTITY_ID,
                identity_type=IDENTITY_TYPE,
                tenant_id=TENANT_ID,
                tenant_domain=DOMAIN,
                location=LOCATION,
            )

    def test_test_connection_tenant_id_client_id_client_secret(self):
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:

            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            test_connection = Microsoft365Provider.test_connection(
                tenant_id=str(uuid4()),
                region="Microsoft365Global",
                raise_on_exception=False,
                client_id=str(uuid4()),
                client_secret=str(uuid4()),
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_with_exception(self):
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session:

            mock_setup_session.side_effect = Exception("Simulated Exception")

            with pytest.raises(Exception) as exception:
                Microsoft365Provider.test_connection(
                    raise_on_exception=True,
                )

            assert exception.type is Exception
            assert exception.value.args[0] == "Simulated Exception"
