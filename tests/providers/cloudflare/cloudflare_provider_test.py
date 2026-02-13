from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
from prowler.providers.cloudflare.exceptions.exceptions import (
    CloudflareCredentialsError,
    CloudflareInvalidAccountError,
)
from prowler.providers.cloudflare.models import (
    CloudflareAccount,
    CloudflareIdentityInfo,
    CloudflareSession,
)
from prowler.providers.common.models import Connection
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    API_EMAIL,
    API_KEY,
    API_TOKEN,
    USER_EMAIL,
    USER_ID,
)


class TestCloudflareProvider:
    def test_cloudflare_provider_with_api_token(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        )
                    ],
                    audited_accounts=[ACCOUNT_ID],
                ),
            ),
        ):
            provider = CloudflareProvider()

            assert provider._type == "cloudflare"
            assert provider.session.api_token == API_TOKEN
            assert provider.identity.user_id == USER_ID
            assert provider.identity.email == USER_EMAIL
            assert len(provider.accounts) == 1
            assert provider.accounts[0].id == ACCOUNT_ID

    def test_cloudflare_provider_with_api_key_and_email(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=None,
                    api_key=API_KEY,
                    api_email=API_EMAIL,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        )
                    ],
                    audited_accounts=[ACCOUNT_ID],
                ),
            ),
        ):
            provider = CloudflareProvider()

            assert provider._type == "cloudflare"
            assert provider.session.api_key == API_KEY
            assert provider.session.api_email == API_EMAIL

    def test_cloudflare_provider_test_connection_success(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        )
                    ],
                    audited_accounts=[ACCOUNT_ID],
                ),
            ),
        ):
            provider = CloudflareProvider()
            connection = provider.test_connection()

            assert isinstance(connection, Connection)
            assert connection.is_connected is True
            assert connection.error is None

    def test_cloudflare_provider_test_connection_failure(self):
        mock_client = MagicMock()
        mock_client.user.get.side_effect = Exception("Connection failed")

        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=mock_client,
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[],
                    audited_accounts=[],
                ),
            ),
        ):
            provider = CloudflareProvider()
            connection = provider.test_connection()

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert connection.error is not None

    def test_cloudflare_provider_no_credentials_raises_error(self):
        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            side_effect=CloudflareCredentialsError(
                file="cloudflare_provider.py",
                message="Cloudflare credentials not found.",
            ),
        ):
            with pytest.raises(CloudflareCredentialsError):
                CloudflareProvider()

    def test_cloudflare_provider_with_filter_zones(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        )
                    ],
                    audited_accounts=[ACCOUNT_ID],
                ),
            ),
        ):
            filter_zones = ["zone1", "zone2"]
            provider = CloudflareProvider(filter_zones=filter_zones)

            assert provider.filter_zones == set(filter_zones)

    def test_cloudflare_provider_with_filter_accounts(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        ),
                        CloudflareAccount(
                            id="other-account-id",
                            name="Other Account",
                            type="standard",
                        ),
                    ],
                    audited_accounts=[ACCOUNT_ID, "other-account-id"],
                ),
            ),
        ):
            provider = CloudflareProvider(filter_accounts=[ACCOUNT_ID])

            assert provider.filter_accounts == {ACCOUNT_ID}
            # Only the filtered account should remain in audited_accounts
            assert provider.identity.audited_accounts == [ACCOUNT_ID]

    def test_cloudflare_provider_with_invalid_filter_accounts(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        ),
                    ],
                    audited_accounts=[ACCOUNT_ID],
                ),
            ),
        ):
            with pytest.raises(CloudflareInvalidAccountError):
                CloudflareProvider(filter_accounts=["non-existent-account-id"])

    def test_cloudflare_provider_properties(self):
        with (
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
                return_value=CloudflareSession(
                    client=MagicMock(),
                    api_token=API_TOKEN,
                    api_key=None,
                    api_email=None,
                ),
            ),
            patch(
                "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_identity",
                return_value=CloudflareIdentityInfo(
                    user_id=USER_ID,
                    email=USER_EMAIL,
                    accounts=[
                        CloudflareAccount(
                            id=ACCOUNT_ID,
                            name=ACCOUNT_NAME,
                            type="standard",
                        )
                    ],
                    audited_accounts=[ACCOUNT_ID],
                ),
            ),
        ):
            provider = CloudflareProvider()

            assert provider.type == "cloudflare"
            assert provider.session is not None
            assert provider.identity is not None
            assert provider.audit_config is not None
            assert provider.fixer_config is not None
            assert provider.mutelist is not None
