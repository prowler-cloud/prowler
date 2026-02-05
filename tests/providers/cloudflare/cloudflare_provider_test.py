from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
from prowler.providers.cloudflare.exceptions.exceptions import (
    CloudflareCredentialsError,
    CloudflareInvalidAccountError,
    CloudflareInvalidAPIKeyError,
    CloudflareInvalidAPITokenError,
    CloudflareNoAccountsError,
    CloudflareUserTokenRequiredError,
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
        mock_client = MagicMock()
        # Simulate successful user.get() call
        mock_client.user.get.return_value = MagicMock(id=USER_ID, email=USER_EMAIL)

        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            return_value=CloudflareSession(
                client=mock_client,
                api_token=API_TOKEN,
                api_key=None,
                api_email=None,
            ),
        ):
            connection = CloudflareProvider.test_connection(api_token=API_TOKEN)

            assert isinstance(connection, Connection)
            assert connection.is_connected is True
            assert connection.error is None

    def test_cloudflare_provider_test_connection_failure_no_accounts(self):
        mock_client = MagicMock()
        mock_client.user.get.side_effect = Exception("Connection failed")
        mock_client.accounts.list.return_value = iter([])  # Empty accounts list

        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            return_value=CloudflareSession(
                client=mock_client,
                api_token=API_TOKEN,
                api_key=None,
                api_email=None,
            ),
        ):
            connection = CloudflareProvider.test_connection(
                api_token=API_TOKEN, raise_on_exception=False
            )

            assert isinstance(connection, Connection)
            assert connection.is_connected is False
            assert connection.error is not None
            assert isinstance(connection.error, CloudflareNoAccountsError)

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


class TestCloudflareValidateCredentials:
    """Tests for validate_credentials method."""

    def test_validate_credentials_success(self):
        """Test successful credential validation."""
        mock_client = MagicMock()
        mock_client.user.get.return_value = MagicMock(id=USER_ID, email=USER_EMAIL)

        session = CloudflareSession(
            client=mock_client,
            api_token=API_TOKEN,
            api_key=None,
            api_email=None,
        )

        # Should not raise any exception
        CloudflareProvider.validate_credentials(session)
        mock_client.user.get.assert_called_once()

    def test_validate_credentials_user_token_required(self):
        """Test that user token required error is raised for Account tokens."""
        mock_client = MagicMock()
        # Simulate error code 9109 - user-level authentication required
        from cloudflare._exceptions import PermissionDeniedError

        mock_client.user.get.side_effect = PermissionDeniedError(
            "Error code: 403 - {'errors': [{'code': 9109, 'message': 'Valid user-level authentication not found'}]}",
            response=MagicMock(status_code=403),
            body=None,
        )

        session = CloudflareSession(
            client=mock_client,
            api_token=API_TOKEN,
            api_key=None,
            api_email=None,
        )

        with pytest.raises(CloudflareUserTokenRequiredError):
            CloudflareProvider.validate_credentials(session)

    def test_validate_credentials_invalid_api_token(self):
        """Test that invalid API token error is raised."""
        mock_client = MagicMock()
        from cloudflare._exceptions import BadRequestError

        mock_client.user.get.side_effect = BadRequestError(
            "Error code: 400 - {'errors': [{'code': 6003, 'message': 'Invalid request headers', 'error_chain': [{'code': 6111}]}]}",
            response=MagicMock(status_code=400),
            body=None,
        )

        session = CloudflareSession(
            client=mock_client,
            api_token="invalid_token",
            api_key=None,
            api_email=None,
        )

        with pytest.raises(CloudflareInvalidAPITokenError):
            CloudflareProvider.validate_credentials(session)

    def test_validate_credentials_invalid_api_key(self):
        """Test that invalid API key error is raised (403 with code 9103)."""
        mock_client = MagicMock()
        from cloudflare._exceptions import PermissionDeniedError

        # Real error: 403 with code 9103 "Unknown X-Auth-Key or X-Auth-Email"
        mock_client.user.get.side_effect = PermissionDeniedError(
            "Error code: 403 - {'success': False, 'errors': [{'code': 9103, 'message': 'Unknown X-Auth-Key or X-Auth-Email'}]}",
            response=MagicMock(status_code=403),
            body=None,
        )

        session = CloudflareSession(
            client=mock_client,
            api_token=None,
            api_key="invalid_key",
            api_email="invalid@email.com",
        )

        with pytest.raises(CloudflareInvalidAPIKeyError):
            CloudflareProvider.validate_credentials(session)

    def test_validate_credentials_invalid_api_key_bad_request(self):
        """Test that invalid API key error is raised when using API Key + Email with 6003 error."""
        mock_client = MagicMock()
        from cloudflare._exceptions import BadRequestError

        # Same error code as token but using API Key + Email auth
        mock_client.user.get.side_effect = BadRequestError(
            "Error code: 400 - {'errors': [{'code': 6003, 'message': 'Invalid request headers'}]}",
            response=MagicMock(status_code=400),
            body=None,
        )

        session = CloudflareSession(
            client=mock_client,
            api_token=None,
            api_key="invalid_key",
            api_email="invalid@email.com",
        )

        # Should raise CloudflareInvalidAPIKeyError, NOT CloudflareInvalidAPITokenError
        with pytest.raises(CloudflareInvalidAPIKeyError):
            CloudflareProvider.validate_credentials(session)

    def test_validate_credentials_fallback_to_accounts_list(self):
        """Test fallback to accounts.list() when user.get() fails with non-auth error."""
        mock_client = MagicMock()
        # Simulate a non-auth error on user.get()
        mock_client.user.get.side_effect = Exception("Some other error")
        # accounts.list() returns valid accounts
        mock_account = MagicMock()
        mock_account.id = ACCOUNT_ID
        mock_client.accounts.list.return_value = iter([mock_account])

        session = CloudflareSession(
            client=mock_client,
            api_token=API_TOKEN,
            api_key=None,
            api_email=None,
        )

        # Should not raise - fallback succeeded
        CloudflareProvider.validate_credentials(session)
        mock_client.accounts.list.assert_called_once()

    def test_validate_credentials_no_accounts(self):
        """Test that no accounts error is raised when accounts.list() is empty."""
        mock_client = MagicMock()
        mock_client.user.get.side_effect = Exception("Some error")
        mock_client.accounts.list.return_value = iter([])  # Empty

        session = CloudflareSession(
            client=mock_client,
            api_token=API_TOKEN,
            api_key=None,
            api_email=None,
        )

        with pytest.raises(CloudflareNoAccountsError):
            CloudflareProvider.validate_credentials(session)


class TestCloudflareTestConnection:
    """Tests for test_connection method."""

    def test_test_connection_returns_prowler_exception(self):
        """Test that test_connection returns Prowler exceptions, not raw SDK errors."""
        mock_client = MagicMock()
        from cloudflare._exceptions import BadRequestError

        mock_client.user.get.side_effect = BadRequestError(
            "Error code: 400 - {'errors': [{'code': 6003}]}",
            response=MagicMock(status_code=400),
            body=None,
        )

        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            return_value=CloudflareSession(
                client=mock_client,
                api_token=API_TOKEN,
                api_key=None,
                api_email=None,
            ),
        ):
            connection = CloudflareProvider.test_connection(
                api_token=API_TOKEN, raise_on_exception=False
            )

            assert connection.is_connected is False
            assert isinstance(connection.error, CloudflareInvalidAPITokenError)

    def test_test_connection_user_token_required(self):
        """Test that user token required error is properly returned."""
        mock_client = MagicMock()
        from cloudflare._exceptions import PermissionDeniedError

        mock_client.user.get.side_effect = PermissionDeniedError(
            "Error code: 403 - {'errors': [{'code': 9109}]}",
            response=MagicMock(status_code=403),
            body=None,
        )

        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            return_value=CloudflareSession(
                client=mock_client,
                api_token=API_TOKEN,
                api_key=None,
                api_email=None,
            ),
        ):
            connection = CloudflareProvider.test_connection(
                api_token=API_TOKEN, raise_on_exception=False
            )

            assert connection.is_connected is False
            assert isinstance(connection.error, CloudflareUserTokenRequiredError)
            # Verify the error message is user-friendly
            assert "User-level API token required" in str(connection.error)

    def test_test_connection_invalid_api_key(self):
        """Test that invalid API key error is properly returned."""
        mock_client = MagicMock()
        from cloudflare._exceptions import BadRequestError

        mock_client.user.get.side_effect = BadRequestError(
            "Unknown X-Auth-Key or X-Auth-Email",
            response=MagicMock(status_code=400),
            body=None,
        )

        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            return_value=CloudflareSession(
                client=mock_client,
                api_token=None,
                api_key=API_KEY,
                api_email=API_EMAIL,
            ),
        ):
            connection = CloudflareProvider.test_connection(
                api_key=API_KEY, api_email=API_EMAIL, raise_on_exception=False
            )

            assert connection.is_connected is False
            assert isinstance(connection.error, CloudflareInvalidAPIKeyError)
            # Verify the error message is user-friendly
            assert "Invalid API Key or Email" in str(connection.error)

    def test_test_connection_raises_when_requested(self):
        """Test that exceptions are raised when raise_on_exception=True."""
        mock_client = MagicMock()
        from cloudflare._exceptions import BadRequestError

        mock_client.user.get.side_effect = BadRequestError(
            "Error code: 400 - {'errors': [{'code': 6003}]}",
            response=MagicMock(status_code=400),
            body=None,
        )

        with patch(
            "prowler.providers.cloudflare.cloudflare_provider.CloudflareProvider.setup_session",
            return_value=CloudflareSession(
                client=mock_client,
                api_token=API_TOKEN,
                api_key=None,
                api_email=None,
            ),
        ):
            with pytest.raises(CloudflareInvalidAPITokenError):
                CloudflareProvider.test_connection(
                    api_token=API_TOKEN, raise_on_exception=True
                )
