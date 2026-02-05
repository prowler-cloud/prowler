from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
from prowler.providers.cloudflare.exceptions.exceptions import (
    CloudflareAuthenticationError,
    CloudflareCredentialsError,
    CloudflareInvalidAccountError,
    parse_cloudflare_api_error,
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
        mock_client.accounts.list.return_value = iter([])  # Empty accounts list

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
            # Use raise_on_exception=False to get a Connection object instead of exception
            connection = provider.test_connection(raise_on_exception=False)

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


class TestParseCloudflareApiError:
    """Tests for parse_cloudflare_api_error function."""

    def test_parse_cloudflare_api_error_with_message_fields(self):
        """Test parsing error with 'message' fields in Cloudflare API format."""
        error = Exception(
            "Error code: 400 - {'success': False, 'errors': [{'code': 6003, "
            "'message': 'Invalid request headers', 'error_chain': [{'code': 6111, "
            "'message': 'Invalid format for Authorization header'}]}], 'messages': [], 'result': None}"
        )
        result = parse_cloudflare_api_error(error)
        assert "Invalid request headers" in result
        # The technical message is replaced with a user-friendly one
        assert "Invalid API Token format" in result

    def test_parse_cloudflare_api_error_with_401(self):
        """Test parsing error with 401 status code."""
        error = Exception("HTTP 401 Unauthorized")
        result = parse_cloudflare_api_error(error)
        assert result == "Invalid API token or credentials"

    def test_parse_cloudflare_api_error_with_403(self):
        """Test parsing error with 403 status code."""
        error = Exception("HTTP 403 Forbidden - access denied")
        result = parse_cloudflare_api_error(error)
        assert result == "API token lacks required permissions"

    def test_parse_cloudflare_api_error_with_400(self):
        """Test parsing error with 400 status code but no parseable message."""
        error = Exception("HTTP 400 Bad Request")
        result = parse_cloudflare_api_error(error)
        assert result == "Invalid request - please check your API token format"

    def test_parse_cloudflare_api_error_fallback(self):
        """Test fallback message for unparseable errors."""
        error = Exception("Some unknown error")
        result = parse_cloudflare_api_error(error)
        assert result == "Authentication failed - please verify your credentials"

    def test_parse_cloudflare_api_error_max_retries(self):
        """Test parsing error when max retries exceeded."""
        error = Exception("Max retries exceeded with url: /user")
        result = parse_cloudflare_api_error(error)
        assert "Connection failed after multiple attempts" in result

    def test_parse_cloudflare_api_error_deduplicates_messages(self):
        """Test that duplicate messages are deduplicated."""
        error = Exception(
            "{'message': 'Error A', 'nested': {'message': 'Error A', 'other': {'message': 'Error B'}}}"
        )
        result = parse_cloudflare_api_error(error)
        # Should only have 'Error A' once and 'Error B' once
        assert result == "Error A - Error B"


class TestCloudflareTestConnectionErrorFormatting:
    """Tests for test_connection error formatting."""

    def test_test_connection_formats_raw_api_error(self):
        """Test that raw Cloudflare API errors are formatted into user-friendly messages."""
        mock_client = MagicMock()
        # Simulate a raw Cloudflare API error on both user.get() and accounts.list()
        cloudflare_api_error = Exception(
            "Error code: 400 - {'success': False, 'errors': [{'code': 6003, "
            "'message': 'Invalid request headers', 'error_chain': [{'code': 6111, "
            "'message': 'Invalid format for Authorization header'}]}], 'messages': [], 'result': None}"
        )
        mock_client.user.get.side_effect = cloudflare_api_error
        mock_client.accounts.list.side_effect = cloudflare_api_error

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
            assert connection.error is not None
            # The error should be a CloudflareAuthenticationError with formatted message
            assert isinstance(connection.error, CloudflareAuthenticationError)
            # The formatted message should contain user-friendly messages
            error_str = str(connection.error)
            assert "Invalid request headers" in error_str
            # Technical messages are replaced with user-friendly ones
            assert "Invalid API Token format" in error_str
            # The raw error should NOT be included in the user-facing message
            assert "Error code: 400" not in error_str
            assert "'success': False" not in error_str
