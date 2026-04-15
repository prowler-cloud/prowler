from datetime import datetime, timezone
from unittest import mock
from unittest.mock import MagicMock

from prowler.providers.cloudflare.services.api.api_service import (
    API,
    CloudflareAPIToken,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    set_mocked_cloudflare_provider,
)


class Test_CloudflareAPIToken_Model:
    def test_cloudflare_api_token_model(self):
        token = CloudflareAPIToken(
            id="token-123",
            name="My API Token",
            status="active",
            ip_allow_list=["192.0.2.0/24"],
            ip_deny_list=["10.0.0.0/8"],
            expires_on=datetime(2026, 12, 31, tzinfo=timezone.utc),
            issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_used_on=datetime(2026, 4, 1, tzinfo=timezone.utc),
            modified_on=datetime(2026, 3, 15, tzinfo=timezone.utc),
        )
        assert token.id == "token-123"
        assert token.name == "My API Token"
        assert token.status == "active"
        assert token.ip_allow_list == ["192.0.2.0/24"]
        assert token.ip_deny_list == ["10.0.0.0/8"]
        assert token.expires_on == datetime(2026, 12, 31, tzinfo=timezone.utc)
        assert token.issued_on == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert token.last_used_on == datetime(2026, 4, 1, tzinfo=timezone.utc)
        assert token.modified_on == datetime(2026, 3, 15, tzinfo=timezone.utc)

    def test_cloudflare_api_token_defaults(self):
        token = CloudflareAPIToken(id="token-456")
        assert token.id == "token-456"
        assert token.name is None
        assert token.status is None
        assert token.ip_allow_list == []
        assert token.ip_deny_list == []
        assert token.expires_on is None
        assert token.issued_on is None
        assert token.last_used_on is None
        assert token.modified_on is None

    def test_cloudflare_api_token_with_ip_allow_list_only(self):
        token = CloudflareAPIToken(
            id="token-789",
            name="Restricted Token",
            status="active",
            ip_allow_list=["192.0.2.0/24", "198.51.100.0/24"],
        )
        assert token.ip_allow_list == ["192.0.2.0/24", "198.51.100.0/24"]
        assert token.ip_deny_list == []

    def test_cloudflare_api_token_with_ip_deny_list_only(self):
        token = CloudflareAPIToken(
            id="token-101",
            name="Deny-list Token",
            status="active",
            ip_deny_list=["10.0.0.0/8", "172.16.0.0/12"],
        )
        assert token.ip_allow_list == []
        assert token.ip_deny_list == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_cloudflare_api_token_disabled_status(self):
        token = CloudflareAPIToken(
            id="token-disabled",
            name="Disabled Token",
            status="disabled",
        )
        assert token.status == "disabled"

    def test_cloudflare_api_token_expired_status(self):
        token = CloudflareAPIToken(
            id="token-expired",
            name="Expired Token",
            status="expired",
            expires_on=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        assert token.status == "expired"
        assert token.expires_on == datetime(2025, 1, 1, tzinfo=timezone.utc)


class Test_API_Service:
    """Tests for the API service _list_api_tokens method."""

    def _make_sdk_token(self, **kwargs):
        """Create a mock Cloudflare SDK token object."""
        token = MagicMock()
        for key, value in kwargs.items():
            setattr(token, key, value)
        return token

    def test_list_api_tokens_with_ip_conditions(self):
        mock_provider = set_mocked_cloudflare_provider()
        request_ip = MagicMock()
        request_ip.in_ = ["192.0.2.0/24"]
        request_ip.not_in = ["10.0.0.0/8"]
        condition = MagicMock()
        condition.request_ip = request_ip

        sdk_token = self._make_sdk_token(
            id="token-1",
            name="Test Token",
            status="active",
            condition=condition,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        mock_provider.session.client.user.tokens.list.return_value = [sdk_token]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            service = API(mock_provider)

        assert len(service.tokens) == 1
        assert service.tokens[0].id == "token-1"
        assert service.tokens[0].name == "Test Token"
        assert service.tokens[0].ip_allow_list == ["192.0.2.0/24"]
        assert service.tokens[0].ip_deny_list == ["10.0.0.0/8"]

    def test_list_api_tokens_without_condition(self):
        mock_provider = set_mocked_cloudflare_provider()
        sdk_token = self._make_sdk_token(
            id="token-2",
            name="No Condition Token",
            status="active",
            condition=None,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        mock_provider.session.client.user.tokens.list.return_value = [sdk_token]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            service = API(mock_provider)

        assert len(service.tokens) == 1
        assert service.tokens[0].ip_allow_list == []
        assert service.tokens[0].ip_deny_list == []

    def test_list_api_tokens_skips_duplicates(self):
        mock_provider = set_mocked_cloudflare_provider()
        sdk_token_1 = self._make_sdk_token(
            id="token-dup",
            name="First",
            status="active",
            condition=None,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        sdk_token_2 = self._make_sdk_token(
            id="token-dup",
            name="Duplicate",
            status="active",
            condition=None,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        sdk_token_3 = self._make_sdk_token(
            id="token-other",
            name="Other",
            status="active",
            condition=None,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        mock_provider.session.client.user.tokens.list.return_value = [
            sdk_token_1,
            sdk_token_2,
            sdk_token_3,
        ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            service = API(mock_provider)

        assert len(service.tokens) == 2
        assert service.tokens[0].id == "token-dup"
        assert service.tokens[0].name == "First"
        assert service.tokens[1].id == "token-other"

    def test_list_api_tokens_skips_none_id(self):
        mock_provider = set_mocked_cloudflare_provider()
        sdk_token_no_id = self._make_sdk_token(
            id=None,
            name="No ID",
            status="active",
            condition=None,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        sdk_token_valid = self._make_sdk_token(
            id="token-valid",
            name="Valid",
            status="active",
            condition=None,
            expires_on=None,
            issued_on=None,
            last_used_on=None,
            modified_on=None,
        )
        mock_provider.session.client.user.tokens.list.return_value = [
            sdk_token_no_id,
            sdk_token_valid,
        ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            service = API(mock_provider)

        assert len(service.tokens) == 1
        assert service.tokens[0].id == "token-valid"

    def test_list_api_tokens_handles_exception(self):
        mock_provider = set_mocked_cloudflare_provider()
        mock_provider.session.client.user.tokens.list.side_effect = Exception(
            "API error"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock_provider,
        ):
            service = API(mock_provider)

        assert service.tokens == []
