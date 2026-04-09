from datetime import datetime, timezone

from prowler.providers.cloudflare.services.api.api_service import (
    CloudflareAPIToken,
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
