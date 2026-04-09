from unittest import mock

from prowler.providers.cloudflare.services.api.api_service import (
    CloudflareAPIToken,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    set_mocked_cloudflare_provider,
)

TOKEN_ID = "test-token-id"
TOKEN_NAME = "Test API Token"


class Test_api_token_ip_restriction_enabled:
    """Tests for the api_token_ip_restriction_enabled check."""

    def test_no_tokens(self):
        api_client = mock.MagicMock
        api_client.tokens = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled.api_client",
                new=api_client,
            ),
        ):
            from prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled import (
                api_token_ip_restriction_enabled,
            )

            check = api_token_ip_restriction_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_token_with_ip_allow_list(self):
        api_client = mock.MagicMock
        api_client.tokens = [
            CloudflareAPIToken(
                id=TOKEN_ID,
                name=TOKEN_NAME,
                status="active",
                ip_allow_list=["192.0.2.0/24", "198.51.100.0/24"],
                ip_deny_list=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled.api_client",
                new=api_client,
            ),
        ):
            from prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled import (
                api_token_ip_restriction_enabled,
            )

            check = api_token_ip_restriction_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TOKEN_ID
            assert result[0].resource_name == TOKEN_NAME
            assert result[0].status == "PASS"
            assert "has client IP address filtering configured" in result[0].status_extended

    def test_token_with_ip_deny_list(self):
        api_client = mock.MagicMock
        api_client.tokens = [
            CloudflareAPIToken(
                id=TOKEN_ID,
                name=TOKEN_NAME,
                status="active",
                ip_allow_list=[],
                ip_deny_list=["10.0.0.0/8"],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled.api_client",
                new=api_client,
            ),
        ):
            from prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled import (
                api_token_ip_restriction_enabled,
            )

            check = api_token_ip_restriction_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TOKEN_ID
            assert result[0].status == "PASS"
            assert "has client IP address filtering configured" in result[0].status_extended

    def test_token_with_both_allow_and_deny_lists(self):
        api_client = mock.MagicMock
        api_client.tokens = [
            CloudflareAPIToken(
                id=TOKEN_ID,
                name=TOKEN_NAME,
                status="active",
                ip_allow_list=["192.0.2.0/24"],
                ip_deny_list=["10.0.0.0/8"],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled.api_client",
                new=api_client,
            ),
        ):
            from prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled import (
                api_token_ip_restriction_enabled,
            )

            check = api_token_ip_restriction_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has client IP address filtering configured" in result[0].status_extended

    def test_token_without_ip_restriction(self):
        api_client = mock.MagicMock
        api_client.tokens = [
            CloudflareAPIToken(
                id=TOKEN_ID,
                name=TOKEN_NAME,
                status="active",
                ip_allow_list=[],
                ip_deny_list=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled.api_client",
                new=api_client,
            ),
        ):
            from prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled import (
                api_token_ip_restriction_enabled,
            )

            check = api_token_ip_restriction_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TOKEN_ID
            assert result[0].resource_name == TOKEN_NAME
            assert result[0].status == "FAIL"
            assert "does not have client IP address filtering configured" in result[0].status_extended

    def test_multiple_tokens_mixed(self):
        api_client = mock.MagicMock
        api_client.tokens = [
            CloudflareAPIToken(
                id="token-1",
                name="Restricted Token",
                status="active",
                ip_allow_list=["192.0.2.0/24"],
                ip_deny_list=[],
            ),
            CloudflareAPIToken(
                id="token-2",
                name="Unrestricted Token",
                status="active",
                ip_allow_list=[],
                ip_deny_list=[],
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled.api_client",
                new=api_client,
            ),
        ):
            from prowler.providers.cloudflare.services.api.api_token_ip_restriction_enabled.api_token_ip_restriction_enabled import (
                api_token_ip_restriction_enabled,
            )

            check = api_token_ip_restriction_enabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].resource_id == "token-1"
            assert result[0].status == "PASS"
            assert result[1].resource_id == "token-2"
            assert result[1].status == "FAIL"
