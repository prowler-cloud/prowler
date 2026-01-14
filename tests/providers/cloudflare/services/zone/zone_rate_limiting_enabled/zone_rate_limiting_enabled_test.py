from unittest import mock

from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareFirewallRule,
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class Test_zone_rate_limiting_enabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled import (
                zone_rate_limiting_enabled,
            )

            check = zone_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_rate_limiting_rules(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                firewall_rules=[
                    CloudflareFirewallRule(
                        id="rule-1",
                        name="Rate limit API",
                        phase="http_ratelimit",
                        action="block",
                        expression="(http.request.uri.path contains '/api/')",
                        enabled=True,
                    )
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled import (
                zone_rate_limiting_enabled,
            )

            check = zone_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "Rate limiting is configured" in result[0].status_extended
            assert "1 rule(s)" in result[0].status_extended

    def test_zone_with_multiple_rate_limiting_rules(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                firewall_rules=[
                    CloudflareFirewallRule(
                        id="rule-1",
                        name="Rate limit 1",
                        phase="http_ratelimit",
                        enabled=True,
                    ),
                    CloudflareFirewallRule(
                        id="rule-2",
                        name="Rate limit 2",
                        phase="http_ratelimit",
                        enabled=True,
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled import (
                zone_rate_limiting_enabled,
            )

            check = zone_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "2 rule(s)" in result[0].status_extended

    def test_zone_without_rate_limiting_rules(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                firewall_rules=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled import (
                zone_rate_limiting_enabled,
            )

            check = zone_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No rate limiting rules configured" in result[0].status_extended

    def test_zone_with_disabled_rate_limiting_rules(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                firewall_rules=[
                    CloudflareFirewallRule(
                        id="rule-1",
                        name="Disabled rate limit",
                        phase="http_ratelimit",
                        enabled=False,
                    )
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled import (
                zone_rate_limiting_enabled,
            )

            check = zone_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_with_different_phase_rules(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                firewall_rules=[
                    CloudflareFirewallRule(
                        id="rule-1",
                        name="Custom firewall rule",
                        phase="http_request_firewall_custom",
                        enabled=True,
                    )
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_rate_limiting_enabled.zone_rate_limiting_enabled import (
                zone_rate_limiting_enabled,
            )

            check = zone_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
