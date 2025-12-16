from typing import Optional
from unittest import mock

from pydantic import BaseModel

from prowler.providers.cloudflare.services.zones.zones_service import (
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class CloudflareFirewallRule(BaseModel):
    """Cloudflare firewall rule representation for testing."""

    id: Optional[str] = None
    zone_id: str
    zone_name: str
    ruleset_id: Optional[str] = None
    phase: Optional[str] = None
    action: Optional[str] = None
    expression: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True


class Test_zones_rate_limiting_enabled:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}

        firewall_client = mock.MagicMock
        firewall_client.rules = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_rate_limiting_rules(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        firewall_client = mock.MagicMock
        firewall_client.rules = [
            CloudflareFirewallRule(
                id="rule-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                ruleset_id="ruleset-1",
                phase="http_ratelimit",
                action="block",
                expression="(http.request.uri.path contains '/api/')",
                enabled=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "Rate limiting is configured" in result[0].status_extended
            assert "1 rule(s)" in result[0].status_extended

    def test_zone_with_multiple_rate_limiting_rules(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        firewall_client = mock.MagicMock
        firewall_client.rules = [
            CloudflareFirewallRule(
                id="rule-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                phase="http_ratelimit",
                enabled=True,
            ),
            CloudflareFirewallRule(
                id="rule-2",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                phase="http_ratelimit",
                enabled=True,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "2 rule(s)" in result[0].status_extended

    def test_zone_without_rate_limiting_rules(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        firewall_client = mock.MagicMock
        firewall_client.rules = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No rate limiting rules configured" in result[0].status_extended

    def test_zone_with_disabled_rate_limiting_rules(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        firewall_client = mock.MagicMock
        firewall_client.rules = [
            CloudflareFirewallRule(
                id="rule-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                phase="http_ratelimit",
                enabled=False,  # Disabled
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_with_different_phase_rules(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        firewall_client = mock.MagicMock
        firewall_client.rules = [
            CloudflareFirewallRule(
                id="rule-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                phase="http_request_firewall_custom",  # Different phase
                enabled=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_with_rate_limiting_rules_for_different_zone(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        firewall_client = mock.MagicMock
        firewall_client.rules = [
            CloudflareFirewallRule(
                id="rule-1",
                zone_id="other-zone-id",
                zone_name="other.com",
                phase="http_ratelimit",
                enabled=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.zones_client",
                new=zones_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_rate_limiting_enabled.zones_rate_limiting_enabled import (
                zones_rate_limiting_enabled,
            )

            check = zones_rate_limiting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
