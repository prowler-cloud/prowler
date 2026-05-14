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


class Test_zone_firewall_blocking_rules_configured:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured import (
                zone_firewall_blocking_rules_configured,
            )

            check = zone_firewall_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_blocking_rules(self):
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
                        name="Block bad actors",
                        action="block",
                        enabled=True,
                    ),
                    CloudflareFirewallRule(
                        id="rule-2",
                        name="Challenge suspicious",
                        action="challenge",
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
                "prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured import (
                zone_firewall_blocking_rules_configured,
            )

            check = zone_firewall_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert (
                "has firewall rules with blocking actions" in result[0].status_extended
            )
            assert "2 rule(s)" in result[0].status_extended

    def test_zone_without_blocking_rules(self):
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
                        name="Log traffic",
                        action="log",
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
                "prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured import (
                zone_firewall_blocking_rules_configured,
            )

            check = zone_firewall_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "has no firewall rules with blocking actions"
                in result[0].status_extended
            )

    def test_zone_with_no_firewall_rules(self):
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
                "prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured import (
                zone_firewall_blocking_rules_configured,
            )

            check = zone_firewall_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "has no firewall rules with blocking actions"
                in result[0].status_extended
            )

    def test_zone_with_js_challenge_rule(self):
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
                        name="JS Challenge",
                        action="js_challenge",
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
                "prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured import (
                zone_firewall_blocking_rules_configured,
            )

            check = zone_firewall_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "has firewall rules with blocking actions" in result[0].status_extended
            )

    def test_zone_with_managed_challenge_rule(self):
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
                        name="Managed Challenge",
                        action="managed_challenge",
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
                "prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_firewall_blocking_rules_configured.zone_firewall_blocking_rules_configured import (
                zone_firewall_blocking_rules_configured,
            )

            check = zone_firewall_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "has firewall rules with blocking actions" in result[0].status_extended
            )
