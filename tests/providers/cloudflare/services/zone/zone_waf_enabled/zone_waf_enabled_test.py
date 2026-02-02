from unittest import mock

from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareWAFRuleset,
    CloudflareWAFRulesetRule,
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)

CLOUDFLARE_MANAGED_ID = "efb7b8c949ac4650a09736fc376e9aee"
OWASP_CORE_ID = "4814384a9e5d4991b9815dcfc25d2f1f"
FREE_MANAGED_ID = "77454fe2d30c4220b5701f6fdfb893ba"


class Test_zone_waf_enabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled import (
                zone_waf_enabled,
            )

            check = zone_waf_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_waf_enabled_with_cloudflare_managed(self):
        """PASS when Cloudflare Managed Ruleset is deployed and enabled."""
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="entrypoint-id",
                        name="zone",
                        kind="zone",
                        phase="http_request_firewall_managed",
                        rules=[
                            CloudflareWAFRulesetRule(
                                id="rule-1",
                                name="Execute Cloudflare Managed Ruleset",
                                action="execute",
                                enabled=True,
                                managed_ruleset_id=CLOUDFLARE_MANAGED_ID,
                            ),
                        ],
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
                "prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled import (
                zone_waf_enabled,
            )

            check = zone_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "WAF is enabled" in result[0].status_extended

    def test_zone_waf_fail_only_owasp(self):
        """FAIL when only OWASP is deployed (covered by separate check)."""
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="entrypoint-id",
                        name="zone",
                        kind="zone",
                        phase="http_request_firewall_managed",
                        rules=[
                            CloudflareWAFRulesetRule(
                                id="rule-1",
                                name="Execute OWASP Core Ruleset",
                                action="execute",
                                enabled=True,
                                managed_ruleset_id=OWASP_CORE_ID,
                            ),
                        ],
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
                "prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled import (
                zone_waf_enabled,
            )

            check = zone_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_waf_fail_only_free_ruleset(self):
        """FAIL when only the Free Managed Ruleset is active (always-on, not configurable)."""
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="entrypoint-id",
                        name="zone",
                        kind="zone",
                        phase="http_request_firewall_managed",
                        rules=[
                            CloudflareWAFRulesetRule(
                                id="rule-1",
                                name="Execute Free Managed Ruleset",
                                action="execute",
                                enabled=True,
                                managed_ruleset_id=FREE_MANAGED_ID,
                            ),
                        ],
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
                "prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled import (
                zone_waf_enabled,
            )

            check = zone_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "WAF is not enabled" in result[0].status_extended

    def test_zone_waf_fail_no_rulesets(self):
        """FAIL when no WAF rulesets exist at all."""
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled import (
                zone_waf_enabled,
            )

            check = zone_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_waf_fail_paid_ruleset_disabled(self):
        """FAIL when a paid managed ruleset exists but is disabled."""
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="entrypoint-id",
                        name="zone",
                        kind="zone",
                        phase="http_request_firewall_managed",
                        rules=[
                            CloudflareWAFRulesetRule(
                                id="rule-1",
                                name="Execute Cloudflare Managed Ruleset",
                                action="execute",
                                enabled=False,
                                managed_ruleset_id=CLOUDFLARE_MANAGED_ID,
                            ),
                        ],
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
                "prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_enabled.zone_waf_enabled import (
                zone_waf_enabled,
            )

            check = zone_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
