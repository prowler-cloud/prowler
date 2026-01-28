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

OWASP_CORE_ID = "4814384a9e5d4991b9815dcfc25d2f1f"
CLOUDFLARE_MANAGED_ID = "efb7b8c949ac4650a09736fc376e9aee"


class Test_zone_waf_owasp_ruleset_enabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled import (
                zone_waf_owasp_ruleset_enabled,
            )

            check = zone_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_owasp_ruleset_enabled(self):
        """PASS when the OWASP Core Ruleset is deployed and enabled."""
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
                "prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled import (
                zone_waf_owasp_ruleset_enabled,
            )

            check = zone_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has OWASP managed WAF ruleset enabled" in result[0].status_extended

    def test_zone_without_owasp_only_cloudflare_managed(self):
        """FAIL when only Cloudflare Managed Ruleset is deployed (no OWASP)."""
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
                "prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled import (
                zone_waf_owasp_ruleset_enabled,
            )

            check = zone_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_with_owasp_disabled(self):
        """FAIL when OWASP rule exists but is disabled."""
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
                                enabled=False,
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
                "prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled import (
                zone_waf_owasp_ruleset_enabled,
            )

            check = zone_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_zone_with_no_waf_rulesets(self):
        """FAIL when no WAF rulesets exist."""
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_waf_owasp_ruleset_enabled.zone_waf_owasp_ruleset_enabled import (
                zone_waf_owasp_ruleset_enabled,
            )

            check = zone_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
