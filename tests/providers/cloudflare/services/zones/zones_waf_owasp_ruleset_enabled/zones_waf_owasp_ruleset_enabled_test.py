from unittest import mock

from prowler.providers.cloudflare.services.zones.zones_service import (
    CloudflareWAFRuleset,
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class Test_zones_waf_owasp_ruleset_enabled:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled import (
                zones_waf_owasp_ruleset_enabled,
            )

            check = zones_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_owasp_ruleset_by_name(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="ruleset-1",
                        name="Cloudflare OWASP Core Ruleset",
                        kind="managed",
                        phase="http_request_firewall_managed",
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
                "prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled import (
                zones_waf_owasp_ruleset_enabled,
            )

            check = zones_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "has OWASP managed WAF ruleset enabled" in result[0].status_extended

    def test_zone_with_managed_ruleset_by_phase(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="ruleset-1",
                        name="Managed Rules",
                        kind="managed",
                        phase="http_request_firewall_managed",
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
                "prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled import (
                zones_waf_owasp_ruleset_enabled,
            )

            check = zones_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has OWASP managed WAF ruleset enabled" in result[0].status_extended

    def test_zone_without_owasp_ruleset(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="ruleset-1",
                        name="Custom Rules",
                        kind="custom",
                        phase="http_request_firewall_custom",
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
                "prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled import (
                zones_waf_owasp_ruleset_enabled,
            )

            check = zones_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have OWASP managed WAF ruleset enabled"
                in result[0].status_extended
            )

    def test_zone_with_no_waf_rulesets(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
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
                "prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled import (
                zones_waf_owasp_ruleset_enabled,
            )

            check = zones_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have OWASP managed WAF ruleset enabled"
                in result[0].status_extended
            )

    def test_zone_with_multiple_owasp_rulesets(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                waf_rulesets=[
                    CloudflareWAFRuleset(
                        id="ruleset-1",
                        name="Cloudflare OWASP Core Ruleset",
                        kind="managed",
                        phase="http_request_firewall_managed",
                        enabled=True,
                    ),
                    CloudflareWAFRuleset(
                        id="ruleset-2",
                        name="Cloudflare Managed Ruleset",
                        kind="managed",
                        phase="http_request_firewall_managed",
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
                "prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_waf_owasp_ruleset_enabled.zones_waf_owasp_ruleset_enabled import (
                zones_waf_owasp_ruleset_enabled,
            )

            check = zones_waf_owasp_ruleset_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "2 ruleset(s)" in result[0].status_extended
