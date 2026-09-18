from unittest import mock

from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareWAFRuleset,
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


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

    def test_zone_with_owasp_ruleset_by_name(self):
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
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "has OWASP managed WAF ruleset enabled" in result[0].status_extended
            assert "Cloudflare OWASP Core Ruleset" in result[0].status_extended

    def test_zone_with_managed_ruleset_without_owasp_name(self):
        """Test that a managed ruleset without 'owasp' in name does NOT pass."""
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
            assert (
                "does not have OWASP managed WAF ruleset enabled"
                in result[0].status_extended
            )

    def test_zone_without_owasp_ruleset(self):
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
            assert (
                "does not have OWASP managed WAF ruleset enabled"
                in result[0].status_extended
            )

    def test_zone_with_no_waf_rulesets(self):
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
            assert (
                "does not have OWASP managed WAF ruleset enabled"
                in result[0].status_extended
            )

    def test_zone_with_multiple_owasp_rulesets(self):
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
                        id="ruleset-1",
                        name="Cloudflare OWASP Core Ruleset",
                        kind="managed",
                        phase="http_request_firewall_managed",
                        enabled=True,
                    ),
                    CloudflareWAFRuleset(
                        id="ruleset-2",
                        name="Custom OWASP Rules",
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
            assert "Cloudflare OWASP Core Ruleset" in result[0].status_extended
            assert "Custom OWASP Rules" in result[0].status_extended
