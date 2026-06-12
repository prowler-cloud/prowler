from unittest import mock

from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


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

    def test_zone_waf_enabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    waf="on",
                ),
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
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "WAF is enabled" in result[0].status_extended

    def test_zone_waf_disabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    waf="off",
                ),
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

    def test_zone_waf_none(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    waf=None,
                ),
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

    def test_zone_waf_disabled_paid_plan_includes_hint(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                plan="Pro Website",
                settings=CloudflareZoneSettings(
                    waf="off",
                ),
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
            assert "false positive" in result[0].status_extended
            assert "Cloudflare dashboard" in result[0].status_extended

    def test_zone_waf_disabled_free_plan_includes_unavailable_hint(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                plan="Free Website",
                settings=CloudflareZoneSettings(
                    waf="off",
                ),
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
            assert "not available on the Cloudflare Free plan" in (
                result[0].status_extended
            )
            assert "false positive" not in result[0].status_extended
