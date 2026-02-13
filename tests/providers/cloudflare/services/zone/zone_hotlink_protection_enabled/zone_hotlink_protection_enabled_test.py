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


class Test_zone_hotlink_protection_enabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled import (
                zone_hotlink_protection_enabled,
            )

            check = zone_hotlink_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_hotlink_protection_enabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    hotlink_protection="on",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled import (
                zone_hotlink_protection_enabled,
            )

            check = zone_hotlink_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "Hotlink Protection is enabled" in result[0].status_extended

    def test_zone_hotlink_protection_disabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    hotlink_protection="off",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled import (
                zone_hotlink_protection_enabled,
            )

            check = zone_hotlink_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Hotlink Protection is not enabled" in result[0].status_extended

    def test_zone_hotlink_protection_none(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    hotlink_protection=None,
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hotlink_protection_enabled.zone_hotlink_protection_enabled import (
                zone_hotlink_protection_enabled,
            )

            check = zone_hotlink_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
