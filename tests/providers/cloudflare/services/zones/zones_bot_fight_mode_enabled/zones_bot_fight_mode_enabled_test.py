from unittest import mock

from prowler.providers.cloudflare.services.zones.zones_service import (
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class Test_zones_bot_fight_mode_enabled:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled import (
                zones_bot_fight_mode_enabled,
            )

            check = zones_bot_fight_mode_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_bot_fight_mode_enabled(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    browser_check="on",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled import (
                zones_bot_fight_mode_enabled,
            )

            check = zones_bot_fight_mode_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "Bot Fight Mode" in result[0].status_extended
            assert "enabled" in result[0].status_extended

    def test_zone_bot_fight_mode_disabled(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    browser_check="off",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled import (
                zones_bot_fight_mode_enabled,
            )

            check = zones_bot_fight_mode_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended

    def test_zone_bot_fight_mode_none(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    browser_check=None,
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_bot_fight_mode_enabled.zones_bot_fight_mode_enabled import (
                zones_bot_fight_mode_enabled,
            )

            check = zones_bot_fight_mode_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
