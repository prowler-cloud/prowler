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


class Test_zone_automatic_https_rewrites_enabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled import (
                zone_automatic_https_rewrites_enabled,
            )

            check = zone_automatic_https_rewrites_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_automatic_https_rewrites_enabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    automatic_https_rewrites="on",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled import (
                zone_automatic_https_rewrites_enabled,
            )

            check = zone_automatic_https_rewrites_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "Automatic HTTPS Rewrites is enabled" in result[0].status_extended

    def test_zone_automatic_https_rewrites_disabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    automatic_https_rewrites="off",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled import (
                zone_automatic_https_rewrites_enabled,
            )

            check = zone_automatic_https_rewrites_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Automatic HTTPS Rewrites is not enabled" in result[0].status_extended
            )

    def test_zone_automatic_https_rewrites_none(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    automatic_https_rewrites=None,
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_automatic_https_rewrites_enabled.zone_automatic_https_rewrites_enabled import (
                zone_automatic_https_rewrites_enabled,
            )

            check = zone_automatic_https_rewrites_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Automatic HTTPS Rewrites is not enabled" in result[0].status_extended
            )
