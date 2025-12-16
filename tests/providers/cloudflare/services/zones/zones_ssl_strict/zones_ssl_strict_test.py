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


class Test_zones_ssl_strict:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict import (
                zones_ssl_strict,
            )

            check = zones_ssl_strict()
            result = check.execute()
            assert len(result) == 0

    def test_zone_ssl_strict_mode(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    ssl_encryption_mode="strict",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict import (
                zones_ssl_strict,
            )

            check = zones_ssl_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "strict" in result[0].status_extended

    def test_zone_ssl_full_strict_mode(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    ssl_encryption_mode="full_strict",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict import (
                zones_ssl_strict,
            )

            check = zones_ssl_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "full_strict" in result[0].status_extended

    def test_zone_ssl_full_mode(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    ssl_encryption_mode="full",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict import (
                zones_ssl_strict,
            )

            check = zones_ssl_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "full" in result[0].status_extended

    def test_zone_ssl_flexible_mode(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    ssl_encryption_mode="flexible",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict import (
                zones_ssl_strict,
            )

            check = zones_ssl_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "flexible" in result[0].status_extended

    def test_zone_ssl_off_mode(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    ssl_encryption_mode="off",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_ssl_strict.zones_ssl_strict import (
                zones_ssl_strict,
            )

            check = zones_ssl_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
