from unittest import mock

from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareZone,
    CloudflareZoneSettings,
    StrictTransportSecurity,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class Test_zone_hsts_enabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled import (
                zone_hsts_enabled,
            )

            check = zone_hsts_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_hsts_enabled_properly_configured(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    strict_transport_security=StrictTransportSecurity(
                        enabled=True,
                        max_age=31536000,  # 1 year
                        include_subdomains=True,
                        preload=True,
                    )
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled import (
                zone_hsts_enabled,
            )

            check = zone_hsts_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "HSTS is enabled" in result[0].status_extended

    def test_zone_hsts_disabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    strict_transport_security=StrictTransportSecurity(
                        enabled=False,
                    )
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled import (
                zone_hsts_enabled,
            )

            check = zone_hsts_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "HSTS is not enabled" in result[0].status_extended

    def test_zone_hsts_enabled_no_subdomains(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    strict_transport_security=StrictTransportSecurity(
                        enabled=True,
                        max_age=31536000,
                        include_subdomains=False,
                    )
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled import (
                zone_hsts_enabled,
            )

            check = zone_hsts_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not include subdomains" in result[0].status_extended

    def test_zone_hsts_enabled_low_max_age(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    strict_transport_security=StrictTransportSecurity(
                        enabled=True,
                        max_age=3600,  # Only 1 hour
                        include_subdomains=True,
                    )
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_hsts_enabled.zone_hsts_enabled import (
                zone_hsts_enabled,
            )

            check = zone_hsts_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "max-age" in result[0].status_extended
