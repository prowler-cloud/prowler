from unittest import mock

from prowler.providers.cloudflare.services.zones.zones_service import (
    CloudflareZone,
    CloudflareZoneSettings,
    StrictTransportSecurity,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class Test_zones_hsts_include_subdomains:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains import (
                zones_hsts_include_subdomains,
            )

            check = zones_hsts_include_subdomains()
            result = check.execute()
            assert len(result) == 0

    def test_zone_hsts_enabled_with_subdomains(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    strict_transport_security=StrictTransportSecurity(
                        enabled=True,
                        max_age=31536000,
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
                "prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains import (
                zones_hsts_include_subdomains,
            )

            check = zones_hsts_include_subdomains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "includeSubDomains" in result[0].status_extended

    def test_zone_hsts_enabled_without_subdomains(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
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
                "prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains import (
                zones_hsts_include_subdomains,
            )

            check = zones_hsts_include_subdomains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not include subdomains" in result[0].status_extended

    def test_zone_hsts_disabled(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
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
                "prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_hsts_include_subdomains.zones_hsts_include_subdomains import (
                zones_hsts_include_subdomains,
            )

            check = zones_hsts_include_subdomains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "HSTS is not enabled" in result[0].status_extended
