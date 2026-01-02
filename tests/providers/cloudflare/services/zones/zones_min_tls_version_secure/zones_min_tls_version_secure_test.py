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


class Test_zones_min_tls_version_secure:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}
        zones_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure import (
                zones_min_tls_version_secure,
            )

            check = zones_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 0

    def test_zone_tls_version_secure(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    min_tls_version="1.2",
                ),
            )
        }
        zones_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure import (
                zones_min_tls_version_secure,
            )

            check = zones_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "1.2" in result[0].status_extended

    def test_zone_tls_version_1_3(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    min_tls_version="1.3",
                ),
            )
        }
        zones_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure import (
                zones_min_tls_version_secure,
            )

            check = zones_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_zone_tls_version_insecure(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    min_tls_version="1.0",
                ),
            )
        }
        zones_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure import (
                zones_min_tls_version_secure,
            )

            check = zones_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].status == "FAIL"
            assert "1.0" in result[0].status_extended
            assert "below the recommended" in result[0].status_extended

    def test_zone_tls_version_1_1(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    min_tls_version="1.1",
                ),
            )
        }
        zones_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_min_tls_version_secure.zones_min_tls_version_secure import (
                zones_min_tls_version_secure,
            )

            check = zones_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
