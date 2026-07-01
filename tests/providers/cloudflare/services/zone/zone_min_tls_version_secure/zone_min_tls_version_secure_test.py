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


class Test_zone_min_tls_version_secure:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}
        zone_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure import (
                zone_min_tls_version_secure,
            )

            check = zone_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 0

    def test_zone_tls_version_secure(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
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
        zone_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure import (
                zone_min_tls_version_secure,
            )

            check = zone_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "1.2" in result[0].status_extended

    def test_zone_tls_version_1_3(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
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
        zone_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure import (
                zone_min_tls_version_secure,
            )

            check = zone_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_zone_tls_version_insecure(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
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
        zone_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure import (
                zone_min_tls_version_secure,
            )

            check = zone_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].status == "FAIL"
            assert "1.0" in result[0].status_extended
            assert "below the recommended" in result[0].status_extended

    def test_zone_tls_version_1_1(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
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
        zone_client.audit_config = {"min_tls_version": "1.2"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_min_tls_version_secure.zone_min_tls_version_secure import (
                zone_min_tls_version_secure,
            )

            check = zone_min_tls_version_secure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
