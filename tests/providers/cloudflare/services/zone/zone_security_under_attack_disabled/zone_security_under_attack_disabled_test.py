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


class Test_zone_security_under_attack_disabled:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled import (
                zone_security_under_attack_disabled,
            )

            check = zone_security_under_attack_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_zone_under_attack_mode_enabled(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    security_level="under_attack",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled import (
                zone_security_under_attack_disabled,
            )

            check = zone_security_under_attack_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Zone {ZONE_NAME} has Under Attack Mode enabled."
            )

    def test_zone_security_level_high(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    security_level="high",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled import (
                zone_security_under_attack_disabled,
            )

            check = zone_security_under_attack_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Zone {ZONE_NAME} does not have Under Attack Mode enabled."
            )

    def test_zone_security_level_medium(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    security_level="medium",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled import (
                zone_security_under_attack_disabled,
            )

            check = zone_security_under_attack_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_zone_security_level_low(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    security_level="low",
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled import (
                zone_security_under_attack_disabled,
            )

            check = zone_security_under_attack_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_zone_security_level_none(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    security_level=None,
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_security_under_attack_disabled.zone_security_under_attack_disabled import (
                zone_security_under_attack_disabled,
            )

            check = zone_security_under_attack_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
