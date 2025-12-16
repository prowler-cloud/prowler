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


class Test_zones_challenge_passage_configured:
    def test_no_zones(self):
        zones_client = mock.MagicMock
        zones_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured import (
                zones_challenge_passage_configured,
            )

            check = zones_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 0

    def test_zone_challenge_passage_correct(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=3600,  # Recommended value
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured import (
                zones_challenge_passage_configured,
            )

            check = zones_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "3600" in result[0].status_extended

    def test_zone_challenge_passage_too_long(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=86400,  # Too long (24 hours)
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured import (
                zones_challenge_passage_configured,
            )

            check = zones_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "86400" in result[0].status_extended
            assert "recommended" in result[0].status_extended

    def test_zone_challenge_passage_too_short(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=300,  # Too short (5 minutes)
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured import (
                zones_challenge_passage_configured,
            )

            check = zones_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "300" in result[0].status_extended

    def test_zone_challenge_passage_none(self):
        zones_client = mock.MagicMock
        zones_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=None,
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured.zones_client",
                new=zones_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zones.zones_challenge_passage_configured.zones_challenge_passage_configured import (
                zones_challenge_passage_configured,
            )

            check = zones_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
