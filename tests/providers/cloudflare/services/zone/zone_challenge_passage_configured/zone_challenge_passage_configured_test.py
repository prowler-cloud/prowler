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


class Test_zone_challenge_passage_configured:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 0

    def test_zone_challenge_passage_at_min(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=900,  # 15 minutes - minimum recommended
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert "15 minutes" in result[0].status_extended

    def test_zone_challenge_passage_at_max(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=2700,  # 45 minutes - maximum recommended
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "45 minutes" in result[0].status_extended

    def test_zone_challenge_passage_default(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=1800,  # 30 minutes - default and secure
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "30 minutes" in result[0].status_extended

    def test_zone_challenge_passage_too_short(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=300,  # 5 minutes - too short
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "5 minutes" in result[0].status_extended
            assert "recommended" in result[0].status_extended

    def test_zone_challenge_passage_too_long(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(
                    challenge_ttl=3600,  # 60 minutes - exceeds recommended
                ),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "60 minutes" in result[0].status_extended
            assert "recommended" in result[0].status_extended

    def test_zone_challenge_passage_none(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
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
                "prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured.zone_client",
                new=zone_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_challenge_passage_configured.zone_challenge_passage_configured import (
                zone_challenge_passage_configured,
            )

            check = zone_challenge_passage_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
