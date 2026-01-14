from typing import Optional
from unittest import mock

from pydantic import BaseModel

from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


class CloudflareDNSRecord(BaseModel):
    """Cloudflare DNS record representation for testing."""

    id: str
    zone_id: str
    zone_name: str
    name: Optional[str] = None
    type: Optional[str] = None
    content: str = ""
    ttl: Optional[int] = None
    proxied: bool = False


class Test_zone_record_caa_exists:
    def test_no_zones(self):
        zone_client = mock.MagicMock
        zone_client.zones = {}

        dns_client = mock.MagicMock
        dns_client.records = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists import (
                zone_record_caa_exists,
            )

            check = zone_record_caa_exists()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_caa_record_issue_tag(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=ZONE_NAME,
                type="CAA",
                content='0 issue "letsencrypt.org"',
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists import (
                zone_record_caa_exists,
            )

            check = zone_record_caa_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CAA record with certificate issuance restrictions exists for zone {ZONE_NAME}: {ZONE_NAME}."
            )

    def test_zone_with_multiple_caa_records(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=ZONE_NAME,
                type="CAA",
                content='0 issue "letsencrypt.org"',
            ),
            CloudflareDNSRecord(
                id="record-2",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=ZONE_NAME,
                type="CAA",
                content='0 issuewild ";"',
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists import (
                zone_record_caa_exists,
            )

            check = zone_record_caa_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CAA record with certificate issuance restrictions exists for zone {ZONE_NAME}: {ZONE_NAME}, {ZONE_NAME}."
            )

    def test_zone_with_caa_record_only_iodef(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=ZONE_NAME,
                type="CAA",
                content='0 iodef "mailto:security@example.com"',
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists import (
                zone_record_caa_exists,
            )

            check = zone_record_caa_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CAA record exists for zone {ZONE_NAME} but does not specify authorized CAs with issue or issuewild tags: {ZONE_NAME}."
            )

    def test_zone_without_caa_record(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=ZONE_NAME,
                type="A",
                content="192.0.2.1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists import (
                zone_record_caa_exists,
            )

            check = zone_record_caa_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No CAA record found for zone {ZONE_NAME}."
            )

    def test_zone_with_caa_record_for_different_zone(self):
        zone_client = mock.MagicMock
        zone_client.zones = {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
            )
        }

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id="other-zone-id",
                zone_name="other.com",
                name="other.com",
                type="CAA",
                content='0 issue "letsencrypt.org"',
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_caa_exists.zone_record_caa_exists import (
                zone_record_caa_exists,
            )

            check = zone_record_caa_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No CAA record found for zone {ZONE_NAME}."
            )
