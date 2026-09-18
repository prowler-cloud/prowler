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


# Valid DKIM public key for testing (real RSA 2048-bit key in DER SubjectPublicKeyInfo format)
# This is a complete valid RSA public key that can be loaded by cryptography library
VALID_DKIM_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp4czBy2GlDrezAtyoKtrqZYpTLMsuJz1HjV0wZ/yIpClhKp5f8xGlAJuxOjxWokz5SoyW/XpmUtIPkFYwj90jlvUVkFhh9Q81BlJ/0DmhNnmIOs9MnVzgnLiUfNv06NQeKg3d65reCWNjEyrb1fDP6U4ePKM/lunTQc5CbHEUnSnU43vXpUO8v1TYb6OGeAKhumfVSdXFBF905c43/sqkt2QeRMabIoWPkYlSI0KSV0qhNpcRtOdfntFSyPljwa7iNVLlV9AckdL4+abOiy8zuYW0GDF5/1Jgl/Xbdab2M70AXuFnYldq6EgkhvyyiGEm7/15H5STgKxp8idarb6XQIDAQAB"


class Test_zone_record_dkim_exists:
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
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 0

    def test_zone_with_dkim_record_valid_key(self):
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                content=f"v=DKIM1; k=rsa; p={VALID_DKIM_KEY}",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ZONE_ID
            assert result[0].resource_name == ZONE_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DKIM record with valid public key exists for zone {ZONE_NAME}: google._domainkey.{ZONE_NAME}."
            )

    def test_zone_with_multiple_dkim_records(self):
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                content=f"v=DKIM1; k=rsa; p={VALID_DKIM_KEY}",
            ),
            CloudflareDNSRecord(
                id="record-2",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=f"selector1._domainkey.{ZONE_NAME}",
                type="TXT",
                content=f"v=DKIM1; k=rsa; p={VALID_DKIM_KEY}",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DKIM record with valid public key exists for zone {ZONE_NAME}: google._domainkey.{ZONE_NAME}, selector1._domainkey.{ZONE_NAME}."
            )

    def test_zone_with_dkim_record_revoked_key(self):
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                content="v=DKIM1; k=rsa; p=",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DKIM record exists for zone {ZONE_NAME} but has invalid or missing public key: google._domainkey.{ZONE_NAME}."
            )

    def test_zone_with_dkim_record_invalid_key_not_real_public_key(self):
        """Test that valid Base64 that is not a real public key fails."""
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                # Valid Base64 but not a valid DER-encoded public key
                content="v=DKIM1; k=rsa; p=SGVsbG9Xb3JsZFRoaXNJc05vdEFWYWxpZFB1YmxpY0tleUJ1dEl0SXNWYWxpZEJhc2U2NA==",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DKIM record exists for zone {ZONE_NAME} but has invalid or missing public key: google._domainkey.{ZONE_NAME}."
            )

    def test_zone_with_dkim_record_invalid_base64(self):
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                # Invalid Base64 - contains characters not valid in Base64 and is long enough
                content="v=DKIM1; k=rsa; p=ThisIsNotValidBase64!!!@@@###$$$%%%^^^&&&***Because_It_Contains_Invalid_Characters_And_Is_Long_Enough_To_Pass_Length_Check",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DKIM record exists for zone {ZONE_NAME} but has invalid or missing public key: google._domainkey.{ZONE_NAME}."
            )

    def test_zone_without_dkim_record(self):
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
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No DKIM record found for zone {ZONE_NAME}."
            )

    def test_zone_with_domainkey_but_not_dkim(self):
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                content="some other txt record",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No DKIM record found for zone {ZONE_NAME}."
            )

    def test_zone_with_dkim_record_lowercase(self):
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
                name=f"default._domainkey.{ZONE_NAME}",
                type="TXT",
                content=f"v=dkim1; k=rsa; p={VALID_DKIM_KEY}",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DKIM record with valid public key exists for zone {ZONE_NAME}: default._domainkey.{ZONE_NAME}."
            )

    def test_zone_with_dkim_record_different_zone(self):
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
                name="google._domainkey.other.com",
                type="TXT",
                content=f"v=DKIM1; k=rsa; p={VALID_DKIM_KEY}",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No DKIM record found for zone {ZONE_NAME}."
            )

    def test_zone_with_dkim_record_quoted_content(self):
        """Test that DKIM records with quoted content from Cloudflare API work."""
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
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                # Cloudflare API returns content wrapped in quotes
                content=f'"v=DKIM1; k=rsa; p={VALID_DKIM_KEY}"',
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DKIM record with valid public key exists for zone {ZONE_NAME}: google._domainkey.{ZONE_NAME}."
            )

    def test_zone_with_dkim_record_split_quoted_content(self):
        """Test that long DKIM records split into multiple quoted strings work."""
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

        # Split the key to simulate how Cloudflare returns long TXT records
        # The split happens in the middle of the p= value with '" "' between parts
        key_part1 = VALID_DKIM_KEY[:200]
        key_part2 = VALID_DKIM_KEY[200:]

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name=f"google._domainkey.{ZONE_NAME}",
                type="TXT",
                # Cloudflare splits long TXT records with '" "' between parts
                content=f'v=DKIM1; k=rsa; p={key_part1}" "{key_part2}',
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.zone_client",
                new=zone_client,
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.zone.zone_record_dkim_exists.zone_record_dkim_exists import (
                zone_record_dkim_exists,
            )

            check = zone_record_dkim_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DKIM record with valid public key exists for zone {ZONE_NAME}: google._domainkey.{ZONE_NAME}."
            )
