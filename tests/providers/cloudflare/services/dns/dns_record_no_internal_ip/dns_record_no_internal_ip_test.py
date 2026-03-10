from typing import Optional
from unittest import mock

from pydantic import BaseModel

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


class Test_dns_record_no_internal_ip:
    def test_no_records(self):
        dns_client = mock.MagicMock
        dns_client.records = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 0

    def test_non_ip_record(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="CNAME",
                content="example.com",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 0

    def test_a_record_public_ip(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="A",
                content="8.8.8.8",  # Google DNS - a truly public IP
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "record-1"
            assert result[0].resource_name == "www.example.com"
            assert result[0].status == "PASS"
            assert "public IP address" in result[0].status_extended

    def test_a_record_private_ip_10(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="internal.example.com",
                type="A",
                content="10.0.0.1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "internal IP address" in result[0].status_extended
            assert "information disclosure risk" in result[0].status_extended

    def test_a_record_private_ip_172(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="internal.example.com",
                type="A",
                content="172.16.0.1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "internal IP address" in result[0].status_extended

    def test_a_record_private_ip_192(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="internal.example.com",
                type="A",
                content="192.168.1.1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "internal IP address" in result[0].status_extended

    def test_a_record_loopback(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="localhost.example.com",
                type="A",
                content="127.0.0.1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "internal IP address" in result[0].status_extended

    def test_aaaa_record_public_ip(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="AAAA",
                content="2001:db8::1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            # 2001:db8:: is documentation prefix and is reserved
            assert result[0].status == "FAIL"

    def test_aaaa_record_link_local(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="internal.example.com",
                type="AAAA",
                content="fe80::1",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_internal_ip.dns_record_no_internal_ip import (
                dns_record_no_internal_ip,
            )

            check = dns_record_no_internal_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "internal IP address" in result[0].status_extended
