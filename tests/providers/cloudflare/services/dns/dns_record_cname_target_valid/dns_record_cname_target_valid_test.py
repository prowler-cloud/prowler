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


class Test_dns_record_cname_target_valid:
    def test_no_records(self):
        dns_client = mock.MagicMock
        dns_client.records = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid import (
                dns_record_cname_target_valid,
            )

            check = dns_record_cname_target_valid()
            result = check.execute()
            assert len(result) == 0

    def test_non_cname_record(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
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
                "prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid import (
                dns_record_cname_target_valid,
            )

            check = dns_record_cname_target_valid()
            result = check.execute()
            assert len(result) == 0

    def test_cname_record_valid_target(self):
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
                "prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid.dns_client",
                new=dns_client,
            ),
            mock.patch(
                "socket.getaddrinfo",
                return_value=[("", "", "", "", ("192.0.2.1", 0))],
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid import (
                dns_record_cname_target_valid,
            )

            check = dns_record_cname_target_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "record-1"
            assert result[0].resource_name == "www.example.com"
            assert result[0].status == "PASS"
            assert "points to valid target" in result[0].status_extended

    def test_cname_record_dangling_target(self):
        import socket

        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="old.example.com",
                type="CNAME",
                content="nonexistent.example.com",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid.dns_client",
                new=dns_client,
            ),
            mock.patch(
                "socket.getaddrinfo",
                side_effect=socket.gaierror("Name or service not known"),
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid import (
                dns_record_cname_target_valid,
            )

            check = dns_record_cname_target_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "potentially dangling target" in result[0].status_extended
            assert "subdomain takeover risk" in result[0].status_extended

    def test_cname_record_with_trailing_dot(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="CNAME",
                content="example.com.",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid.dns_client",
                new=dns_client,
            ),
            mock.patch(
                "socket.getaddrinfo",
                return_value=[("", "", "", "", ("192.0.2.1", 0))],
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_cname_target_valid.dns_record_cname_target_valid import (
                dns_record_cname_target_valid,
            )

            check = dns_record_cname_target_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
