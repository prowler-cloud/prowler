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


class Test_dns_record_proxied:
    def test_no_records(self):
        dns_client = mock.MagicMock
        dns_client.records = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 0

    def test_non_proxyable_record(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="example.com",
                type="TXT",
                content="v=spf1 include:_spf.google.com ~all",
                proxied=False,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 0

    def test_a_record_proxied(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="A",
                content="8.8.8.8",
                proxied=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "record-1"
            assert result[0].resource_name == "www.example.com"
            assert result[0].status == "PASS"
            assert "is proxied through Cloudflare" in result[0].status_extended
            # DNS records should have zone_name as region
            assert result[0].region == ZONE_NAME
            assert result[0].zone_name == ZONE_NAME

    def test_a_record_not_proxied(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="A",
                content="8.8.8.8",
                proxied=False,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is not proxied through Cloudflare" in result[0].status_extended

    def test_aaaa_record_proxied(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="AAAA",
                content="2001:db8::1",
                proxied=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is proxied through Cloudflare" in result[0].status_extended

    def test_aaaa_record_not_proxied(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="AAAA",
                content="2001:db8::1",
                proxied=False,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is not proxied through Cloudflare" in result[0].status_extended

    def test_cname_record_proxied(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="CNAME",
                content="example.com",
                proxied=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is proxied through Cloudflare" in result[0].status_extended

    def test_cname_record_not_proxied(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="CNAME",
                content="example.com",
                proxied=False,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_proxied.dns_record_proxied import (
                dns_record_proxied,
            )

            check = dns_record_proxied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is not proxied through Cloudflare" in result[0].status_extended
