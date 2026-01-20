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


class Test_dns_record_no_wildcard:
    def test_no_records(self):
        dns_client = mock.MagicMock
        dns_client.records = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 0

    def test_non_ip_record(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="example.com",
                type="TXT",
                content="v=spf1 include:_spf.google.com ~all",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 0

    def test_a_record_not_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="www.example.com",
                type="A",
                content="8.8.8.8",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "record-1"
            assert result[0].resource_name == "www.example.com"
            assert result[0].status == "PASS"
            assert "is not a wildcard record" in result[0].status_extended

    def test_a_record_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="*.example.com",
                type="A",
                content="8.8.8.8",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is a wildcard record" in result[0].status_extended
            assert "may expose unintended services" in result[0].status_extended

    def test_aaaa_record_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="*.example.com",
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
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is a wildcard record" in result[0].status_extended

    def test_cname_record_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="*.example.com",
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
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is a wildcard record" in result[0].status_extended

    def test_cname_record_not_wildcard(self):
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
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not a wildcard record" in result[0].status_extended

    def test_mx_record_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="*.example.com",
                type="MX",
                content="10 mail.example.com",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is a wildcard record" in result[0].status_extended

    def test_mx_record_not_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="example.com",
                type="MX",
                content="10 mail.example.com",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not a wildcard record" in result[0].status_extended

    def test_srv_record_wildcard(self):
        dns_client = mock.MagicMock
        dns_client.records = [
            CloudflareDNSRecord(
                id="record-1",
                zone_id=ZONE_ID,
                zone_name=ZONE_NAME,
                name="*._tcp.example.com",
                type="SRV",
                content="10 5 5060 sip.example.com",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_cloudflare_provider(),
            ),
            mock.patch(
                "prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.cloudflare.services.dns.dns_record_no_wildcard.dns_record_no_wildcard import (
                dns_record_no_wildcard,
            )

            check = dns_record_no_wildcard()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is a wildcard record" in result[0].status_extended
