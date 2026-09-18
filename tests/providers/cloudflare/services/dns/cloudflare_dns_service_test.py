from types import SimpleNamespace
from typing import Optional

import httpx
from cloudflare import PermissionDeniedError
from pydantic import BaseModel

from prowler.providers.cloudflare.services.dns.dns_service import DNS
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
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


class TestDNSService:
    def test_cloudflare_dns_record_model(self):
        record = CloudflareDNSRecord(
            id="record-123",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            name="www.example.com",
            type="A",
            content="192.0.2.1",
            ttl=3600,
            proxied=True,
        )

        assert record.id == "record-123"
        assert record.zone_id == ZONE_ID
        assert record.zone_name == ZONE_NAME
        assert record.name == "www.example.com"
        assert record.type == "A"
        assert record.content == "192.0.2.1"
        assert record.ttl == 3600
        assert record.proxied is True

    def test_cloudflare_dns_record_defaults(self):
        record = CloudflareDNSRecord(
            id="record-123",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
        )

        assert record.id == "record-123"
        assert record.zone_id == ZONE_ID
        assert record.zone_name == ZONE_NAME
        assert record.name is None
        assert record.type is None
        assert record.content == ""
        assert record.ttl is None
        assert record.proxied is False

    def test_cloudflare_dns_record_txt(self):
        record = CloudflareDNSRecord(
            id="record-txt",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            name=ZONE_NAME,
            type="TXT",
            content="v=spf1 include:_spf.google.com ~all",
            ttl=1,
            proxied=False,
        )

        assert record.type == "TXT"
        assert "v=spf1" in record.content
        assert record.proxied is False

    def test_cloudflare_dns_record_cname(self):
        record = CloudflareDNSRecord(
            id="record-cname",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            name="www.example.com",
            type="CNAME",
            content="example.com",
            ttl=3600,
            proxied=True,
        )

        assert record.type == "CNAME"
        assert record.content == "example.com"
        assert record.proxied is True

    def test_cloudflare_dns_record_mx(self):
        record = CloudflareDNSRecord(
            id="record-mx",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            name=ZONE_NAME,
            type="MX",
            content="10 mail.example.com",
            ttl=3600,
            proxied=False,
        )

        assert record.type == "MX"
        assert "mail.example.com" in record.content

    def test_cloudflare_dns_record_caa(self):
        record = CloudflareDNSRecord(
            id="record-caa",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            name=ZONE_NAME,
            type="CAA",
            content='0 issue "letsencrypt.org"',
            ttl=3600,
            proxied=False,
        )

        assert record.type == "CAA"
        assert "letsencrypt.org" in record.content


class TestDNSServiceReadErrors:
    def _provider(self):
        provider = set_mocked_cloudflare_provider()
        provider.session.client.zones.list.return_value = [
            SimpleNamespace(
                id=ZONE_ID,
                name=ZONE_NAME,
                account=SimpleNamespace(id=ACCOUNT_ID),
            )
        ]
        return provider

    def test_forbidden_record_listing_is_recorded_per_zone(self):
        provider = self._provider()
        request = httpx.Request("GET", "https://api.cloudflare.com/client/v4/zones")
        provider.session.client.dns.records.list.side_effect = PermissionDeniedError(
            "Authentication error",
            response=httpx.Response(403, request=request),
            body=None,
        )

        dns = DNS(provider)

        assert dns.records == []
        assert dns.read_errors == {ZONE_ID: "PermissionDeniedError"}

    def test_successful_record_listing_records_no_errors(self):
        provider = self._provider()
        provider.session.client.dns.records.list.return_value = []

        assert DNS(provider).read_errors == {}
