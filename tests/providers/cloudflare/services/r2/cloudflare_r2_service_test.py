from types import SimpleNamespace

import httpx
from cloudflare import NotFoundError

from prowler.providers.cloudflare.services.r2.r2_service import R2
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    set_mocked_cloudflare_provider,
)


def _not_found():
    request = httpx.Request("GET", "https://api.cloudflare.com")
    return NotFoundError(
        "not found", response=httpx.Response(404, request=request), body=None
    )


def _provider():
    provider = set_mocked_cloudflare_provider()
    client = provider.session.client

    def list_buckets(account_id, jurisdiction):
        if jurisdiction == "default":
            return SimpleNamespace(
                buckets=[
                    SimpleNamespace(
                        name="public-bucket",
                        jurisdiction="default",
                        location="weur",
                        creation_date="2026-01-01",
                    ),
                    SimpleNamespace(name="public-bucket", jurisdiction="default"),
                ]
            )
        if jurisdiction == "eu":
            return SimpleNamespace(
                buckets=[SimpleNamespace(name="eu-bucket", jurisdiction="eu")]
            )
        raise Exception("fedramp not enabled")

    client.r2.buckets.list.side_effect = list_buckets

    def managed(bucket_name, account_id, jurisdiction):
        return SimpleNamespace(
            enabled=bucket_name == "public-bucket",
            domain=f"pub-{bucket_name}.r2.dev",
        )

    client.r2.buckets.domains.managed.list.side_effect = managed

    def custom(bucket_name, account_id, jurisdiction):
        if bucket_name == "eu-bucket":
            raise Exception("boom")
        return SimpleNamespace(
            domains=[
                SimpleNamespace(domain="assets.example.com", enabled=True, min_tls=None)
            ]
        )

    client.r2.buckets.domains.custom.list.side_effect = custom

    def cors(bucket_name, account_id, jurisdiction):
        if bucket_name == "eu-bucket":
            raise _not_found()
        return SimpleNamespace(
            rules=[
                SimpleNamespace(
                    allowed=SimpleNamespace(origins=["*"], methods=["GET", "PUT"])
                )
            ]
        )

    client.r2.buckets.cors.get.side_effect = cors
    return provider


class TestR2Service:
    def test_service(self):
        provider = _provider()
        service = R2(provider)

        assert service.service == "r2"
        buckets = {b.name: b for b in service.buckets}
        assert set(buckets) == {"public-bucket", "eu-bucket"}

        public = buckets["public-bucket"]
        assert public.id == "public-bucket"
        assert public.account_id == ACCOUNT_ID
        assert public.jurisdiction == "default"
        assert public.location == "weur"
        assert public.public_dev_url_enabled is True
        assert public.public_dev_url == "pub-public-bucket.r2.dev"
        assert public.custom_domains[0].domain == "assets.example.com"
        assert public.custom_domains[0].min_tls is None
        assert public.cors_rules[0].origins == ["*"]
        assert public.cors_rules[0].methods == ["GET", "PUT"]

        eu = buckets["eu-bucket"]
        assert eu.jurisdiction == "eu"
        assert eu.public_dev_url_enabled is False
        # error retrieving custom domains -> unknown
        assert eu.custom_domains is None
        # 404 on CORS -> no policy
        assert eu.cors_rules == []

        provider.session.client.r2.buckets.cors.get.assert_any_call(
            bucket_name="eu-bucket", account_id=ACCOUNT_ID, jurisdiction="eu"
        )

    def test_list_error(self):
        provider = set_mocked_cloudflare_provider()
        provider.session.client.r2.buckets.list.side_effect = Exception("boom")
        assert R2(provider).buckets == []
