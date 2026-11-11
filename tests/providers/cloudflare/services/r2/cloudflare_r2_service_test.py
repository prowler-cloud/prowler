from types import SimpleNamespace

import httpx
from cloudflare import NotFoundError, PermissionDeniedError

from prowler.providers.cloudflare.services.r2.r2_service import (
    R2,
    R2_BUCKETS_PAGE_SIZE,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    set_mocked_cloudflare_provider,
)


def _not_found():
    request = httpx.Request("GET", "https://api.cloudflare.com")
    return NotFoundError(
        "not found", response=httpx.Response(404, request=request), body=None
    )


def _forbidden():
    request = httpx.Request("GET", "https://api.cloudflare.com")
    return PermissionDeniedError(
        "access denied", response=httpx.Response(403, request=request), body=None
    )


def _provider():
    provider = set_mocked_cloudflare_provider()
    client = provider.session.client

    def list_buckets(account_id, jurisdiction, **kwargs):
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
        raise _forbidden()

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
        # IDs are qualified: names are only unique per account and jurisdiction
        assert public.id == f"{ACCOUNT_ID}/default/public-bucket"
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
        assert eu.id == f"{ACCOUNT_ID}/eu/eu-bucket"
        assert eu.jurisdiction == "eu"
        assert eu.public_dev_url_enabled is False
        # error retrieving custom domains -> unknown, tracked for MANUAL
        assert eu.custom_domains is None
        assert service.custom_domains_failed_accounts == {ACCOUNT_ID}
        # fedramp is optional: its 403 is not a listing failure
        assert service.list_failed_accounts == set()
        # 404 on CORS -> no policy
        assert eu.cors_rules == []

        provider.session.client.r2.buckets.cors.get.assert_any_call(
            bucket_name="eu-bucket", account_id=ACCOUNT_ID, jurisdiction="eu"
        )

    def test_list_follows_pagination(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        names = [f"bucket-{i:05d}" for i in range(R2_BUCKETS_PAGE_SIZE + 1)]
        calls = []

        def list_buckets(account_id, jurisdiction, per_page, start_after=None):
            calls.append((jurisdiction, start_after))
            if jurisdiction != "default":
                return SimpleNamespace(buckets=[])
            start = names.index(start_after) + 1 if start_after else 0
            return SimpleNamespace(
                buckets=[
                    SimpleNamespace(name=n, jurisdiction="default")
                    for n in names[start : start + per_page]
                ]
            )

        client.r2.buckets.list.side_effect = list_buckets
        service = R2(provider)

        assert len(service.buckets) == R2_BUCKETS_PAGE_SIZE + 1
        assert calls[:2] == [
            ("default", None),
            ("default", names[R2_BUCKETS_PAGE_SIZE - 1]),
        ]

    def test_list_stops_when_api_does_not_advance(self):
        provider = set_mocked_cloudflare_provider()
        full_page = [
            SimpleNamespace(name="same", jurisdiction="default")
        ] * R2_BUCKETS_PAGE_SIZE
        provider.session.client.r2.buckets.list.return_value = SimpleNamespace(
            buckets=full_page
        )
        service = R2(provider)
        # one bucket per jurisdiction after deduplication, and no infinite loop
        assert [b.name for b in service.buckets] == ["same"]

    def test_unique_name_includes_non_default_jurisdiction(self):
        provider = _provider()
        buckets = {b.name: b for b in R2(provider).buckets}
        assert buckets["public-bucket"].unique_name == "public-bucket"
        assert buckets["eu-bucket"].unique_name == "eu/eu-bucket"

    def test_fedramp_non_permission_error_is_reported(self):
        provider = set_mocked_cloudflare_provider()

        def list_buckets(account_id, jurisdiction, **kwargs):
            if jurisdiction == "fedramp":
                raise Exception("500 internal error")
            return SimpleNamespace(buckets=[])

        provider.session.client.r2.buckets.list.side_effect = list_buckets
        assert R2(provider).list_failed_accounts == {ACCOUNT_ID}

    def test_eu_listing_failure_is_reported(self):
        provider = set_mocked_cloudflare_provider()

        def list_buckets(account_id, jurisdiction, **kwargs):
            if jurisdiction == "eu":
                raise Exception("eu boom")
            return SimpleNamespace(buckets=[])

        provider.session.client.r2.buckets.list.side_effect = list_buckets
        assert R2(provider).list_failed_accounts == {ACCOUNT_ID}

    def test_list_error(self):
        provider = set_mocked_cloudflare_provider()
        provider.session.client.r2.buckets.list.side_effect = Exception("boom")
        assert R2(provider).buckets == []
