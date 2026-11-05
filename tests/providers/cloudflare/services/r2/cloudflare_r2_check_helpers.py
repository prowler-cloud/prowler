from types import SimpleNamespace
from unittest import mock

from prowler.providers.cloudflare.services.r2.r2_service import CloudflareR2Bucket
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    set_mocked_cloudflare_provider,
)

BUCKET = "my-bucket"


def make_bucket(**kwargs):
    jurisdiction = kwargs.get("jurisdiction", "default")
    return CloudflareR2Bucket(
        id=f"{ACCOUNT_ID}/{jurisdiction}/{BUCKET}",
        name=BUCKET,
        account_id=ACCOUNT_ID,
        **kwargs,
    )


def run_r2_check(check_name, buckets, list_failed=(), failed=()):
    r2_client = mock.MagicMock()
    r2_client.buckets = buckets
    r2_client.list_failed_accounts = set(list_failed)
    r2_client.dev_url_failed_accounts = set(failed)
    r2_client.custom_domains_failed_accounts = set(failed)
    r2_client.cors_failed_accounts = set(failed)
    r2_client.provider = SimpleNamespace(
        identity=SimpleNamespace(
            accounts=[SimpleNamespace(id=ACCOUNT_ID, name=ACCOUNT_NAME)]
        )
    )
    module = f"prowler.providers.cloudflare.services.r2.{check_name}.{check_name}"
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_cloudflare_provider(),
        ),
        mock.patch(f"{module}.r2_client", new=r2_client),
    ):
        check_module = __import__(module, fromlist=[check_name])
        return getattr(check_module, check_name)().execute()
