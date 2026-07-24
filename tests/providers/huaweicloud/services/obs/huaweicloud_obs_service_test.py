from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.obs.obs_service import OBS, Bucket
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(service_client):
    """Return a mocked provider whose single (global) client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.session.client = mock.MagicMock(return_value=service_client)
    return provider


def _buckets_response(*bucket_items):
    """Wrap bucket items in the nested OBS SDK response shape (.buckets.bucket)."""
    return SimpleNamespace(buckets=SimpleNamespace(bucket=list(bucket_items)))


class TestOBSService:
    def test_list_buckets_parses_buckets(self):
        bucket_items = [
            SimpleNamespace(name="public-acl", location="ap-southeast-1"),
            SimpleNamespace(name="public-policy", location="ap-southeast-2"),
            SimpleNamespace(name="private-bucket", location=None),
        ]
        service_client = mock.MagicMock(region=REGION)
        service_client.list_buckets.return_value = _buckets_response(*bucket_items)

        def public_status(request):
            # public-acl is public via the bucket public status endpoint.
            return SimpleNamespace(is_public=request.bucket_name == "public-acl")

        def policy_public_status(request):
            # public-policy is public via the bucket policy public status endpoint.
            return SimpleNamespace(is_public=request.bucket_name == "public-policy")

        service_client.get_bucket_public_status.side_effect = public_status
        service_client.get_bucket_policy_public_status.side_effect = (
            policy_public_status
        )

        obs = OBS(_provider_with_client(service_client))

        assert len(obs.buckets) == 3
        by_name = {bucket.name: bucket for bucket in obs.buckets}

        acl_public = by_name["public-acl"]
        assert isinstance(acl_public, Bucket)
        assert acl_public.region == "ap-southeast-1"
        assert acl_public.is_public is True
        assert acl_public.acl == "public"

        # Public via the policy status endpoint (bucket public status is False).
        policy_public = by_name["public-policy"]
        assert policy_public.region == "ap-southeast-2"
        assert policy_public.is_public is True
        assert policy_public.acl == "public"

        # Neither endpoint reports public; location None falls back to the region.
        private = by_name["private-bucket"]
        assert private.region == REGION
        assert private.is_public is False
        assert private.acl == "private"

    def test_list_buckets_empty(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_buckets.return_value = _buckets_response()

        obs = OBS(_provider_with_client(service_client))

        assert obs.buckets == []

    def test_list_buckets_handles_sdk_error(self):
        service_client = mock.MagicMock(region=REGION)
        service_client.list_buckets.side_effect = Exception("boom")

        obs = OBS(_provider_with_client(service_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert obs.buckets == []
