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

    def test_list_buckets_parses_object_lock(self):
        from huaweicloudsdkcore.exceptions.exceptions import (
            ClientRequestException,
            SdkError,
        )

        bucket_items = [
            SimpleNamespace(name="locked", location="cn-north-4"),
            SimpleNamespace(name="unlocked-404", location="cn-north-4"),
            SimpleNamespace(name="error-500", location="cn-north-4"),
        ]
        service_client = mock.MagicMock(region=REGION)
        service_client.list_buckets.return_value = _buckets_response(*bucket_items)
        service_client.get_bucket_public_status.return_value = SimpleNamespace(
            is_public=False
        )
        service_client.get_bucket_policy_public_status.return_value = SimpleNamespace(
            is_public=False
        )

        def object_lock(request):
            if request.bucket_name == "locked":
                return SimpleNamespace(
                    object_lock_configuration=SimpleNamespace(
                        object_lock_enabled="Enabled"
                    )
                )
            if request.bucket_name == "unlocked-404":
                raise ClientRequestException(
                    404,
                    SdkError(
                        error_msg="Not Found",
                        error_code="ObjectLockConfigurationNotFoundError",
                        request_id="req-1",
                    ),
                )
            raise Exception("Internal Server Error")

        service_client.get_bucket_object_lock.side_effect = object_lock

        obs = OBS(_provider_with_client(service_client))

        by_name = {bucket.name: bucket for bucket in obs.buckets}
        assert by_name["locked"].object_lock_enabled is True
        assert by_name["unlocked-404"].object_lock_enabled is False
        assert by_name["error-500"].object_lock_enabled is None

    def test_list_buckets_parses_metadata_notification_and_acl(self):
        from huaweicloudsdkcore.exceptions.exceptions import (
            ClientRequestException,
            SdkError,
        )

        bucket_items = [
            SimpleNamespace(name="hardened", location="cn-north-4"),
            SimpleNamespace(name="risky", location="cn-north-4"),
            SimpleNamespace(name="errored", location="cn-north-4"),
        ]
        service_client = mock.MagicMock(region=REGION)
        service_client.list_buckets.return_value = _buckets_response(*bucket_items)
        service_client.get_bucket_public_status.return_value = SimpleNamespace(
            is_public=False
        )
        service_client.get_bucket_policy_public_status.return_value = SimpleNamespace(
            is_public=False
        )
        service_client.get_bucket_object_lock.return_value = SimpleNamespace(
            object_lock_configuration=None
        )

        def metadata(request):
            if request.bucket_name == "hardened":
                return SimpleNamespace(
                    x_obs_az_redundancy="3az",
                    access_control_allow_origin="https://example.com",
                )
            if request.bucket_name == "risky":
                return SimpleNamespace(
                    x_obs_az_redundancy=None,
                    access_control_allow_origin="*",
                )
            raise Exception("Metadata failed")

        def notification(request):
            if request.bucket_name == "hardened":
                return SimpleNamespace(
                    notification_configuration=SimpleNamespace(
                        topic_configuration=[SimpleNamespace(id="topic-1")],
                        function_stage_configuration=[],
                    )
                )
            if request.bucket_name == "risky":
                raise ClientRequestException(
                    404,
                    SdkError(
                        error_msg="Not Found",
                        error_code="NoSuchNotificationConfiguration",
                        request_id="req-2",
                    ),
                )
            raise Exception("Notification failed")

        def acl(request):
            if request.bucket_name == "hardened":
                return SimpleNamespace(
                    access_control_list=SimpleNamespace(
                        grant=[
                            SimpleNamespace(
                                grantee=SimpleNamespace(id="owner-1", canned=None),
                                permission="FULL_CONTROL",
                            )
                        ]
                    )
                )
            if request.bucket_name == "risky":
                return SimpleNamespace(
                    access_control_list=SimpleNamespace(
                        grant=[
                            SimpleNamespace(
                                grantee=SimpleNamespace(id=None, canned="Everyone"),
                                permission="READ",
                            )
                        ]
                    )
                )
            raise Exception("ACL failed")

        service_client.get_bucket_metadata.side_effect = metadata
        service_client.get_bucket_notification.side_effect = notification
        service_client.get_bucket_acl.side_effect = acl

        obs = OBS(_provider_with_client(service_client))

        by_name = {bucket.name: bucket for bucket in obs.buckets}

        assert by_name["hardened"].az_redundancy == "3az"
        assert by_name["hardened"].cors_allow_origin == "https://example.com"
        assert by_name["hardened"].event_notification_enabled is True
        assert by_name["hardened"].acl_everyone_permissions == []

        assert by_name["risky"].az_redundancy == ""
        assert by_name["risky"].cors_allow_origin == "*"
        assert by_name["risky"].event_notification_enabled is False
        assert by_name["risky"].acl_everyone_permissions == ["READ"]

        assert by_name["errored"].az_redundancy is None
        assert by_name["errored"].cors_allow_origin is None
        assert by_name["errored"].event_notification_enabled is None
        assert by_name["errored"].acl_everyone_permissions is None
