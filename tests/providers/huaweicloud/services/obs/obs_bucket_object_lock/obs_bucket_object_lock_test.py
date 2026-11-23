from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketObjectLock:
    def test_no_resources(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock import (
                obs_bucket_object_lock,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            result = obs_bucket_object_lock().execute()
            assert len(result) == 0

    def test_bucket_object_lock_enabled_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock import (
                obs_bucket_object_lock,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="locked-bucket",
                region="cn-north-4",
                object_lock_enabled=True,
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_object_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "locked-bucket"
            assert result[0].region == "cn-north-4"
            assert (
                result[0].resource_arn
                == "huaweicloud:obs:cn-north-4:123456789012:bucket/locked-bucket"
            )
            assert "Object Lock enabled" in result[0].status_extended

    def test_bucket_object_lock_disabled_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock import (
                obs_bucket_object_lock,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="unlocked-bucket",
                region="cn-north-4",
                object_lock_enabled=False,
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_object_lock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "unlocked-bucket"
            assert "does not have Object Lock enabled" in result[0].status_extended

    def test_bucket_object_lock_unknown_skipped(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock import (
                obs_bucket_object_lock,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="unreadable-bucket",
                region="cn-north-4",
                object_lock_enabled=None,
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_object_lock()
            result = check.execute()

            assert len(result) == 0

    def test_no_buckets(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_object_lock.obs_bucket_object_lock import (
                obs_bucket_object_lock,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            check = obs_bucket_object_lock()
            result = check.execute()

            assert len(result) == 0
