from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketPublicAccess:
    def test_private_bucket_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_public_access.obs_bucket_public_access.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_public_access.obs_bucket_public_access import (
                obs_bucket_public_access,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="private-bucket",
                is_public=False,
                region="la-south-2",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not public" in result[0].status_extended

    def test_public_bucket_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_public_access.obs_bucket_public_access.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_public_access.obs_bucket_public_access import (
                obs_bucket_public_access,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="public-bucket",
                is_public=True,
                region="la-south-2",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "public" in result[0].status_extended

    def test_no_buckets(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_public_access.obs_bucket_public_access.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_public_access.obs_bucket_public_access import (
                obs_bucket_public_access,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            check = obs_bucket_public_access()
            result = check.execute()

            assert len(result) == 0
