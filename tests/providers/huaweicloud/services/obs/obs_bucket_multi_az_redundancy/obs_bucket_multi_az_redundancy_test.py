from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketMultiAzRedundancy:
    def test_bucket_3az_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_multi_az_redundancy.obs_bucket_multi_az_redundancy.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_multi_az_redundancy.obs_bucket_multi_az_redundancy import (
                obs_bucket_multi_az_redundancy,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(name="multi-az-bucket", region="cn-north-4", az_redundancy="3az")
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_multi_az_redundancy().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "multi-AZ (3AZ) redundancy enabled" in result[0].status_extended

    def test_bucket_single_az_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_multi_az_redundancy.obs_bucket_multi_az_redundancy.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_multi_az_redundancy.obs_bucket_multi_az_redundancy import (
                obs_bucket_multi_az_redundancy,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(name="single-az-bucket", region="cn-north-4", az_redundancy="")
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_multi_az_redundancy().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have multi-AZ" in result[0].status_extended

    def test_bucket_metadata_unknown_skipped(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_multi_az_redundancy.obs_bucket_multi_az_redundancy.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_multi_az_redundancy.obs_bucket_multi_az_redundancy import (
                obs_bucket_multi_az_redundancy,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(name="unknown-bucket", region="cn-north-4", az_redundancy=None)
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_multi_az_redundancy().execute()

            assert len(result) == 0
