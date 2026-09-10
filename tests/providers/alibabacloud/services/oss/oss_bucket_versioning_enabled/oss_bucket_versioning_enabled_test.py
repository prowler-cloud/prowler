from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestOssBucketVersioningEnabled:
    def test_bucket_with_versioning_enabled(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled import (
                oss_bucket_versioning_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:versioning-enabled",
                name="versioning-enabled",
                region="cn-hangzhou",
                versioning_status="Enabled",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_versioning_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has versioning enabled" in result[0].status_extended
            assert result[0].resource_id == "versioning-enabled"
            assert result[0].resource_arn == bucket.arn

    def test_bucket_with_versioning_suspended(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled import (
                oss_bucket_versioning_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:versioning-suspended",
                name="versioning-suspended",
                region="cn-hangzhou",
                versioning_status="Suspended",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_versioning_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has versioning suspended" in result[0].status_extended
            assert result[0].resource_id == "versioning-suspended"
            assert result[0].resource_arn == bucket.arn

    def test_bucket_without_versioning(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled import (
                oss_bucket_versioning_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:no-versioning",
                name="no-versioning",
                region="cn-hangzhou",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_versioning_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have versioning enabled" in result[0].status_extended
            assert result[0].resource_id == "no-versioning"
            assert result[0].resource_arn == bucket.arn

    def test_no_buckets(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_versioning_enabled.oss_bucket_versioning_enabled import (
                oss_bucket_versioning_enabled,
            )

            oss_client.buckets = {}

            check = oss_bucket_versioning_enabled()
            result = check.execute()

            assert len(result) == 0
