from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestOssBucketLoggingEnabled:
    def test_bucket_with_logging_enabled(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_logging_enabled.oss_bucket_logging_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_logging_enabled.oss_bucket_logging_enabled import (
                oss_bucket_logging_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:with-logging",
                name="with-logging",
                region="cn-hangzhou",
                logging_enabled=True,
                logging_target_bucket="log-bucket",
                logging_target_prefix="logs/",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "logging enabled" in result[0].status_extended
            assert result[0].resource_id == "with-logging"
            assert result[0].resource_arn == bucket.arn

    def test_bucket_without_logging(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_logging_enabled.oss_bucket_logging_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_logging_enabled.oss_bucket_logging_enabled import (
                oss_bucket_logging_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:no-logging",
                name="no-logging",
                region="cn-hangzhou",
                logging_enabled=False,
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have logging enabled" in result[0].status_extended
            assert result[0].resource_id == "no-logging"
            assert result[0].resource_arn == bucket.arn
