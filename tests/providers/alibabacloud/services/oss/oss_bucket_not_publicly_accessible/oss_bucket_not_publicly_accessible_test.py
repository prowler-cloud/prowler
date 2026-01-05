from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestOssBucketNotPubliclyAccessible:
    def test_public_acl_fails(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_not_publicly_accessible.oss_bucket_not_publicly_accessible.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_not_publicly_accessible.oss_bucket_not_publicly_accessible import (
                oss_bucket_not_publicly_accessible,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:public-acl",
                name="public-acl",
                region="cn-hangzhou",
                acl="public-read",
                policy={},
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "publicly accessible" in result[0].status_extended
            assert "public-read" in result[0].status_extended

    def test_private_bucket_passes(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_not_publicly_accessible.oss_bucket_not_publicly_accessible.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_not_publicly_accessible.oss_bucket_not_publicly_accessible import (
                oss_bucket_not_publicly_accessible,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:private",
                name="private",
                region="cn-hangzhou",
                acl="private",
                policy={},
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not publicly accessible" in result[0].status_extended
