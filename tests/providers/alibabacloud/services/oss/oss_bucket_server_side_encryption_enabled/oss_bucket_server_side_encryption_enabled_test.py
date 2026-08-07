from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestOssBucketServerSideEncryptionEnabled:
    def test_bucket_with_aes256_encryption(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled import (
                oss_bucket_server_side_encryption_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:encrypted-aes",
                name="encrypted-aes",
                region="cn-hangzhou",
                encryption_algorithm="AES256",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_server_side_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "server-side encryption enabled" in result[0].status_extended
            assert "AES256" in result[0].status_extended
            assert result[0].resource_id == "encrypted-aes"
            assert result[0].resource_arn == bucket.arn

    def test_bucket_with_kms_encryption(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled import (
                oss_bucket_server_side_encryption_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:encrypted-kms",
                name="encrypted-kms",
                region="cn-hangzhou",
                encryption_algorithm="KMS",
                encryption_kms_key_id="9468da86-3509-4f8d-a61e-6eab1eac",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_server_side_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "KMS" in result[0].status_extended
            assert "9468da86-3509-4f8d-a61e-6eab1eac" in result[0].status_extended
            assert result[0].resource_id == "encrypted-kms"
            assert result[0].resource_arn == bucket.arn


    def test_bucket_with_sm4_encryption(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled import (
                oss_bucket_server_side_encryption_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:encrypted-sm4",
                name="encrypted-sm4",
                region="cn-hangzhou",
                encryption_algorithm="SM4",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_server_side_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "server-side encryption enabled" in result[0].status_extended
            assert "SM4" in result[0].status_extended
            assert result[0].resource_id == "encrypted-sm4"
            assert result[0].resource_arn == bucket.arn

    def test_bucket_without_encryption(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled import (
                oss_bucket_server_side_encryption_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:no-encryption",
                name="no-encryption",
                region="cn-hangzhou",
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_server_side_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have default server-side encryption enabled"
                in result[0].status_extended
            )
            assert result[0].resource_id == "no-encryption"
            assert result[0].resource_arn == bucket.arn

    def test_no_buckets(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_server_side_encryption_enabled.oss_bucket_server_side_encryption_enabled import (
                oss_bucket_server_side_encryption_enabled,
            )

            oss_client.buckets = {}

            check = oss_bucket_server_side_encryption_enabled()
            result = check.execute()

            assert len(result) == 0
