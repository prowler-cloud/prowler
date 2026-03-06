from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestOssBucketSecureTransportEnabled:
    def test_bucket_without_secure_transport_policy(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_secure_transport_enabled.oss_bucket_secure_transport_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_secure_transport_enabled.oss_bucket_secure_transport_enabled import (
                oss_bucket_secure_transport_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:insecure",
                name="insecure",
                region="cn-hangzhou",
                policy={},
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_secure_transport_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have secure transfer required enabled"
                in result[0].status_extended
            )
            assert result[0].resource_id == "insecure"

    def test_bucket_with_secure_transport_policy(self):
        oss_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.oss.oss_bucket_secure_transport_enabled.oss_bucket_secure_transport_enabled.oss_client",
                new=oss_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_secure_transport_enabled.oss_bucket_secure_transport_enabled import (
                oss_bucket_secure_transport_enabled,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            bucket = Bucket(
                arn="acs:oss::1234567890:secure",
                name="secure",
                region="cn-hangzhou",
                policy={
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Condition": {"Bool": {"acs:SecureTransport": ["false"]}},
                        }
                    ]
                },
            )
            oss_client.buckets = {bucket.arn: bucket}

            check = oss_bucket_secure_transport_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "secure transfer required enabled" in result[0].status_extended
            assert result[0].resource_id == "secure"
