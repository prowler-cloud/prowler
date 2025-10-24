from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_oss_bucket_cors_not_overly_permissive:
    def test_no_buckets(self):
        oss_client = mock.MagicMock
        oss_client.buckets = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.oss.oss_bucket_cors_not_overly_permissive.oss_bucket_cors_not_overly_permissive.oss_client",
            new=oss_client,
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_cors_not_overly_permissive.oss_bucket_cors_not_overly_permissive import (
                oss_bucket_cors_not_overly_permissive,
            )

            check = oss_bucket_cors_not_overly_permissive()
            result = check.execute()
            assert len(result) == 0

    def test_bucket_cors_not_permissive(self):
        oss_client = mock.MagicMock
        bucket_name = "test-bucket-cors-safe"
        bucket_arn = f"acs:oss:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:bucket/{bucket_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.oss.oss_bucket_cors_not_overly_permissive.oss_bucket_cors_not_overly_permissive.oss_client",
            new=oss_client,
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_cors_not_overly_permissive.oss_bucket_cors_not_overly_permissive import (
                oss_bucket_cors_not_overly_permissive,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            oss_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    arn=bucket_arn,
                    region=ALIBABACLOUD_REGION,
                    creation_date="2023-01-01",
                    cors_rules=[
                        {
                            "AllowedOrigin": ["https://example.com"],
                            "AllowedMethod": ["GET"],
                        }
                    ],
                )
            }
            oss_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = oss_bucket_cors_not_overly_permissive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == bucket_name
            assert result[0].resource_arn == bucket_arn
            assert result[0].region == ALIBABACLOUD_REGION

    def test_bucket_cors_overly_permissive(self):
        oss_client = mock.MagicMock
        bucket_name = "test-bucket-cors-permissive"
        bucket_arn = f"acs:oss:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:bucket/{bucket_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.oss.oss_bucket_cors_not_overly_permissive.oss_bucket_cors_not_overly_permissive.oss_client",
            new=oss_client,
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_cors_not_overly_permissive.oss_bucket_cors_not_overly_permissive import (
                oss_bucket_cors_not_overly_permissive,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            oss_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    arn=bucket_arn,
                    region=ALIBABACLOUD_REGION,
                    creation_date="2023-01-01",
                    cors_rules=[
                        {
                            "AllowedOrigin": ["*"],
                            "AllowedMethod": ["GET", "POST", "PUT", "DELETE"],
                        }
                    ],
                )
            }
            oss_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = oss_bucket_cors_not_overly_permissive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == bucket_name
            assert result[0].resource_arn == bucket_arn
            assert result[0].region == ALIBABACLOUD_REGION
