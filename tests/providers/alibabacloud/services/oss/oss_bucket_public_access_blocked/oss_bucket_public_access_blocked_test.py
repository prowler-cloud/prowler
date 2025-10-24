from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_oss_bucket_public_access_blocked:
    def test_no_buckets(self):
        oss_client = mock.MagicMock
        oss_client.buckets = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.oss.oss_bucket_public_access_blocked.oss_bucket_public_access_blocked.oss_client",
            new=oss_client,
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_public_access_blocked.oss_bucket_public_access_blocked import (
                oss_bucket_public_access_blocked,
            )

            check = oss_bucket_public_access_blocked()
            result = check.execute()
            assert len(result) == 0

    def test_bucket_private_access(self):
        oss_client = mock.MagicMock
        bucket_name = "test-bucket-private"
        bucket_arn = f"acs:oss:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:bucket/{bucket_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.oss.oss_bucket_public_access_blocked.oss_bucket_public_access_blocked.oss_client",
            new=oss_client,
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_public_access_blocked.oss_bucket_public_access_blocked import (
                oss_bucket_public_access_blocked,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            oss_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    arn=bucket_arn,
                    region=ALIBABACLOUD_REGION,
                    creation_date="2023-01-01",
                    public_access=False,
                )
            }
            oss_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = oss_bucket_public_access_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == bucket_name
            assert result[0].resource_arn == bucket_arn
            assert result[0].region == ALIBABACLOUD_REGION

    def test_bucket_public_access(self):
        oss_client = mock.MagicMock
        bucket_name = "test-bucket-public"
        bucket_arn = f"acs:oss:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:bucket/{bucket_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.oss.oss_bucket_public_access_blocked.oss_bucket_public_access_blocked.oss_client",
            new=oss_client,
        ):
            from prowler.providers.alibabacloud.services.oss.oss_bucket_public_access_blocked.oss_bucket_public_access_blocked import (
                oss_bucket_public_access_blocked,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            oss_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    arn=bucket_arn,
                    region=ALIBABACLOUD_REGION,
                    creation_date="2023-01-01",
                    public_access=True,
                )
            }
            oss_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = oss_bucket_public_access_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == bucket_name
            assert result[0].resource_arn == bucket_arn
            assert result[0].region == ALIBABACLOUD_REGION
