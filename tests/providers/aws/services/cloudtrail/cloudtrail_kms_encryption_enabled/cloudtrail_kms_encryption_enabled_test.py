from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudtrail_kms_encryption_enabled:
    @mock_aws
    def test_no_trails(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled import (
                cloudtrail_kms_encryption_enabled,
            )

            check = cloudtrail_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_trail_no_kms(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled import (
                cloudtrail_kms_encryption_enabled,
            )

            check = cloudtrail_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has encryption disabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_kms(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        key_arn = kms_client.create_key()["KeyMetadata"]["Arn"]
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            KmsKeyId=key_arn,
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled import (
                cloudtrail_kms_encryption_enabled,
            )

            check = cloudtrail_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has encryption enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_access_denied(self):

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled import (
                cloudtrail_kms_encryption_enabled,
            )

            service_client.trails = None
            check = cloudtrail_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 0
