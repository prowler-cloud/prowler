from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_cloudtrail_multi_region_enabled_fixer:
    @mock_aws
    def test_cloudtrail_multi_region_enabled_fixer(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_US_EAST_1],
            fixer_config={
                "cloudtrail_multi_region_enabled": {
                    "TrailName": "DefaultTrail",
                    "S3BucketName": "test-bucket",
                    "IsMultiRegionTrail": True,
                    "EnableLogFileValidation": True,
                },
            },
        )
        # Create s3 test-bucket
        s3 = client("s3")
        s3.create_bucket(Bucket="test-bucket")

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled_fixer.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled_fixer import (
                    fixer,
                )

                assert fixer(AWS_REGION_US_EAST_1)
