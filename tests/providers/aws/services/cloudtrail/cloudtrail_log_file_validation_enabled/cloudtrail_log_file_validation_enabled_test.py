from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudtrail_log_file_validation_enabled:
    @mock_aws
    def test_no_trails(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_log_file_validation_enabled.cloudtrail_log_file_validation_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_log_file_validation_enabled.cloudtrail_log_file_validation_enabled import (
                cloudtrail_log_file_validation_enabled,
            )

            check = cloudtrail_log_file_validation_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_no_logging_validation(self):
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_log_file_validation_enabled.cloudtrail_log_file_validation_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_log_file_validation_enabled.cloudtrail_log_file_validation_enabled import (
                cloudtrail_log_file_validation_enabled,
            )

            check = cloudtrail_log_file_validation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("log file validation disabled", result[0].status_extended)
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_various_trails_with_and_without_logging_validation(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        cloudtrail_client_eu_west_1 = client(
            "cloudtrail", region_name=AWS_REGION_EU_WEST_1
        )
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        trail_eu = cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_log_file_validation_enabled.cloudtrail_log_file_validation_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_log_file_validation_enabled.cloudtrail_log_file_validation_enabled import (
                cloudtrail_log_file_validation_enabled,
            )

            regions = []
            for region in service_client.regional_clients.keys():
                regions.append(region)

            check = cloudtrail_log_file_validation_enabled()
            result = check.execute()
            assert len(result) == 2
            for report in result:
                if report.resource_id == trail_name_us:
                    assert report.status == "PASS"
                    assert search("log file validation enabled", report.status_extended)
                    assert report.resource_id == trail_name_us
                    assert report.resource_arn == trail_us["TrailARN"]
                    assert report.resource_tags == []
                    assert report.region == AWS_REGION_US_EAST_1
                elif report.resource_id == trail_name_eu:
                    assert report.status == "FAIL"
                    assert search(
                        "log file validation disabled", report.status_extended
                    )
                    assert report.resource_id == trail_name_eu
                    assert report.resource_arn == trail_eu["TrailARN"]
                    assert report.resource_tags == []
                    assert report.region == AWS_REGION_EU_WEST_1
