from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_cloudtrail_insights_exist:
    @mock_aws
    def test_no_trails(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_insights_exist.cloudtrail_insights_exist.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_insights_exist.cloudtrail_insights_exist import (
                    cloudtrail_insights_exist,
                )

                check = cloudtrail_insights_exist()
                result = check.execute()
                assert len(result) == 0

    @mock_aws
    def test_trails_with_no_insight_selector(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us_with_no_insight_selector"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_insights_exist.cloudtrail_insights_exist.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_insights_exist.cloudtrail_insights_exist import (
                    cloudtrail_insights_exist,
                )

                check = cloudtrail_insights_exist()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Trail {trail_name_us} does not have insight selectors and it is logging."
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].resource_tags == []

    @mock_aws
    def test_trails_with_insight_selector(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us_with_insight_selector"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)
        cloudtrail_client_us_east_1.put_insight_selectors(
            TrailName=trail_name_us,
            InsightSelectors=[{"InsightType": "ApiErrorRateInsight"}],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_insights_exist.cloudtrail_insights_exist.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_insights_exist.cloudtrail_insights_exist import (
                    cloudtrail_insights_exist,
                )

                check = cloudtrail_insights_exist()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Trail {trail_name_us} has insight selectors and it is logging."
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].resource_tags == []
