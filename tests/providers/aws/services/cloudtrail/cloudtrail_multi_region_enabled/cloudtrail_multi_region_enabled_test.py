from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_cloudtrail_multi_region_enabled:
    @mock_aws
    def test_no_trails(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled import (
                    cloudtrail_multi_region_enabled,
                )

                check = cloudtrail_multi_region_enabled()
                result = check.execute()
                assert len(result) == len(current_audit_info.identity.audited_regions)
                for report in result:
                    if report.region == AWS_REGION_US_EAST_1:
                        assert report.status == "FAIL"
                        assert (
                            report.status_extended
                            == "No CloudTrail trails enabled and logging were found."
                        )
                        assert report.resource_id == AWS_ACCOUNT_NUMBER
                        assert (
                            report.resource_arn
                            == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
                        )
                        assert report.resource_tags == []
                    elif report.region == AWS_REGION_EU_WEST_1:
                        assert report.status == "FAIL"
                        assert (
                            report.status_extended
                            == "No CloudTrail trails enabled and logging were found."
                        )
                        assert report.resource_id == AWS_ACCOUNT_NUMBER
                        assert (
                            report.resource_arn
                            == f"arn:aws:cloudtrail:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:trail"
                        )
                        assert report.resource_tags == []

    @mock_aws
    def test_various_trails_no_logging(self):
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
        _ = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled import (
                    cloudtrail_multi_region_enabled,
                )

                check = cloudtrail_multi_region_enabled()
                result = check.execute()
                assert len(result) == len(current_audit_info.identity.audited_regions)
                for report in result:
                    if report.region == AWS_REGION_US_EAST_1:
                        assert report.status == "FAIL"
                        assert (
                            report.status_extended
                            == "No CloudTrail trails enabled and logging were found."
                        )
                        assert report.resource_id == AWS_ACCOUNT_NUMBER
                        assert (
                            report.resource_arn
                            == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
                        )
                        assert report.resource_tags == []
                    elif report.region == AWS_REGION_EU_WEST_1:
                        assert report.status == "FAIL"
                        assert (
                            report.status_extended
                            == "No CloudTrail trails enabled and logging were found."
                        )
                        assert report.resource_id == AWS_ACCOUNT_NUMBER
                        assert (
                            report.resource_arn
                            == f"arn:aws:cloudtrail:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:trail"
                        )
                        assert report.resource_tags == []

    @mock_aws
    def test_various_trails_with_and_without_logging(self):
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
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled import (
                    cloudtrail_multi_region_enabled,
                )

                check = cloudtrail_multi_region_enabled()
                result = check.execute()
                assert len(result) == len(current_audit_info.identity.audited_regions)
                for report in result:
                    if report.resource_id == trail_name_us:
                        assert report.status == "PASS"
                        assert search(
                            "is not multiregion and it is logging",
                            report.status_extended,
                        )
                        assert report.resource_id == trail_name_us
                        assert report.resource_arn == trail_us["TrailARN"]
                        assert report.resource_tags == []
                        assert report.region == AWS_REGION_US_EAST_1
                    else:
                        assert report.status == "FAIL"
                        assert search(
                            "No CloudTrail trails enabled and logging were found.",
                            report.status_extended,
                        )
                        assert report.resource_id == AWS_ACCOUNT_NUMBER
                        assert (
                            report.resource_arn
                            == f"arn:aws:cloudtrail:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:trail"
                        )
                        assert report.resource_tags == []
                        assert report.region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_trail_multiregion_logging_and_single_region_not_logging(self):
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
        trail_name_eu = "aaaaa"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=True
        )
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled.cloudtrail_multi_region_enabled import (
                    cloudtrail_multi_region_enabled,
                )

                check = cloudtrail_multi_region_enabled()
                result = check.execute()
                assert len(result) == len(current_audit_info.identity.audited_regions)
                for report in result:
                    if report.region == AWS_REGION_US_EAST_1:
                        assert report.status == "PASS"
                        assert search(
                            f"Trail {trail_name_us} is multiregion and it is logging.",
                            report.status_extended,
                        )
                        assert report.resource_id == trail_name_us
                        assert report.resource_arn == trail_us["TrailARN"]
                        assert report.resource_tags == []
                    elif report.region == AWS_REGION_EU_WEST_1:
                        assert report.status == "PASS"
                        assert search(
                            f"Trail {trail_name_us} is multiregion and it is logging.",
                            report.status_extended,
                        )
                        assert report.resource_id == trail_name_us
                        assert report.resource_arn == trail_us["TrailARN"]
                        assert report.resource_tags == []
