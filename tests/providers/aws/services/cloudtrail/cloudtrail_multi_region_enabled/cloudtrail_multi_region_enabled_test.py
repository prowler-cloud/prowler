from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = 123456789012


class Test_cloudtrail_multi_region_enabled:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_cloudtrail
    def test_no_trails(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                assert len(result) == len(current_audit_info.audited_regions)
                for report in result:
                    assert report.status == "FAIL"
                    assert search(
                        "No CloudTrail trails enabled and logging were found",
                        report.status_extended,
                    )
                    assert report.resource_id == "No trails"
                    assert report.resource_arn == "No trails"

    @mock_cloudtrail
    @mock_s3
    def test_various_trails_no_login(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        cloudtrail_client_eu_west_1 = client("cloudtrail", region_name="eu-west-1")
        s3_client_eu_west_1 = client("s3", region_name="eu-west-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
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

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                assert len(result) == len(current_audit_info.audited_regions)
                for report in result:
                    assert report.status == "FAIL"
                    assert search(
                        "No CloudTrail trails enabled and logging were found",
                        report.status_extended,
                    )
                    assert report.resource_id == "No trails"
                    assert report.resource_arn == "No trails"

    @mock_cloudtrail
    @mock_s3
    def test_various_trails_with_and_without_login(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        cloudtrail_client_eu_west_1 = client("cloudtrail", region_name="eu-west-1")
        s3_client_eu_west_1 = client("s3", region_name="eu-west-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
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

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                assert len(result) == len(current_audit_info.audited_regions)
                for report in result:
                    if report.resource_id == trail_name_us:
                        assert report.status == "PASS"
                        assert search(
                            "is not multiregion and it is logging",
                            report.status_extended,
                        )
                        assert report.resource_id == trail_name_us
                        assert report.resource_arn == trail_us["TrailARN"]
                    else:
                        assert report.status == "FAIL"
                        assert search(
                            "No CloudTrail trails enabled and logging were found",
                            report.status_extended,
                        )
                        assert report.resource_id == "No trails"
                        assert report.resource_arn == "No trails"
