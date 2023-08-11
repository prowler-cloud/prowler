from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_cloudtrail_management_exist_with_multi_region_enabled:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_management_exist_with_multi_region_enabled import (
                    cloudtrail_management_exist_with_multi_region_enabled,
                )

                check = cloudtrail_management_exist_with_multi_region_enabled()
                result = check.execute()
                assert len(result) == 1
                report = result[0]
                assert report.status == "FAIL"
                assert search(
                    "No trail found with multi-region enabled and logging management events",
                    report.status_extended,
                )

    @mock_cloudtrail
    @mock_s3
    def test_compliant_trail(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        _ = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=True
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            AdvancedEventSelectors=[
                {
                    "Name": "Management events selector",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Managment"]}
                    ],
                }
            ],
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_management_exist_with_multi_region_enabled import (
                    cloudtrail_management_exist_with_multi_region_enabled,
                )

                check = cloudtrail_management_exist_with_multi_region_enabled()
                result = check.execute()
                assert len(result) == 1
                report = result[0]
                assert report.status == "PASS"
                assert search(
                    f"Trail {trail_name_us} has multi-region and management events logs enabled",
                    report.status_extended,
                )
                assert report.resource_id == trail_name_us

    @mock_cloudtrail
    @mock_s3
    def test_non_compliant_trail(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        _ = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=True
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            AdvancedEventSelectors=[
                {
                    "Name": "Management events selector",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Managment"]},
                        {"Field": "readOnly", "Equals": ["true"]},
                    ],
                }
            ],
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_management_exist_with_multi_region_enabled.cloudtrail_management_exist_with_multi_region_enabled import (
                    cloudtrail_management_exist_with_multi_region_enabled,
                )

                check = cloudtrail_management_exist_with_multi_region_enabled()
                result = check.execute()
                assert len(result) == 1
                report = result[0]
                assert report.status == "FAIL"
                assert search(
                    "No trail found with multi-region enabled and logging management events",
                    report.status_extended,
                )
