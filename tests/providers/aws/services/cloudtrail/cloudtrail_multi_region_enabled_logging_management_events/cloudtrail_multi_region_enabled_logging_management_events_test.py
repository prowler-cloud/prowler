from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"


class Test_cloudtrail_multi_region_enabled_logging_management_events:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=AWS_ACCOUNT_ARN,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=[AWS_REGION],
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events import (
                    cloudtrail_multi_region_enabled_logging_management_events,
                )

                check = cloudtrail_multi_region_enabled_logging_management_events()
                result = check.execute()
                assert len(result) == 1
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].region == AWS_REGION
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "No trail found with multi-region enabled and logging management events."
                )

    @mock_cloudtrail
    @mock_s3
    def test_compliant_trail_advanced_event_selector(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=True
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            AdvancedEventSelectors=[
                {
                    "Name": "Management events selector",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Management"]}
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events import (
                    cloudtrail_multi_region_enabled_logging_management_events,
                )

                check = cloudtrail_multi_region_enabled_logging_management_events()
                result = check.execute()
                assert len(result) == 1
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].region == AWS_REGION
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Trail {trail_name_us} from home region {AWS_REGION} is multi-region, is logging and have management events enabled."
                )

    @mock_cloudtrail
    @mock_s3
    def test_non_compliant_trail_advanced_event_selector(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events import (
                    cloudtrail_multi_region_enabled_logging_management_events,
                )

                check = cloudtrail_multi_region_enabled_logging_management_events()
                result = check.execute()
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].region == AWS_REGION
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "No trail found with multi-region enabled and logging management events."
                )

    @mock_cloudtrail
    @mock_s3
    def test_compliant_trail_classic_event_selector(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=True
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [],
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events import (
                    cloudtrail_multi_region_enabled_logging_management_events,
                )

                check = cloudtrail_multi_region_enabled_logging_management_events()
                result = check.execute()
                assert len(result) == 1
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].region == AWS_REGION
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Trail {trail_name_us} from home region {AWS_REGION} is multi-region, is logging and have management events enabled."
                )

    @mock_cloudtrail
    @mock_s3
    def test_non_compliant_trail_classic_event_selector(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        _ = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=True
        )
        _ = cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "ReadOnly",
                    "IncludeManagementEvents": False,
                    "DataResources": [],
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
                "prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_multi_region_enabled_logging_management_events.cloudtrail_multi_region_enabled_logging_management_events import (
                    cloudtrail_multi_region_enabled_logging_management_events,
                )

                check = cloudtrail_multi_region_enabled_logging_management_events()
                result = check.execute()
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].region == AWS_REGION
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "No trail found with multi-region enabled and logging management events."
                )
