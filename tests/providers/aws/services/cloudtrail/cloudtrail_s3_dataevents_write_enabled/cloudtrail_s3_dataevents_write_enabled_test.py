from unittest import mock

from boto3 import client
from moto import mock_cloudtrail, mock_s3

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_cloudtrail_s3_dataevents_write_enabled:
    @mock_cloudtrail
    @mock_s3
    def test_trail_without_data_events(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails have a data event to record all S3 object-level API operations."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_cloudtrail
    @mock_s3
    def test_trail_without_s3_data_events(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}
                    ],
                }
            ],
        )["EventSelectors"]

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails have a data event to record all S3 object-level API operations."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_cloudtrail
    @mock_s3
    def test_trail_without_s3_data_events_ignoring(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_cloudtrail
    @mock_s3
    def test_trail_without_s3_data_events_ignoring_with_buckets(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails have a data event to record all S3 object-level API operations."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_data_events(self):
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
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::*/*"]}
                    ],
                }
            ],
        )["EventSelectors"]

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name_us} from home region {AWS_REGION_US_EAST_1} has a classic data event selector to record all S3 object-level API operations."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_advanced_data_events(self):
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
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            AdvancedEventSelectors=[
                {
                    "Name": "test",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                    ],
                },
            ],
        )["AdvancedEventSelectors"]
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name_us} from home region {AWS_REGION_US_EAST_1} has an advanced data event selector to record all S3 object-level API operations."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_three_colons(self):
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
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": "AWS::DynamoDB::Table",
                            "Values": ["arn:aws:dynamodb"],
                        },
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]},
                        {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]},
                    ],
                    "ExcludeManagementEventSources": [],
                }
            ],
        )["EventSelectors"]

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info = set_mocked_aws_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name_us} from home region {AWS_REGION_US_EAST_1} has a classic data event selector to record all S3 object-level API operations."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
