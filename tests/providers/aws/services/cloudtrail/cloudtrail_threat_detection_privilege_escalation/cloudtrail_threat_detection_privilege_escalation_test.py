from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock__get_trail_arn_template__(region=None, *_):
    if region:
        return f"arn:aws:cloudtrail:{region}:{AWS_ACCOUNT_NUMBER}:trail"
    else:
        return f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"


def mock__get_lookup_events__(*_):
    return [
        {
            "CloudTrailEvent": '{"sourceIPAddress": "10.10.10.0/64", "eventName": "CreateLoginProfile"}'
        },
        {
            "CloudTrailEvent": '{"sourceIPAddress": "10.10.10.0/64", "eventName": "UpdateLoginProfile"}'
        },
    ]


class Test_CloudTrail_Threat_Detection_Privilege_Escalation:
    @mock_aws
    def test_no_trails(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_privilege_escalation.cloudtrail_threat_detection_privilege_escalation.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_privilege_escalation.cloudtrail_threat_detection_privilege_escalation import (
                cloudtrail_threat_detection_privilege_escalation,
            )

            check = cloudtrail_threat_detection_privilege_escalation()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No potential privilege escalation attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
            )

    @mock_aws
    def test_no_potential_priviledge_escalation(self):
        PRIVILEGE_ESCALATION_ACTIONS = []
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
        cloudtrail_client_us_east_1.audit_config = {
            "threat_detection_privilege_escalation_actions": PRIVILEGE_ESCALATION_ACTIONS
        }

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_privilege_escalation.cloudtrail_threat_detection_privilege_escalation.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_privilege_escalation.cloudtrail_threat_detection_privilege_escalation import (
                cloudtrail_threat_detection_privilege_escalation,
            )

            check = cloudtrail_threat_detection_privilege_escalation()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No potential privilege escalation attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
            )

    @mock_aws
    def test_potential_priviledge_escalation(self):
        PRIVILEGE_ESCALATION_ACTIONS = ["CreateLoginProfile", "UpdateLoginProfile"]
        THRESHOLD = 0.1
        THREAT_DETECTION_MINUTES = 1440
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_privilege_escalation_actions": PRIVILEGE_ESCALATION_ACTIONS,
            "threat_detection_privilege_escalation_threshold": THRESHOLD,
            "threat_detection_privilege_escalation_minutes": THREAT_DETECTION_MINUTES,
        }
        cloudtrail_client.__lookup_events__ = mock__get_lookup_events__
        cloudtrail_client.__get_trail_arn_template__ = mock__get_trail_arn_template__

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_privilege_escalation.cloudtrail_threat_detection_privilege_escalation.cloudtrail_client",
            new=cloudtrail_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_privilege_escalation.cloudtrail_threat_detection_privilege_escalation import (
                cloudtrail_threat_detection_privilege_escalation,
            )

            check = cloudtrail_threat_detection_privilege_escalation()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No potential privilege escalation attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
            )
