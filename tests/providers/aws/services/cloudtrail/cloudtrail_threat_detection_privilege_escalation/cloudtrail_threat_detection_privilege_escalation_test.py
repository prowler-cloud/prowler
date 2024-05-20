from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock__get_trail_arn_template__(region=None, *_) -> str:
    if region:
        return f"arn:aws:cloudtrail:{region}:{AWS_ACCOUNT_NUMBER}:trail"
    else:
        return f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"


def mock__get_lookup_events__(trail=None, event_name=None, minutes=None, *_) -> list:
    return [
        {
            "CloudTrailEvent": '{"sourceIPAddress": "172.28.7.0/24", "eventName": "CreateLoginProfile"}'
        },
        {
            "CloudTrailEvent": '{"sourceIPAddress": "172.28.7.0/24", "eventName": "UpdateLoginProfile"}'
        },
    ]


class Test_cloudtrail_threat_detection_privilege_escalation:
    @mock_aws
    def test_no_trails(self):
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {}
        cloudtrail_client.__lookup_events__ = mock__get_lookup_events__
        cloudtrail_client.__get_trail_arn_template__ = mock__get_trail_arn_template__
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
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
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_privilege_escalation_actions": [],
            "threat_detection_privilege_escalation_threshold": 0.1,
            "threat_detection_privilege_escalation_minutes": 1440,
        }

        cloudtrail_client.__lookup_events__ = mock__get_lookup_events__
        cloudtrail_client.__get_trail_arn_template__ = mock__get_trail_arn_template__

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
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
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_privilege_escalation_actions": [
                "CreateLoginProfile",
                "UpdateLoginProfile",
            ],
            "threat_detection_privilege_escalation_threshold": 0.1,
            "threat_detection_privilege_escalation_minutes": 1440,
        }

        cloudtrail_client.__lookup_events__ = mock__get_lookup_events__
        cloudtrail_client.__get_trail_arn_template__ = mock__get_trail_arn_template__

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
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
                == "Potential privilege escalation attack detected from source IP 172.28.7.0/24 with an threshold of 1.0."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
            )

    @mock_aws
    def test_bigger_threshold(self):
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_privilege_escalation_actions": [
                "CreateLoginProfile",
                "UpdateLoginProfile",
            ],
            "threat_detection_privilege_escalation_threshold": 2.0,
            "threat_detection_privilege_escalation_minutes": 1440,
        }

        cloudtrail_client.__lookup_events__ = mock__get_lookup_events__
        cloudtrail_client.__get_trail_arn_template__ = mock__get_trail_arn_template__

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
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
