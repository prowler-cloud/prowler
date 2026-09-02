import json
from types import SimpleNamespace
from unittest import mock

from moto import mock_aws

from prowler.lib.outputs.finding import Finding
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock_get_trail_arn_template(region=None, *_) -> str:
    if region:
        return f"arn:aws:cloudtrail:{region}:{AWS_ACCOUNT_NUMBER}:trail"
    else:
        return f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"


def mock__get_lookup_events__(trail=None, event_name=None, minutes=None, *_) -> list:
    del trail, minutes
    return [
        {
            "CloudTrailEvent": '{"eventName": "DescribeAccessEntry", "userIdentity": {"type": "IAMUser", "principalId": "EXAMPLE6E4XEGITWATV6R", "arn": "arn:aws:iam::123456789012:user/Attacker", "accountId": "123456789012", "accessKeyId": "AKIAIOSFODNN7EXAMPLE", "userName": "Attacker", "sessionContext": {"sessionIssuer": {}, "webIdFederationData": {}, "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"}}}}'
        },
        {
            "CloudTrailEvent": '{"eventName": "DescribeAccountAttributes", "userIdentity": {"type": "IAMUser", "principalId": "EXAMPLE6E4XEGITWATV6R", "arn": "arn:aws:iam::123456789012:user/Attacker", "accountId": "123456789012", "accessKeyId": "AKIAIOSFODNN7EXAMPLE", "userName": "Attacker", "sessionContext": {"sessionIssuer": {}, "webIdFederationData": {}, "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"}}}}'
        },
    ]


def mock__get_lookup_events_aws_service__(
    trail=None, event_name=None, minutes=None, *_
) -> list:
    del trail, minutes
    return [
        {
            "CloudTrailEvent": '{"eventName": "DescribeAccessEntry", "userIdentity": {"type": "AWSService", "principalId": "EXAMPLE6E4XEGITWATV6R", "accountId": "123456789012", "sessionContext": {"sessionIssuer": {}, "webIdFederationData": {}, "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"}}}}'
        },
        {
            "CloudTrailEvent": '{"eventName": "DescribeAccountAttributes", "userIdentity": {"type": "AWSService", "principalId": "EXAMPLE6E4XEGITWATV6R", "accountId": "123456789012", "sessionContext": {"sessionIssuer": {}, "webIdFederationData": {}, "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"}}}}'
        },
    ]


def mock__get_lookup_events_assumed_role__(
    trail=None, event_name=None, minutes=None, *_
) -> list:
    del trail, minutes
    session_name = (
        "enumeration-session-one"
        if event_name == "DescribeAccessEntry"
        else "enumeration-session-two"
    )
    return [
        {
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {
                        "type": "AssumedRole",
                        "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/platform-attacker/{session_name}",
                        "sessionContext": {
                            "sessionIssuer": {
                                "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/security/platform-attacker"
                            }
                        },
                    }
                }
            )
        }
    ]


class Test_cloudtrail_threat_detection_enumeration:
    @mock_aws
    def test_no_trails(self):
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {}
        cloudtrail_client._lookup_events = mock__get_lookup_events__
        cloudtrail_client._get_trail_arn_template = mock_get_trail_arn_template
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        cloudtrail_client.region = AWS_REGION_US_EAST_1

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration.cloudtrail_client",
                new=cloudtrail_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration import (
                cloudtrail_threat_detection_enumeration,
            )

            check = cloudtrail_threat_detection_enumeration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "No potential enumeration attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].resource["identity_type"] == "AWSAccount"

    @mock_aws
    def test_no_potential_enumeration(self):
        ENUMERATION_ACTIONS = []
        THRESHOLD = 0.1
        THREAT_DETECTION_MINUTES = 1440
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_enumeration_actions": ENUMERATION_ACTIONS,
            "threat_detection_enumeration_threshold": THRESHOLD,
            "threat_detection_enumeration_minutes": THREAT_DETECTION_MINUTES,
        }

        cloudtrail_client._lookup_events = mock__get_lookup_events__
        cloudtrail_client._get_trail_arn_template = mock_get_trail_arn_template

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration.cloudtrail_client",
                new=cloudtrail_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration import (
                cloudtrail_threat_detection_enumeration,
            )

            check = cloudtrail_threat_detection_enumeration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "No potential enumeration attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"

    @mock_aws
    def test_potential_enumeration(self):
        ENUMERATION_ACTIONS = ["DescribeAccessEntry", "DescribeAccountAttributes"]
        THRESHOLD = 0.1
        THREAT_DETECTION_MINUTES = 1440
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_enumeration_actions": ENUMERATION_ACTIONS,
            "threat_detection_enumeration_threshold": THRESHOLD,
            "threat_detection_enumeration_minutes": THREAT_DETECTION_MINUTES,
        }

        cloudtrail_client._lookup_events = mock__get_lookup_events__
        cloudtrail_client._get_trail_arn_template = mock_get_trail_arn_template

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration.cloudtrail_client",
                new=cloudtrail_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration import (
                cloudtrail_threat_detection_enumeration,
            )

            check = cloudtrail_threat_detection_enumeration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Potential enumeration attack detected from AWS IAMUser Attacker with a threshold of 1.0."
            )
            assert result[0].resource_id == "user/Attacker"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/Attacker"
            )
            assert result[0].resource["name"] == "Attacker"
            assert result[0].resource["identity_type"] == "IAMUser"
            assert result[0].check_metadata.ResourceType == "Other"

    @mock_aws
    def test_big_threshold(self):
        ENUMERATION_ACTIONS = ["DescribeAccessEntry", "DescribeAccountAttributes"]
        THRESHOLD = 2.0
        THREAT_DETECTION_MINUTES = 1440
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_enumeration_actions": ENUMERATION_ACTIONS,
            "threat_detection_enumeration_threshold": THRESHOLD,
            "threat_detection_enumeration_minutes": THREAT_DETECTION_MINUTES,
        }

        cloudtrail_client._lookup_events = mock__get_lookup_events__
        cloudtrail_client._get_trail_arn_template = mock_get_trail_arn_template

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration.cloudtrail_client",
                new=cloudtrail_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration import (
                cloudtrail_threat_detection_enumeration,
            )

            check = cloudtrail_threat_detection_enumeration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "No potential enumeration attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"

    @mock_aws
    def test_potential_enumeration_from_aws_service(self):
        ENUMERATION_ACTIONS = ["DescribeAccessEntry", "DescribeAccountAttributes"]
        THRESHOLD = 2.0
        THREAT_DETECTION_MINUTES = 1440
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.trails["us-east-1"].name = "trail_test_us"
        cloudtrail_client.trails["us-east-1"].s3_bucket_name = "bucket_test_us"
        cloudtrail_client.trails["us-east-1"].region = "us-east-1"
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_enumeration_actions": ENUMERATION_ACTIONS,
            "threat_detection_enumeration_threshold": THRESHOLD,
            "threat_detection_enumeration_minutes": THREAT_DETECTION_MINUTES,
        }

        cloudtrail_client._lookup_events = mock__get_lookup_events_aws_service__
        cloudtrail_client._get_trail_arn_template = mock_get_trail_arn_template

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration.cloudtrail_client",
                new=cloudtrail_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration import (
                cloudtrail_threat_detection_enumeration,
            )

            check = cloudtrail_threat_detection_enumeration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "No potential enumeration attack detected."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"

    @mock_aws
    def test_assumed_role_sessions_aggregate_into_one_finding(self):
        aws_provider = set_mocked_aws_provider()
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"us-east-1": mock.MagicMock()}
        cloudtrail_client.trails["us-east-1"].is_multiregion = False
        cloudtrail_client.audited_account = AWS_ACCOUNT_NUMBER
        cloudtrail_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.audit_config = {
            "threat_detection_enumeration_actions": [
                "DescribeAccessEntry",
                "DescribeAccountAttributes",
            ],
            "threat_detection_enumeration_threshold": 0.6,
            "threat_detection_enumeration_minutes": 1440,
        }
        cloudtrail_client._lookup_events = mock__get_lookup_events_assumed_role__

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration.cloudtrail_client",
                new=cloudtrail_client,
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_threat_detection_enumeration.cloudtrail_threat_detection_enumeration import (
                cloudtrail_threat_detection_enumeration,
            )

            result = cloudtrail_threat_detection_enumeration().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "role/security/platform-attacker"
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/security/platform-attacker"
            )
            assert result[0].resource["identity_type"] == "AssumedRole"
            assert result[0].resource["source_arn"].startswith("arn:aws:sts::")

            finding = Finding.generate_output(
                aws_provider,
                result[0],
                SimpleNamespace(unix_timestamp=False, bulk_checks_metadata={}),
            )
            assert finding.resource_name == "role/security/platform-attacker"
            assert finding.resource_uid == result[0].resource_arn
            assert finding.resource_metadata == result[0].resource
            assert finding.uid.endswith("-role/security/platform-attacker")
