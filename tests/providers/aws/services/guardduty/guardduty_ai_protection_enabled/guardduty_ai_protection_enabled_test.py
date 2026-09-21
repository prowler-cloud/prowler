from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_CLIENT_PATH = "prowler.providers.aws.services.guardduty.guardduty_ai_protection_enabled.guardduty_ai_protection_enabled.guardduty_client"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_get_detector_raises(self, operation_name, kwarg):
    """Deny GetDetector only, leaving every other GuardDuty operation intact."""
    if operation_name == "GetDetector":
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _run_check(aws_provider):
    """Run the check against a GuardDuty service built from the mocked provider."""
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(CHECK_CLIENT_PATH, new=GuardDuty(aws_provider)),
    ):
        from prowler.providers.aws.services.guardduty.guardduty_ai_protection_enabled.guardduty_ai_protection_enabled import (
            guardduty_ai_protection_enabled,
        )

        return guardduty_ai_protection_enabled().execute()


class Test_guardduty_ai_protection_enabled:
    @mock_aws
    def test_no_detectors(self):
        """A Region with no detector has no resource to judge; guardduty_is_enabled owns it."""
        client("guardduty", region_name=AWS_REGION_US_EAST_1)

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 0

    @mock_aws
    def test_ai_protection_enabled(self):
        """An enabled feature PASSes and carries the detector's own resource fields."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "AI_PROTECTION", "Status": "ENABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} has AI Protection enabled."
        )
        assert result[0].resource_id == response["DetectorId"]
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].resource_arn
            == f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert result[0].resource_tags == []

    @mock_aws
    def test_ai_protection_disabled(self):
        """A reported-disabled feature FAILs and names the detector."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "AI_PROTECTION", "Status": "DISABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} does not have AI Protection enabled."
        )
        assert result[0].resource_id == response["DetectorId"]
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ai_protection_feature_absent(self):
        """A feature GuardDuty does not report is not a feature GuardDuty turned off.

        The Region or the GuardDuty version may not offer AI Protection at all.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[
                {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
                {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"},
            ],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} does not report the AI Protection feature, so verify manually whether AI Protection is available in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == response["DetectorId"]
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_no_features_reported(self):
        """An empty features array reads the same as an absent AI_PROTECTION entry."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(Enable=True)

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} does not report the AI Protection feature, so verify manually whether AI Protection is available in region {AWS_REGION_US_EAST_1}."
        )

    @mock_aws
    def test_detector_not_enabled(self):
        """A suspended detector is MANUAL: its feature state is unknown, not absent."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=False,
            Features=[{"Name": "AI_PROTECTION", "Status": "ENABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} is not enabled or could not be read, so AI Protection coverage could not be determined."
        )

    @mock_aws
    def test_get_detector_unreadable(self):
        """A denied GetDetector is unknown, not absent: MANUAL instead of FAIL."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "AI_PROTECTION", "Status": "DISABLED"}],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_get_detector_raises
        ):
            result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} is not enabled or could not be read, so AI Protection coverage could not be determined."
        )

    @mock_aws
    def test_real_get_detector_payload_ai_protection_disabled(self):
        """The real GetDetector payload carries AI_PROTECTION alongside AI_ANALYST.

        AI_PROTECTION is absent from the pinned DetectorFeatureResult enum, so this
        asserts the name still reaches the check alongside the two runtime feature names.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[
                {"Name": "CLOUD_TRAIL", "Status": "ENABLED"},
                {"Name": "DNS_LOGS", "Status": "ENABLED"},
                {"Name": "FLOW_LOGS", "Status": "ENABLED"},
                {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
                {"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"},
                {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"},
                {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"},
                {"Name": "AI_PROTECTION", "Status": "DISABLED"},
                {"Name": "AI_ANALYST", "Status": "ENABLED"},
                {"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"},
                {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"},
                {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"},
            ],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} does not have AI Protection enabled."
        )
