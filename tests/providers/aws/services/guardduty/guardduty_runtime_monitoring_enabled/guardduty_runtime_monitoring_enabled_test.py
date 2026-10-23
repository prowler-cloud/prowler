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

CHECK_CLIENT_PATH = "prowler.providers.aws.services.guardduty.guardduty_runtime_monitoring_enabled.guardduty_runtime_monitoring_enabled.guardduty_client"

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
        from prowler.providers.aws.services.guardduty.guardduty_runtime_monitoring_enabled.guardduty_runtime_monitoring_enabled import (
            guardduty_runtime_monitoring_enabled,
        )

        return guardduty_runtime_monitoring_enabled().execute()


class Test_guardduty_runtime_monitoring_enabled:
    @mock_aws
    def test_no_detectors(self):
        """A Region with no detector has no resource to judge; guardduty_is_enabled owns it."""
        client("guardduty", region_name=AWS_REGION_US_EAST_1)

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 0

    @mock_aws
    def test_detector_disabled(self):
        """A suspended detector is MANUAL, never dropped.

        The detector exists, so omitting it would leave the Region unreported, which
        reads as compliant -- and it is reported here with Runtime Monitoring ENABLED,
        the case where the omission was hardest to notice.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=False,
            Features=[{"Name": "RUNTIME_MONITORING", "Status": "ENABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} is not enabled or could not be read, so Runtime Monitoring coverage could not be determined."
        )
        assert result[0].resource_id == response["DetectorId"]
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_get_detector_unreadable(self):
        """A denied GetDetector is unknown, not absent: MANUAL instead of FAIL.

        Detector.status cannot distinguish this from a suspended detector, which is why
        both carry the same MANUAL wording rather than a definite verdict.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "RUNTIME_MONITORING", "Status": "DISABLED"}],
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
            == f"GuardDuty detector {response['DetectorId']} is not enabled or could not be read, so Runtime Monitoring coverage could not be determined."
        )

    @mock_aws
    def test_runtime_monitoring_enabled(self):
        """An enabled unified feature PASSes and carries the detector's own resource fields."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "RUNTIME_MONITORING", "Status": "ENABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} has Runtime Monitoring enabled."
        )
        assert result[0].resource_id == response["DetectorId"]
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].resource_arn
            == f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert result[0].resource_tags == []

    @mock_aws
    def test_runtime_monitoring_disabled(self):
        """A reported-disabled unified feature FAILs and names the detector."""
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "RUNTIME_MONITORING", "Status": "DISABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} does not have Runtime Monitoring enabled."
        )
        assert result[0].resource_id == response["DetectorId"]
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_unreported_runtime_feature_is_manual_not_fail(self):
        """A feature the detector never reports is not the same as one it reports DISABLED.

        GuardDuty returns a disabled feature with Status DISABLED rather than omitting
        it -- which is exactly why AI_PROTECTION is recorded even when off -- so an
        omitted RUNTIME_MONITORING means the Region does not offer the unified feature,
        or the features array could not be read. Neither is a definite absence of
        runtime coverage.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} did not report the Runtime Monitoring feature, so runtime coverage could not be determined; verify manually."
        )

    @mock_aws
    def test_runtime_monitoring_reported_disabled_still_fails(self):
        """The complement of the unreported case: reported and DISABLED stays a FAIL.

        Making the unreported case MANUAL must not soften a definite absence of coverage.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "RUNTIME_MONITORING", "Status": "DISABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} does not have Runtime Monitoring enabled."
        )

    @mock_aws
    def test_legacy_eks_runtime_monitoring_only_fails(self):
        """The legacy EKS-only feature covers Amazon EKS and nothing else.

        It must not PASS a check about Amazon EC2 and Amazon ECS on Fargate coverage.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[
                {"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"},
                {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"},
            ],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} only has the legacy EKS Runtime Monitoring enabled, leaving Amazon EC2 instances and Amazon ECS on Fargate tasks without runtime coverage."
        )

    @mock_aws
    def test_legacy_eks_only_without_any_unified_entry_fails(self):
        """The real legacy shape: the unified feature is absent, not reported DISABLED.

        The two features are mutually exclusive at the API, so a detector on the legacy
        one has no RUNTIME_MONITORING entry at all -- which is the same absence that makes
        an unknown detector MANUAL. The test above supplies a DISABLED unified entry as
        well, so it never reaches that ambiguity. Here the legacy verdict has to win on
        ordering alone: EKS coverage is stated, so EC2 and Fargate are definitively
        uncovered rather than undetermined.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[{"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"}],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} only has the legacy EKS Runtime Monitoring enabled, leaving Amazon EC2 instances and Amazon ECS on Fargate tasks without runtime coverage."
        )

    @mock_aws
    def test_unified_enabled_with_legacy_disabled(self):
        """GetDetector returns an entry for both feature names on the same detector.

        A DISABLED legacy feature must not mask the ENABLED unified one.
        """
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            Features=[
                {"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"},
                {"Name": "RUNTIME_MONITORING", "Status": "ENABLED"},
            ],
        )

        result = _run_check(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"GuardDuty detector {response['DetectorId']} has Runtime Monitoring enabled."
        )
