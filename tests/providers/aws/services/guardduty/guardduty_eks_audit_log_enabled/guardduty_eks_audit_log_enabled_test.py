from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_guardduty_eks_audit_log_enabled:
    def test_no_detectors(self):
        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled import (
                guardduty_eks_audit_log_enabled,
            )

            check = guardduty_eks_audit_log_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_detector_disabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        guardduty_client.create_detector(Enable=False)

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled import (
                guardduty_eks_audit_log_enabled,
            )

            check = guardduty_eks_audit_log_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_detector_eks_audit_log_enabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(
            Enable=True, DataSources={"Kubernetes": {"AuditLogs": {"Enable": True}}}
        )["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled import (
                guardduty_eks_audit_log_enabled,
            )

            check = guardduty_eks_audit_log_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {detector_id} has EKS Audit Log Monitoring enabled."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_detector_eks_audit_log_disabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(
            Enable=True, DataSources={"Kubernetes": {"AuditLogs": {"Enable": False}}}
        )["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_eks_audit_log_enabled.guardduty_eks_audit_log_enabled import (
                guardduty_eks_audit_log_enabled,
            )

            check = guardduty_eks_audit_log_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {detector_id} does not have EKS Audit Log Monitoring enabled."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )
            assert result[0].resource_tags == []
