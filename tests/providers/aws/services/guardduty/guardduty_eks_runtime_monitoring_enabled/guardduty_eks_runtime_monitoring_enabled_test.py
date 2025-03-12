from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_guardduty_eks_runtime_monitoring_enabled:
    @mock_aws
    def test_no_detectors(self):
        client("guardduty", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):

            from prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled import (
                guardduty_eks_runtime_monitoring_enabled,
            )

            check = guardduty_eks_runtime_monitoring_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_detector_disabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        guardduty_client.create_detector(
            Enable=False,
            DataSources={
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": True}},
            },
            Features=[{"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"}],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):

            from prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled import (
                guardduty_eks_runtime_monitoring_enabled,
            )

            check = guardduty_eks_runtime_monitoring_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_detector_enabled_eks_runtime_monitoring_disabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            DataSources={
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": True}},
            },
            Features=[{"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"}],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):

            from prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled import (
                guardduty_eks_runtime_monitoring_enabled,
            )

            check = guardduty_eks_runtime_monitoring_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {response['DetectorId']} does not have EKS Runtime Monitoring enabled."
            )
            assert result[0].resource_id == response["DetectorId"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_detector_enabled_eks_runtime_monitoring_enabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_US_EAST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            DataSources={
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": True}},
            },
            Features=[{"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"}],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_eks_runtime_monitoring_enabled.guardduty_eks_runtime_monitoring_enabled import (
                guardduty_eks_runtime_monitoring_enabled,
            )

            check = guardduty_eks_runtime_monitoring_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {response['DetectorId']} has EKS Runtime Monitoring enabled."
            )
            assert result[0].resource_id == response["DetectorId"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
            )
            assert result[0].resource_tags == []
