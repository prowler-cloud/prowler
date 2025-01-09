from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListFindings":
        return {
            "FindingIds": [
                "f1",
                "f2",
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_guardduty_no_high_severity_findings:
    @mock_aws
    def test_no_detectors(self):
        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_no_high_findings(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {detector_id} does not have high severity findings."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )
            assert result[0].resource_tags == []

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_high_findings(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {detector_id} has 2 high severity findings."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )
            assert result[0].resource_tags == []
