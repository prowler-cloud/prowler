from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import (
    InspectorFinding,
)

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)


class Test_inspector2_findings_exist:
    def test_no_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors_findings = []
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                inspector2_findings_exist,
            )

            check = inspector2_findings_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "There are no Inspector2 findings."
            assert result[0].resource_id == "Inspector2"
            assert result[0].resource_arn == ""

    def test_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors_findings = [
            InspectorFinding(
                arn=FINDING_ARN,
                region=AWS_REGION,
                severity="MEDIUM",
                status="ACTIVE",
                title="CVE-2022-40897 - setuptools",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                inspector2_findings_exist,
            )

            check = inspector2_findings_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "There are 1 Inspector2 findings."
            assert result[0].resource_id == "Inspector2"
            assert result[0].resource_arn == ""
