from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import (
    Inspector,
    InspectorFinding,
)

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)


class Test_inspector2_findings_exist:
    def test_inspector2_disabled(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID, status="DISABLED", region=AWS_REGION, findings=[]
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
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Inspector2 is not enabled."
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
            assert result[0].region == AWS_REGION

    def test_enabled_no_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID, status="ENABLED", region=AWS_REGION, findings=[]
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
            assert (
                result[0].status_extended == "Inspector2 is enabled with no findings."
            )
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
            assert result[0].region == AWS_REGION

    def test_enabled_with_no_active_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                status="ENABLED",
                findings=[
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="NOT_ACTIVE",
                        title="CVE-2022-40897 - setuptools",
                    )
                ],
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
            assert (
                result[0].status_extended
                == "Inspector2 is enabled with no active findings."
            )
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
            assert result[0].region == AWS_REGION

    def test_enabled_with_active_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                status="ENABLED",
                findings=[
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="ACTIVE",
                        title="CVE-2022-40897 - setuptools",
                    )
                ],
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
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "There are 1 ACTIVE Inspector2 findings."
            )
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
            assert result[0].region == AWS_REGION

    def test_enabled_with_active_and_closed_findings(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                status="ENABLED",
                findings=[
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="ACTIVE",
                        title="CVE-2022-40897 - setuptools",
                    ),
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="CLOSED",
                        title="CVE-2022-27404 - freetype",
                    ),
                ],
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
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "There are 1 ACTIVE Inspector2 findings."
            )
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
            assert result[0].region == AWS_REGION
