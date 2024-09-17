from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import Inspector
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)


class Test_inspector2_active_findings_exist:
    def test_enabled_no_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock

        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
                active_findings=False,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist.inspector2_client",
                new=inspector2_client,
            ):

                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist import (
                    inspector2_active_findings_exist,
                )

                check = inspector2_active_findings_exist()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Inspector2 is enabled with no active findings."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_enabled_with_no_active_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock

        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                region=AWS_REGION_EU_WEST_1,
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                active_findings=False,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist.inspector2_client",
                new=inspector2_client,
            ):

                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist import (
                    inspector2_active_findings_exist,
                )

                check = inspector2_active_findings_exist()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Inspector2 is enabled with no active findings."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_enabled_with_active_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock

        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                region=AWS_REGION_EU_WEST_1,
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                active_findings=True,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist.inspector2_client",
                new=inspector2_client,
            ):

                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist import (
                    inspector2_active_findings_exist,
                )

                check = inspector2_active_findings_exist()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended == "There are active Inspector2 findings."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_inspector2_disabled_ignoring(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        awslambda_client.functions = {}
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = mock.MagicMock
        ecr_client.registries[AWS_REGION_EU_WEST_1].repositories = []
        ec2_client = mock.MagicMock
        ec2_client.instances = []
        ec2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        awslambda_client.aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.provider._scan_unused_services = False
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="DISABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
                active_findings=False,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist.inspector2_client",
                new=inspector2_client,
            ):

                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist import (
                    inspector2_active_findings_exist,
                )

                check = inspector2_active_findings_exist()
                result = check.execute()

                assert len(result) == 0
