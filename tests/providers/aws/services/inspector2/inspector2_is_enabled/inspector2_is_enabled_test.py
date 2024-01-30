from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import Inspector
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)


class Test_inspector2_is_enabled:
    def test_inspector2_disabled(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        ecr_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        awslambda_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        inspector2_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
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
                region=AWS_REGION_EU_WEST_1,
                findings=[],
            )
        ]
        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].status_extended == "Inspector2 is not enabled."
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_enabled_no_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        ecr_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        awslambda_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        inspector2_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
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
                region=AWS_REGION_EU_WEST_1,
                findings=[],
            )
        ]
        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.ecr_client",
                    new=ecr_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.ec2_client",
                        new=ec2_client,
                    ):
                        with mock.patch(
                            "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.awslambda_client",
                            new=awslambda_client,
                        ):
                            # Test Check
                            from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                                inspector2_is_enabled,
                            )

                            check = inspector2_is_enabled()
                            result = check.execute()

                            assert len(result) == 1
                            assert result[0].status == "PASS"
                            assert result[0].status_extended == "Inspector2 is enabled."
                            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                            assert (
                                result[0].resource_arn
                                == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                            )
                            assert result[0].region == AWS_REGION_EU_WEST_1
