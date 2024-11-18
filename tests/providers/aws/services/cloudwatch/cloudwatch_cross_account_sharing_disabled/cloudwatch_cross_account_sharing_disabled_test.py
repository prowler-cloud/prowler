from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudwatch_cross_account_sharing_disabled:
    @mock_aws
    def test_cloudwatch_without_cross_account_role(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled import (
                cloudwatch_cross_account_sharing_disabled,
            )

            check = cloudwatch_cross_account_sharing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch doesn't allow cross-account sharing."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:role"
                or result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:role"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_cloudwatch_log_group_with_cross_account_role(self):
        # Generate Logs Client
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        # Request Logs group
        iam_client.create_role(
            RoleName="CloudWatch-CrossAccountSharingRole",
            AssumeRolePolicyDocument="{}",
            Tags=[{"Key": "Name", "Value": "CloudWatch-CrossAccountSharingRole"}],
        )
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled import (
                cloudwatch_cross_account_sharing_disabled,
            )

            check = cloudwatch_cross_account_sharing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CloudWatch has allowed cross-account sharing."
            )
            assert result[0].resource_id == "CloudWatch-CrossAccountSharingRole"
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/CloudWatch-CrossAccountSharingRole"
            )
            assert (
                result[0].region == AWS_REGION_US_EAST_1
                or result[0].region == AWS_REGION_EU_WEST_1
            )
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "CloudWatch-CrossAccountSharingRole"}
            ]

    @mock_aws
    def test_access_denied(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled.iam_client",
            new=IAM(aws_provider),
        ) as iam_client:
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled import (
                cloudwatch_cross_account_sharing_disabled,
            )

            iam_client.roles = None
            check = cloudwatch_cross_account_sharing_disabled()
            result = check.execute()

            assert len(result) == 0
