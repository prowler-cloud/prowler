from unittest import mock

from boto3 import client
from moto import mock_iam

AWS_REGION = "us-east-1"


class Test_cloudwatch_cross_account_sharing_disabled:
    @mock_iam
    def test_cloudwatch_without_cross_account_role(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM
        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audited_partition = "aws"
        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled.iam_client",
            new=IAM(current_audit_info),
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
                == "CloudWatch doesn't allows cross-account sharing"
            )
            assert result[0].resource_id == "CloudWatch-CrossAccountSharingRole"

    @mock_iam
    def test_cloudwatch_log_group_with_cross_account_role(self):
        # Generate Logs Client
        iam_client = client("iam", region_name=AWS_REGION)
        # Request Logs group
        iam_client.create_role(
            RoleName="CloudWatch-CrossAccountSharingRole", AssumeRolePolicyDocument="{}"
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM
        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audited_partition = "aws"
        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_cross_account_sharing_disabled.cloudwatch_cross_account_sharing_disabled.iam_client",
            new=IAM(current_audit_info),
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
