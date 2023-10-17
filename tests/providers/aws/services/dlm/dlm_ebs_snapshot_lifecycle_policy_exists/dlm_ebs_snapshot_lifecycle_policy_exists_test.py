from unittest import mock

from prowler.providers.aws.services.dlm.dlm_service import LifecyclePolicy

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"

LIFECYCLE_POLICY_ID = "policy-XXXXXXXXXXXX"


class Test_dlm_ebs_snapshot_lifecycle_policy_exists:
    def test_no_ebs_snapshot_lifecycle_policies(self):
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {AWS_REGION: {}}

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.DLM",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "No EBS Snapshot lifecycle policies found."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN

    def test_one_ebs_snapshot_lifecycle_policy(self):
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {
            AWS_REGION: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.DLM",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "EBS snapshot lifecycle policies found."
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
