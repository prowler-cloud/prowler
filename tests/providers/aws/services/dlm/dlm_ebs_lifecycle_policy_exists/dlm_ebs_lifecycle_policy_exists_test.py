from re import search
from unittest import mock

# from prowler.providers.aws.services.dlm.dlm_service import Dlm

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_dlm_ebs_lifecycle_policy_exists:
    def test_no_ebs_lifecycle_policies(self):
        dlm_client = mock.MagicMock
        dlm_client.lifecycle_policies = []

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.Dlm",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_lifecycle_policy_exists.dlm_ebs_lifecycle_policy_exists import (
                dlm_ebs_lifecycle_policy_exists,
            )

            check = dlm_ebs_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "No EBS lifecycle policies found",
                result[0].status_extended,
            )

    def test_one_ebs_lifecycle_policy(self):
        dlm_client = mock.MagicMock
        dlm_client.lifecycle_policies = ["test-policy"]

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.Dlm",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_lifecycle_policy_exists.dlm_ebs_lifecycle_policy_exists import (
                dlm_ebs_lifecycle_policy_exists,
            )

            check = dlm_ebs_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "EBS lifecycle policies found",
                result[0].status_extended,
            )
