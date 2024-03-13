from unittest import mock

from prowler.providers.aws.services.fms.fms_service import (
    Policy,
    PolicyAccountComplianceStatus,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_fms_policy_compliant:
    def test_fms_not_admin(self):
        fms_client = mock.MagicMock
        fms_client.region = AWS_REGION_US_EAST_1
        fms_client.fms_admin_account = False
        with mock.patch(
            "prowler.providers.aws.services.fms.fms_service.FMS",
            new=fms_client,
        ):
            # Test Check
            from prowler.providers.aws.services.fms.fms_policy_compliant.fms_policy_compliant import (
                fms_policy_compliant,
            )

            check = fms_policy_compliant()
            result = check.execute()

            assert len(result) == 0

    def test_fms_admin_with_non_compliant_policies(self):
        fms_client = mock.MagicMock
        fms_client.audited_account = AWS_ACCOUNT_NUMBER
        fms_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        fms_client.region = AWS_REGION_US_EAST_1
        fms_client.audited_partition = "aws"
        fms_client.fms_admin_account = True
        fms_client.fms_policies = [
            Policy(
                arn=f"arn:aws:fms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy",
                id=AWS_ACCOUNT_NUMBER,
                name="test",
                resource_type="AWS::EC2::Instance",
                service_type="WAF",
                remediation_enabled=True,
                delete_unused_managed_resources=True,
                compliance_status=[
                    PolicyAccountComplianceStatus(
                        account_id=AWS_ACCOUNT_NUMBER,
                        policy_id=AWS_ACCOUNT_NUMBER,
                        status="NON_COMPLIANT",
                    )
                ],
            )
        ]
        fms_client.policy_arn_template = f"arn:{fms_client.audited_partition}:fms:{fms_client.region}:{fms_client.audited_account}:policy"
        fms_client.__get_policy_arn_template__ = mock.MagicMock(
            return_value=fms_client.policy_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.fms.fms_service.FMS",
            new=fms_client,
        ):
            # Test Check
            from prowler.providers.aws.services.fms.fms_policy_compliant.fms_policy_compliant import (
                fms_policy_compliant,
            )

            check = fms_policy_compliant()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FMS with non-compliant policy {fms_client.fms_policies[0].name} for account {fms_client.fms_policies[0].compliance_status[0].account_id}."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:fms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_fms_admin_with_compliant_policies(self):
        fms_client = mock.MagicMock
        fms_client.audited_account = AWS_ACCOUNT_NUMBER
        fms_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        fms_client.region = AWS_REGION_US_EAST_1
        fms_client.audited_partition = "aws"
        fms_client.fms_admin_account = True
        fms_client.fms_policies = [
            Policy(
                arn="arn:aws:fms:us-east-1:12345678901",
                id="12345678901",
                name="test",
                resource_type="AWS::EC2::Instance",
                service_type="WAF",
                remediation_enabled=True,
                delete_unused_managed_resources=True,
                compliance_status=[
                    PolicyAccountComplianceStatus(
                        account_id="12345678901",
                        policy_id="12345678901",
                        status="COMPLIANT",
                    )
                ],
            )
        ]
        fms_client.policy_arn_template = f"arn:{fms_client.audited_partition}:fms:{fms_client.region}:{fms_client.audited_account}:policy"
        fms_client.__get_policy_arn_template__ = mock.MagicMock(
            return_value=fms_client.policy_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.fms.fms_service.FMS",
            new=fms_client,
        ):
            # Test Check
            from prowler.providers.aws.services.fms.fms_policy_compliant.fms_policy_compliant import (
                fms_policy_compliant,
            )

            check = fms_policy_compliant()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "FMS enabled with all compliant accounts."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:fms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_fms_admin_with_non_and_compliant_policies(self):
        fms_client = mock.MagicMock
        fms_client.audited_account = AWS_ACCOUNT_NUMBER
        fms_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        fms_client.audited_partition = "aws"
        fms_client.region = AWS_REGION_US_EAST_1
        fms_client.fms_admin_account = True
        fms_client.fms_policies = [
            Policy(
                arn=f"arn:aws:fms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy",
                id="12345678901",
                name="test",
                resource_type="AWS::EC2::Instance",
                service_type="WAF",
                remediation_enabled=True,
                delete_unused_managed_resources=True,
                compliance_status=[
                    PolicyAccountComplianceStatus(
                        account_id="12345678901",
                        policy_id="12345678901",
                        status="COMPLIANT",
                    ),
                    PolicyAccountComplianceStatus(
                        account_id="12345678901",
                        policy_id="12345678901",
                        status="NON_COMPLIANT",
                    ),
                ],
            )
        ]
        fms_client.policy_arn_template = f"arn:{fms_client.audited_partition}:fms:{fms_client.region}:{fms_client.audited_account}:policy"
        fms_client.__get_policy_arn_template__ = mock.MagicMock(
            return_value=fms_client.policy_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.fms.fms_service.FMS",
            new=fms_client,
        ):
            # Test Check
            from prowler.providers.aws.services.fms.fms_policy_compliant.fms_policy_compliant import (
                fms_policy_compliant,
            )

            check = fms_policy_compliant()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FMS with non-compliant policy {fms_client.fms_policies[0].name} for account {fms_client.fms_policies[0].compliance_status[0].account_id}."
            )
            assert result[0].resource_id == "12345678901"
            assert (
                result[0].resource_arn
                == f"arn:aws:fms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_fms_admin_without_policies(self):
        fms_client = mock.MagicMock
        fms_client.audited_account = AWS_ACCOUNT_NUMBER
        fms_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        fms_client.region = AWS_REGION_US_EAST_1
        fms_client.audited_partition = "aws"
        fms_client.fms_admin_account = True
        fms_client.fms_policies = []
        fms_client.policy_arn_template = f"arn:{fms_client.audited_partition}:fms:{fms_client.region}:{fms_client.audited_account}:policy"
        fms_client.__get_policy_arn_template__ = mock.MagicMock(
            return_value=fms_client.policy_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.fms.fms_service.FMS",
            new=fms_client,
        ):
            # Test Check
            from prowler.providers.aws.services.fms.fms_policy_compliant.fms_policy_compliant import (
                fms_policy_compliant,
            )

            check = fms_policy_compliant()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FMS without any compliant policy for account {AWS_ACCOUNT_NUMBER}."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:fms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_fms_admin_with_policy_with_null_status(self):
        fms_client = mock.MagicMock
        fms_client.audited_account = AWS_ACCOUNT_NUMBER
        fms_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        fms_client.audited_partition = "aws"
        fms_client.region = AWS_REGION_US_EAST_1
        fms_client.fms_admin_account = True
        fms_client.fms_policies = [
            Policy(
                arn="arn:aws:fms:us-east-1:12345678901",
                id="12345678901",
                name="test",
                resource_type="AWS::EC2::Instance",
                service_type="WAF",
                remediation_enabled=True,
                delete_unused_managed_resources=True,
                compliance_status=[
                    PolicyAccountComplianceStatus(
                        account_id="12345678901",
                        policy_id="12345678901",
                        status="",
                    ),
                ],
            )
        ]
        fms_client.policy_arn_template = f"arn:{fms_client.audited_partition}:fms:{fms_client.region}:{fms_client.audited_account}:policy"
        fms_client.__get_policy_arn_template__ = mock.MagicMock(
            return_value=fms_client.policy_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.fms.fms_service.FMS",
            new=fms_client,
        ):
            # Test Check
            from prowler.providers.aws.services.fms.fms_policy_compliant.fms_policy_compliant import (
                fms_policy_compliant,
            )

            check = fms_policy_compliant()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FMS with non-compliant policy {fms_client.fms_policies[0].name} for account {fms_client.fms_policies[0].compliance_status[0].account_id}."
            )
            assert result[0].resource_id == "12345678901"
            assert result[0].resource_arn == "arn:aws:fms:us-east-1:12345678901"
            assert result[0].region == AWS_REGION_US_EAST_1
