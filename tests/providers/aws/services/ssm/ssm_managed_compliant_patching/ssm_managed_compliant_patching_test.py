from unittest import mock

from prowler.providers.aws.services.ssm.ssm_service import (
    ComplianceResource,
    ResourceStatus,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_ssm_managed_compliant_patching:
    def test_no_compliance_resources(self):
        ssm_client = mock.MagicMock
        ssm_client.compliance_resources = {}
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_managed_compliant_patching.ssm_managed_compliant_patching import (
                ssm_managed_compliant_patching,
            )

            check = ssm_managed_compliant_patching()
            result = check.execute()

            assert len(result) == 0

    def test_compliance_resources_compliant(self):
        ssm_client = mock.MagicMock
        instance_id = "i-1234567890abcdef0"
        ssm_client.audited_account = AWS_ACCOUNT_NUMBER
        ssm_client.compliance_resources = {
            instance_id: ComplianceResource(
                id="i-1234567890abcdef0",
                region=AWS_REGION_US_EAST_1,
                status=ResourceStatus.COMPLIANT,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_managed_compliant_patching.ssm_managed_compliant_patching import (
                ssm_managed_compliant_patching,
            )

            check = ssm_managed_compliant_patching()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == instance_id
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EC2 managed instance {instance_id} is compliant."
            )

    def test_compliance_resources_non_compliant(self):
        ssm_client = mock.MagicMock
        instance_id = "i-1234567890abcdef0"
        ssm_client.audited_account = AWS_ACCOUNT_NUMBER
        ssm_client.compliance_resources = {
            instance_id: ComplianceResource(
                id="i-1234567890abcdef0",
                region=AWS_REGION_US_EAST_1,
                status=ResourceStatus.NON_COMPLIANT,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_managed_compliant_patching.ssm_managed_compliant_patching import (
                ssm_managed_compliant_patching,
            )

            check = ssm_managed_compliant_patching()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == instance_id
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EC2 managed instance {instance_id} is non-compliant."
            )
