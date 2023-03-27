from unittest import mock

from boto3 import client
from moto import mock_organizations

AWS_REGION = "us-east-1"


class Test_organizations_account_part_of_organizations:
    @mock_organizations
    def test_no_organization(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations.organizations_client",
            new=Organizations(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations import (
                organizations_account_part_of_organizations,
            )

            check = organizations_account_part_of_organizations()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    @mock_organizations
    def test_organization(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        current_audit_info.audited_partition = "aws"

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        conn.create_organization()

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations.organizations_client",
            new=Organizations(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations import (
                organizations_account_part_of_organizations,
            )

            check = organizations_account_part_of_organizations()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
