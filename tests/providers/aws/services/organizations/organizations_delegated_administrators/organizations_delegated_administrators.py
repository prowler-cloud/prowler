from unittest import mock

from boto3 import client
from moto import mock_organizations

AWS_REGION = "us-east-1"


class Test_organizations_delegated_administrators:
    @mock_organizations
    def test_no_organization(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
            new=Organizations(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                organizations_delegated_administrators,
            )

            check = organizations_delegated_administrators()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_organizations
    def test_organization_no_delegations(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        current_audit_info.audited_partition = "aws"

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        conn.create_organization()

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
            new=Organizations(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                organizations_delegated_administrators,
            )

            check = organizations_delegated_administrators()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_organizations
    def test_organization_trusted_delegated(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        current_audit_info.audited_partition = "aws"

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        conn.create_organization()
        # Create Dummy Account
        response = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        # Delegate Administrator
        conn.register_delegated_administrator(
            AccountId=response["CreateAccountStatus"]["AccountId"],
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        def mock_get_config_var(config_var):
            if config_var == "organizations_trusted_delegated_administrators":
                return [response["CreateAccountStatus"]["AccountId"]]
            return []

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
            new=Organizations(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.get_config_var",
                new=mock_get_config_var,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    @mock_organizations
    def test_organization_untrusted_delegated(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        current_audit_info.audited_partition = "aws"

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        conn.create_organization()
        # Create Dummy Account
        response = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        # Delegate Administrator
        conn.register_delegated_administrator(
            AccountId=response["CreateAccountStatus"]["AccountId"],
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
            new=Organizations(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                organizations_delegated_administrators,
            )

            check = organizations_delegated_administrators()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
