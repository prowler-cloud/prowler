from re import search
from unittest import mock

from boto3 import client
from moto import mock_organizations

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_organizations_delegated_administrators:
    @mock_organizations
    def test_no_organization(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        audit_info.audit_config = {"organizations_trusted_delegated_administrators": []}
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 0

    @mock_organizations
    def test_organization_no_delegations(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        audit_info.audit_config = {"organizations_trusted_delegated_administrators": []}

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "No Delegated Administrators",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_organizations
    def test_organization_trusted_delegated(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        # Create Dummy Account
        account = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        # Delegate Administrator
        conn.register_delegated_administrator(
            AccountId=account["CreateAccountStatus"]["AccountId"],
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        # Set config variable
        audit_info.audit_config = {
            "organizations_trusted_delegated_administrators": [
                account["CreateAccountStatus"]["AccountId"]
            ]
        }

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "Trusted Delegated Administrator",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_organizations
    def test_organization_untrusted_delegated(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        # Create Dummy Account
        account = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        # Delegate Administrator
        conn.register_delegated_administrator(
            AccountId=account["CreateAccountStatus"]["AccountId"],
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        # Set config variable
        audit_info.audit_config = {"organizations_trusted_delegated_administrators": []}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "Untrusted Delegated Administrator",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION_EU_WEST_1
