from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

orig_make_api_call = botocore.client.BaseClient._make_api_call


def make_mock_delegated_services_access_denied():
    def _mock(self, operation_name, api_params):
        if operation_name == "ListDelegatedServicesForAccount":
            raise botocore.exceptions.ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "User is not authorized to perform: organizations:ListDelegatedServicesForAccount",
                    }
                },
                operation_name,
            )
        return orig_make_api_call(self, operation_name, api_params)

    return _mock


class Test_organizations_delegated_administrators:
    @mock_aws
    def test_no_organization(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_organization_no_delegations(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
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
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has no Delegated Administrators."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_trusted_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
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
        org_id = response["Organization"]["Id"]
        account_id = account["CreateAccountStatus"]["AccountId"]
        admin_arn = conn.list_delegated_administrators()["DelegatedAdministrators"][0][
            "Arn"
        ]

        # Set config variable
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [
                account["CreateAccountStatus"]["AccountId"]
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == account_id
                assert result[0].resource_arn == admin_arn
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has a trusted Delegated Administrator: {account_id}, delegated for: config-multiaccountsetup.amazonaws.com."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_untrusted_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
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
        org_id = response["Organization"]["Id"]
        account_id = account["CreateAccountStatus"]["AccountId"]
        admin_arn = conn.list_delegated_administrators()["DelegatedAdministrators"][0][
            "Arn"
        ]

        # Set config variable
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == account_id
                assert result[0].resource_arn == admin_arn
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: {account_id}, delegated for: config-multiaccountsetup.amazonaws.com."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_multiple_delegated_administrators(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Create a trusted delegated administrator, registered for two services
        trusted_account = conn.create_account(
            Email="trusted@test.com",
            AccountName="trusted",
        )
        trusted_account_id = trusted_account["CreateAccountStatus"]["AccountId"]
        conn.register_delegated_administrator(
            AccountId=trusted_account_id,
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )
        conn.register_delegated_administrator(
            AccountId=trusted_account_id,
            ServicePrincipal="guardduty.amazonaws.com",
        )

        # Create an untrusted delegated administrator, registered for one service
        untrusted_account = conn.create_account(
            Email="untrusted@test.com",
            AccountName="untrusted",
        )
        untrusted_account_id = untrusted_account["CreateAccountStatus"]["AccountId"]
        conn.register_delegated_administrator(
            AccountId=untrusted_account_id,
            ServicePrincipal="macie.amazonaws.com",
        )

        # Set config variable - only the first account is trusted
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [trusted_account_id]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                # Each delegated administrator must be its own finding
                assert len(result) == 2
                results_by_id = {r.resource_id: r for r in result}

                trusted_result = results_by_id[trusted_account_id]
                assert trusted_result.status == "PASS"
                assert (
                    trusted_result.status_extended
                    == f"AWS Organization {org_id} has a trusted Delegated Administrator: "
                    f"{trusted_account_id}, delegated for: "
                    "config-multiaccountsetup.amazonaws.com, guardduty.amazonaws.com."
                )

                untrusted_result = results_by_id[untrusted_account_id]
                assert untrusted_result.status == "FAIL"
                assert (
                    untrusted_result.status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: "
                    f"{untrusted_account_id}, delegated for: macie.amazonaws.com."
                )

    @mock_aws
    def test_organization_untrusted_delegated_unknown_services(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        account = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        account_id = account["CreateAccountStatus"]["AccountId"]
        conn.register_delegated_administrator(
            AccountId=account_id,
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }

        # The caller can list delegated administrators but is denied when
        # asking which services a specific administrator is delegated for
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_delegated_services_access_denied(),
        ):
            organizations = Organizations(aws_provider)

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == account_id
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: "
                    f"{account_id}, delegated services could not be determined."
                )
