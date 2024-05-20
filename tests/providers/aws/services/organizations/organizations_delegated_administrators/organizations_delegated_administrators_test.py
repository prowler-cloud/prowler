from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


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
        response = conn.create_organization()

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
                assert search(
                    "No Delegated Administrators",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_trusted_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

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
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "Trusted Delegated Administrator",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_untrusted_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

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
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "Untrusted Delegated Administrator",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION_EU_WEST_1
